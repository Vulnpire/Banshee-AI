package analysis

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
)

// extractDomainFromURL extracts the domain from a full URL
func extractDomainFromURL(urlStr string) string {
	// Remove protocol if present
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")

	// Extract domain (everything before first /)
	parts := strings.Split(urlStr, "/")
	if len(parts) == 0 {
		return ""
	}

	domain := parts[0]

	// Remove port if present
	domain = strings.Split(domain, ":")[0]

	// Remove www. prefix if present
	domain = strings.TrimPrefix(domain, "www.")

	return domain
}

// convertToBraveDork converts Google dork syntax to Brave Search compatible format
// Brave Search has different operators and syntax requirements
func convertToBraveDork(googleDork string) string {
	// Brave Search operator compatibility:
	// - site: ✓ (same)
	// - inurl: ✓ (same)
	// - intitle: ✓ (same)
	// - intext: ✓ (same)
	// - filetype: ✓ (same)
	// - ext: ✗ (not supported, use filetype:)
	// - -ext: ✗ (not supported, use -filetype:)
	// - before: ✓ (same)
	// - after: ✓ (same)

	braveDork := googleDork

	// Convert -ext: to -filetype: (exclusion)
	// Example: -ext:pdf → -filetype:pdf
	braveDork = regexp.MustCompile(`-ext:(\w+)`).ReplaceAllString(braveDork, `-filetype:$1`)

	// Convert ext: to filetype: (inclusion)
	// Example: ext:pdf → filetype:pdf
	// Be careful not to convert -ext: again (already converted above)
	braveDork = regexp.MustCompile(`\bext:(\w+)`).ReplaceAllString(braveDork, `filetype:$1`)

	return braveDork
}

// isCVEHuntingIntent uses simple keyword analysis to detect if user wants CVE hunting
// This is more precise than just checking for "vulnerab" which catches too many cases
func isCVEHuntingIntent(prompt string) bool {
	promptLower := strings.ToLower(prompt)

	// Explicit CVE hunting indicators
	cveKeywords := []string{
		"cve",
		"cves",
		"find cve",
		"search cve",
		"hunt cve",
		"discover cve",
		"detect cve",
		"identify cve",
		"cve database",
		"known vulnerabilities",
		"exploit database",
		"vulnerability database",
		"security advisory",
		"security advisories",
	}

	for _, keyword := range cveKeywords {
		if strings.Contains(promptLower, keyword) {
			return true
		}
	}

	// Check for CVE-specific vulnerability hunting (not general SQLi/XSS hunting)
	// "find CVE for SQLi" is CVE hunting
	// "find subdomains vulnerable to SQLi" is NOT CVE hunting
	if strings.Contains(promptLower, "vulnerab") {
		// Check if it's in context of CVE/advisory hunting
		if strings.Contains(promptLower, "known") ||
			strings.Contains(promptLower, "public") ||
			strings.Contains(promptLower, "disclosed") ||
			strings.Contains(promptLower, "advisory") ||
			strings.Contains(promptLower, "database") {
			return true
		}
	}

	return false
}

// LoadNonSensitiveKeywords loads non-sensitive document keywords from file,
// creating it with defaults if it doesn't exist
func LoadNonSensitiveKeywords() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	configDir := filepath.Join(home, ".config", "banshee")
	keywordsPath := filepath.Join(configDir, "filtered-nonsensitive-doc-keywords.txt")

	// Default non-sensitive keywords (documents that are typically NOT sensitive)
	defaultKeywords := []string{
		// User documentation
		"user-guide", "user's-guide", "users-guide", "user_guide",
		"owner-manual", "owner's-manual", "owners-manual", "owner_manual",
		"getting-started", "quick-start", "quickstart",
		"tutorial", "how-to", "howto",

		// Product documentation
		"datasheet", "data-sheet", "spec-sheet", "specsheet",
		"product-brief", "product-guide", "product-overview",
		"feature-list", "feature-guide",
		"brochure", "catalog",

		// Technical documentation (generic)
		"reference-guide", "reference-manual",
		"installation-guide", "install-guide",
		"setup-guide", "setup-manual",
		"deployment-guide",
		"maintenance-guide", "maintenance-manual",
		"troubleshooting", "troubleshoot",
		"faq", "faqs",

		// Service documentation
		"service-manual", "service-guide",
		"repair-manual", "repair-guide",

		// Generic manuals
		"handbook", "manual", "guide",
		"readme", "read-me",

		// Release notes and updates
		"release-note", "release-notes",
		"changelog", "change-log",
		"update-guide",

		// Training materials
		"training-guide", "training-manual",
		"certification-guide",
		"course-material",
	}

	// Check if file exists
	if _, err := os.Stat(keywordsPath); os.IsNotExist(err) {
		// Create config directory if it doesn't exist
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return defaultKeywords, nil // Return defaults if can't create dir
		}

		// Create file with default keywords
		content := "# Non-sensitive document keywords (one per line)\n"
		content += "# Documents containing these keywords in their URLs will be filtered out from analysis\n"
		content += "# You can add or remove keywords as needed\n"
		content += "#\n"
		content += "# Format: one keyword per line (case-insensitive)\n"
		content += "# Comments start with #\n\n"

		for _, keyword := range defaultKeywords {
			content += keyword + "\n"
		}

		if err := os.WriteFile(keywordsPath, []byte(content), 0644); err != nil {
			return defaultKeywords, nil // Return defaults if can't write file
		}

		return defaultKeywords, nil
	}

	// Read keywords from file
	content, err := os.ReadFile(keywordsPath)
	if err != nil {
		return defaultKeywords, nil // Return defaults if can't read file
	}

	var keywords []string
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			keywords = append(keywords, strings.ToLower(line))
		}
	}

	// If file is empty, return defaults
	if len(keywords) == 0 {
		return defaultKeywords, nil
	}

	return keywords, nil
}

// extractTextFromXLSX extracts text content from XLSX files
// XLSX files are ZIP archives containing XML files
func extractTextFromXLSX(filePath string) (string, error) {
	// Open XLSX as ZIP
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open XLSX as ZIP: %v", err)
	}
	defer r.Close()

	// First, read shared strings (if present)
	sharedStrings := make([]string, 0)
	for _, f := range r.File {
		if f.Name == "xl/sharedStrings.xml" {
			rc, err := f.Open()
			if err != nil {
				continue
			}

			// Parse shared strings XML
			type SST struct {
				XMLName xml.Name `xml:"sst"`
				SI      []struct {
					T string `xml:"t"`
				} `xml:"si"`
			}

			var sst SST
			if err := xml.NewDecoder(rc).Decode(&sst); err == nil {
				for _, si := range sst.SI {
					sharedStrings = append(sharedStrings, si.T)
				}
			}
			rc.Close() // Close immediately, not defer inside loop
			break
		}
	}

	// Now read worksheet data
	var textContent strings.Builder
	for _, f := range r.File {
		// Process all worksheet files
		if strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml") {
			rc, err := f.Open()
			if err != nil {
				continue
			}

			// Parse worksheet XML
			type Worksheet struct {
				XMLName   xml.Name `xml:"worksheet"`
				SheetData struct {
					Row []struct {
						C []struct {
							T  string `xml:"t,attr"` // Cell type (s=shared string, str=inline string)
							V  string `xml:"v"`      // Cell value
							Is struct {
								T string `xml:"t"` // Inline string value
							} `xml:"is"`
						} `xml:"c"`
					} `xml:"row"`
				} `xml:"sheetData"`
			}

			var ws Worksheet
			if err := xml.NewDecoder(rc).Decode(&ws); err != nil {
				rc.Close() // Close before continue
				continue
			}

			// Extract text from cells
			for _, row := range ws.SheetData.Row {
				for _, cell := range row.C {
					var cellText string

					// Handle different cell types
					switch cell.T {
					case "s": // Shared string
						// V contains index into shared strings array
						if idx, err := strconv.Atoi(cell.V); err == nil {
							if idx >= 0 && idx < len(sharedStrings) {
								cellText = sharedStrings[idx]
							}
						}
					case "str", "inlineStr": // Inline string
						if cell.Is.T != "" {
							cellText = cell.Is.T
						} else {
							cellText = cell.V
						}
					default: // Number or other type
						cellText = cell.V
					}

					if cellText != "" {
						textContent.WriteString(cellText)
						textContent.WriteString(" ")
					}
				}
				textContent.WriteString("\n")
			}

			rc.Close() // Close immediately after processing each worksheet
		}
	}

	extracted := strings.TrimSpace(textContent.String())
	if extracted == "" {
		return "", fmt.Errorf("no text content extracted from XLSX")
	}

	return extracted, nil
}

// ShouldFilterDocument checks if a document URL contains non-sensitive keywords
// and should be filtered out from analysis. Returns true if document should be SKIPPED.
func ShouldFilterDocument(docURL string, keywords []string) bool {
	urlLower := strings.ToLower(docURL)

	// Check if URL contains any non-sensitive keywords
	for _, keyword := range keywords {
		if strings.Contains(urlLower, keyword) {
			return true // Filter out (skip analysis)
		}
	}

	return false // Don't filter (proceed with analysis)
}

// extractDownloadURLFromHTML attempts to extract the actual download URL from an HTML page
func extractDownloadURLFromHTML(html, baseURL string) string {
	// Common patterns for download links
	patterns := []string{
		// Direct download links with href
		`href=["']([^"']+\.(?:pdf|docx?|xlsx?|pptx?|txt|csv)[^"']*)["']`,
		// Meta refresh redirects
		`<meta[^>]*http-equiv=["']refresh["'][^>]*content=["'][^;]*;\s*url=([^"']+)["']`,
		// JavaScript redirects
		`window\.location\.href\s*=\s*["']([^"']+)["']`,
		`window\.location\s*=\s*["']([^"']+)["']`,
		// Data download URLs
		`data-download-url=["']([^"']+)["']`,
		`data-href=["']([^"']+)["']`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)
		if len(matches) > 1 {
			downloadURL := matches[1]

			// Make URL absolute if it's relative
			if !strings.HasPrefix(downloadURL, "http") {
				if parsedBase, err := url.Parse(baseURL); err == nil {
					if parsedDownload, err := parsedBase.Parse(downloadURL); err == nil {
						downloadURL = parsedDownload.String()
					}
				}
			}

			// Decode HTML entities
			downloadURL = strings.ReplaceAll(downloadURL, "&amp;", "&")

			return downloadURL
		}
	}

	// If no pattern matched, look for any link with document extension
	re := regexp.MustCompile(`(?i)(?:href|src)=["']([^"']*\.(?:pdf|docx?|xlsx?|pptx?)(?:\?[^"']*)?)["']`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		downloadURL := matches[1]
		if !strings.HasPrefix(downloadURL, "http") {
			if parsedBase, err := url.Parse(baseURL); err == nil {
				if parsedDownload, err := parsedBase.Parse(downloadURL); err == nil {
					downloadURL = parsedDownload.String()
				}
			}
		}
		downloadURL = strings.ReplaceAll(downloadURL, "&amp;", "&")
		return downloadURL
	}

	return ""
}

// isValidDocumentContent validates that downloaded content matches expected file type
// Checks magic bytes/headers to detect HTML redirects or error pages
func isValidDocumentContent(content []byte, ext string) bool {
	if len(content) < 4 {
		return false
	}

	// Check for HTML content (likely a redirect or error page)
	contentLower := strings.ToLower(string(content[:min(512, len(content))]))
	if strings.Contains(contentLower, "<!doctype html") ||
		strings.Contains(contentLower, "<html") ||
		strings.Contains(contentLower, "<head>") ||
		strings.Contains(contentLower, "<body") {
		return false // This is HTML, not a document
	}

	// Validate file magic bytes
	switch ext {
	case ".pdf":
		return bytes.HasPrefix(content, []byte("%PDF"))
	case ".docx", ".xlsx", ".pptx":
		// These are ZIP files
		return bytes.HasPrefix(content, []byte("PK\x03\x04")) || bytes.HasPrefix(content, []byte("PK\x05\x06"))
	case ".doc":
		// Old Word doc magic bytes
		return bytes.HasPrefix(content, []byte("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"))
	case ".xls":
		// Old Excel magic bytes
		return bytes.HasPrefix(content, []byte("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) ||
			bytes.HasPrefix(content, []byte("\x09\x08\x10\x00\x00\x06\x05\x00"))
	case ".txt", ".csv":
		// Text files don't have magic bytes, always valid
		return true
	}

	return true // Unknown extension, assume valid
}

// extractTextFromPDFRaw extracts readable text from raw PDF bytes
// Used as fallback when pdftotext fails or is unavailable
func extractTextFromPDFRaw(content []byte) string {
	var textBuilder strings.Builder
	inText := false
	charCount := 0

	for _, b := range content {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			textBuilder.WriteByte(b)
			charCount++
			inText = true
		} else if inText && charCount > 3 {
			// End of text sequence, add a space
			textBuilder.WriteByte(' ')
			inText = false
			charCount = 0
		}
	}

	return textBuilder.String()
}

// extractTextFromDOCX extracts text from DOCX files (ZIP containing XML)
func extractTextFromDOCX(filePath string) (string, error) {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open DOCX as ZIP: %v", err)
	}
	defer r.Close()

	var textContent strings.Builder

	// Read word/document.xml which contains the main text
	for _, f := range r.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				continue
			}

			// Parse document XML
			type Text struct {
				XMLName xml.Name `xml:"t"`
				Content string   `xml:",chardata"`
			}
			type Document struct {
				XMLName xml.Name `xml:"document"`
				Text    []Text   `xml:"body>p>r>t"`
			}

			var doc Document
			if err := xml.NewDecoder(rc).Decode(&doc); err == nil {
				for _, t := range doc.Text {
					textContent.WriteString(t.Content)
					textContent.WriteString(" ")
				}
			}
			rc.Close()
			break
		}
	}

	extracted := strings.TrimSpace(textContent.String())
	if extracted == "" {
		return "", fmt.Errorf("no text content extracted from DOCX")
	}

	return extracted, nil
}

// downloadDocumentWithFallbacks attempts to download a document using multi-tier fallback mechanism
// Returns: content []byte, finalURL string (after redirects), error
// Tier 1: Enhanced HTTP client with browser simulation
// Tier 2: wget command-line tool (different network stack)
// Tier 3: curl command-line tool (alternative approach)
// Tier 4: Headless browser print (real Chrome-based fetch, PDF only)
// Tier 5: Streaming extraction without full download (last resort)
func (c *Config) downloadDocumentWithFallbacks(ctx context.Context, docURL string, ext string, parsedURL *url.URL) ([]byte, string, error) {
	console.Logv(c.Verbose, "[DOWNLOAD] Starting 5-tier fallback download system for: %s", docURL)

	// ==================== TIER 1: Enhanced HTTP Client ====================
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-1] HTTP client with browser simulation...")
	content, finalURL, err := c.downloadWithHTTPClient(ctx, docURL, ext, parsedURL)
	if err == nil && len(content) > 0 {
		console.Logv(c.Verbose, "[DOWNLOAD] [TIER-1] ✓ Success! Downloaded %d bytes", len(content))
		return content, finalURL, nil
	}
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-1] ✗ Failed: %v", err)

	// If WAF blocks with 403, jump straight to headless browser before shell tools
	if isHTTPStatusError(err, http.StatusForbidden) {
		console.Logv(c.Verbose, "[DOWNLOAD] [FAST-PATH] 403 detected, escalating to headless browser...")
		content, finalURL, err = c.downloadWithHeadlessBrowser(ctx, docURL, ext)
		if err == nil && len(content) > 0 {
			console.Logv(c.Verbose, "[DOWNLOAD] [FAST-PATH] ✓ Success! Downloaded %d bytes via headless browser", len(content))
			return content, finalURL, nil
		}
		console.Logv(c.Verbose, "[DOWNLOAD] [FAST-PATH] ✗ Headless browser failed: %v", err)
	}

	// ==================== TIER 2: wget Command-Line Tool ====================
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-2] Attempting wget (minimal flags)...")
	content, finalURL, err = c.downloadWithWget(ctx, docURL, ext)
	if err == nil && len(content) > 0 {
		console.Logv(c.Verbose, "[DOWNLOAD] [TIER-2] ✓ Success! Downloaded %d bytes via wget", len(content))
		return content, finalURL, nil
	}
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-2] ✗ Failed: %v", err)

	// ==================== TIER 3: curl Command-Line Tool ====================
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-3] Attempting curl fallback...")
	content, finalURL, err = c.downloadWithCurl(ctx, docURL, ext)
	if err == nil && len(content) > 0 {
		console.Logv(c.Verbose, "[DOWNLOAD] [TIER-3] ✓ Success! Downloaded %d bytes via curl", len(content))
		return content, finalURL, nil
	}
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-3] ✗ Failed: %v", err)

	// ==================== TIER 4: Headless Browser (Chrome/Chromium) ====================
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-4] Attempting headless browser print-to-PDF...")
	content, finalURL, err = c.downloadWithHeadlessBrowser(ctx, docURL, ext)
	if err == nil && len(content) > 0 {
		console.Logv(c.Verbose, "[DOWNLOAD] [TIER-4] ✓ Success! Downloaded %d bytes via headless browser", len(content))
		return content, finalURL, nil
	}
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-4] ✗ Failed: %v", err)

	// ==================== TIER 5: Streaming Extraction (Last Resort) ====================
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-5] Attempting streaming text extraction...")
	content, finalURL, err = c.downloadWithStreamingExtraction(ctx, docURL, ext)
	if err == nil && len(content) > 0 {
		console.Logv(c.Verbose, "[DOWNLOAD] [TIER-5] ✓ Success! Extracted %d bytes via streaming", len(content))
		return content, finalURL, nil
	}
	console.Logv(c.Verbose, "[DOWNLOAD] [TIER-5] ✗ Failed: %v", err)

	// All tiers failed
	return nil, "", fmt.Errorf("all 5 download tiers failed")
}

// downloadWithHTTPClient - Tier 1: Enhanced HTTP client with browser simulation
func (c *Config) downloadWithHTTPClient(ctx context.Context, docURL string, ext string, parsedURL *url.URL) ([]byte, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	// Create an HTTP client that mimics a real browser
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.Insecure,
		},
		DisableCompression:    false,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       0,
	}

	browserClient := &http.Client{
		Transport: transport,
		Timeout:   90 * time.Second,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if len(via) > 0 {
				for key, val := range via[0].Header {
					if key == "User-Agent" || key == "Accept" || key == "Accept-Language" {
						req.Header[key] = val
					}
				}
			}
			return nil
		},
	}

	// PROBE: HEAD request first
	// Warm-up: hit site root to collect cookies before probing the document (helps with 403s)
	if parsedURL != nil {
		warmupURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)
		if warmReq, err := http.NewRequestWithContext(reqCtx, "GET", warmupURL, nil); err == nil {
			warmReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			warmReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			warmReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
			warmReq.Header.Set("Connection", "keep-alive")
			warmReq.Header.Set("Upgrade-Insecure-Requests", "1")
			if resp, err := browserClient.Do(warmReq); err == nil && resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				console.Logv(c.Verbose, "[TIER-1] Warmed up cookies via %s (HTTP %d)", warmupURL, resp.StatusCode)
			}
		}
	}

	// PROBE: HEAD request first
	headReq, err := http.NewRequestWithContext(reqCtx, "HEAD", docURL, nil)
	if err == nil {
		headReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		headReq.Header.Set("Accept", "*/*")
		headReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
		headReq.Header.Set("Connection", "close") // Prevent connection reuse to avoid "Unsolicited response" errors
		headResp, err := browserClient.Do(headReq)
		if err == nil {
			defer headResp.Body.Close()
			// Only fail on 404 (not found) - HTTP 500 is often transient, so we'll still try GET
			if headResp.StatusCode == 404 {
				return nil, "", fmt.Errorf("probe failed with HTTP %d (not found)", headResp.StatusCode)
			}
			if headResp.StatusCode >= 500 {
				console.Logv(c.Verbose, "[TIER-1] Probe warning: HTTP %d (server error, will still attempt GET)", headResp.StatusCode)
			} else {
				console.Logv(c.Verbose, "[TIER-1] Probe successful (HTTP %d)", headResp.StatusCode)
			}
		}
	}

	// Download with retry logic using 5 different browser profiles
	var resp *http.Response
	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			console.Logv(c.Verbose, "[TIER-1] Retry %d/%d...", attempt+1, maxRetries)
			time.Sleep(time.Duration(2+attempt) * time.Second)
		}

		req, err := http.NewRequestWithContext(reqCtx, "GET", docURL, nil)
		if err != nil {
			if attempt == maxRetries-1 {
				return nil, "", err
			}
			continue
		}

		// Different browser profiles
		switch attempt {
		case 0:
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/pdf,application/octet-stream")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Sec-CH-UA", "\"Google Chrome\";v=\"120\", \"Chromium\";v=\"120\", \"Not=A?Brand\";v=\"24\"")
			req.Header.Set("Sec-CH-UA-Mobile", "?0")
			req.Header.Set("Sec-CH-UA-Platform", "\"Windows\"")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "close") // Prevent "Unsolicited response" errors
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Cache-Control", "max-age=0")
			req.Header.Set("Pragma", "no-cache")
		case 1:
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/pdf,application/octet-stream")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Sec-CH-UA", "\"Firefox\";v=\"121\", \"Not=A?Brand\";v=\"24\"")
			req.Header.Set("Sec-CH-UA-Mobile", "?0")
			req.Header.Set("Sec-CH-UA-Platform", "\"Windows\"")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "close") // Prevent "Unsolicited response" errors
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("DNT", "1")
			req.Header.Set("TE", "trailers")
		case 2:
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/pdf,application/octet-stream")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Sec-CH-UA", "\"Google Chrome\";v=\"120\", \"Chromium\";v=\"120\", \"Not=A?Brand\";v=\"24\"")
			req.Header.Set("Sec-CH-UA-Mobile", "?0")
			req.Header.Set("Sec-CH-UA-Platform", "\"macOS\"")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "close") // Prevent "Unsolicited response" errors
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "cross-site")
		case 3:
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,application/pdf,application/octet-stream")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Sec-CH-UA", "\"Safari\";v=\"17\", \"Not=A?Brand\";v=\"24\"")
			req.Header.Set("Sec-CH-UA-Mobile", "?0")
			req.Header.Set("Sec-CH-UA-Platform", "\"macOS\"")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "close") // Prevent "Unsolicited response" errors
			req.Header.Set("Pragma", "no-cache")
		case 4:
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/pdf,application/octet-stream")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Sec-CH-UA", "\"Microsoft Edge\";v=\"120\", \"Chromium\";v=\"120\", \"Not=A?Brand\";v=\"24\"")
			req.Header.Set("Sec-CH-UA-Mobile", "?0")
			req.Header.Set("Sec-CH-UA-Platform", "\"Windows\"")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "close") // Prevent "Unsolicited response" errors
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Cache-Control", "no-cache")
			req.Header.Set("Pragma", "no-cache")
		}
		if parsedURL != nil {
			referer := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)
			req.Header.Set("Referer", referer)
		}

		resp, err = browserClient.Do(req)
		if err != nil {
			if attempt == maxRetries-1 {
				return nil, "", err
			}
			continue
		}

		if resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode) // Let caller fast-path to headless
		}

		if resp.StatusCode == 200 || resp.StatusCode == http.StatusPartialContent {
			break // Success
		}

		resp.Body.Close()
		if attempt == maxRetries-1 {
			return nil, "", fmt.Errorf("HTTP %d after %d attempts", resp.StatusCode, maxRetries)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if resp.StatusCode == http.StatusPartialContent {
			// Accept partial content (Range) responses when servers require it
		} else {
			return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}

	// Read content
	const maxSize = 30 * 1024 * 1024
	content, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, "", err
	}

	if len(content) == 0 {
		return nil, "", fmt.Errorf("empty content")
	}

	// Validate content
	if !isValidDocumentContent(content, ext) {
		// Check for HTML redirect
		contentStr := string(content)
		if strings.Contains(strings.ToLower(contentStr), "<html") {
			downloadURL := extractDownloadURLFromHTML(contentStr, docURL)
			if downloadURL != "" {
				console.Logv(c.Verbose, "[TIER-1] HTML redirect detected, following: %s", downloadURL)
				// Recursive download with new URL
				return c.downloadDocumentWithFallbacks(ctx, downloadURL, ext, parsedURL)
			}
		}
		return nil, "", fmt.Errorf("invalid content type (got HTML or corrupted file)")
	}

	return content, resp.Request.URL.String(), nil
}

// downloadWithWget - Tier 2: wget command-line tool
func (c *Config) downloadWithWget(ctx context.Context, docURL string, ext string) ([]byte, string, error) {
	// Check if wget is available
	if _, err := exec.LookPath("wget"); err != nil {
		return nil, "", fmt.Errorf("wget not available: %v", err)
	}

	var referer string
	if parsed, err := url.Parse(docURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		referer = fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host)
	}

	// Create temporary file for output
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("banshee-wget-*%s", ext))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Build wget command with minimal flags (like manual wget)
	// NOTE: Extra headers and user-agents trigger anti-bot protection on some servers
	args := []string{
		"--timeout=90", // 90 second timeout
		"--tries=3",    // 3 retry attempts
		"-O", tmpPath,  // Output to temp file
		"-q", // Quiet mode (cleaner output)
	}

	// Add insecure flag if needed
	if c.Insecure {
		args = append(args, "--no-check-certificate")
	}
	if referer != "" {
		args = append(args, "--referer", referer)
	}

	args = append(args, docURL)

	// Execute wget
	cmd := exec.CommandContext(ctx, "wget", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Extract just the HTTP status from wget output for cleaner error messages
		outputStr := string(output)
		if strings.Contains(outputStr, "ERROR") {
			// Extract the error line only
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "ERROR") {
					return nil, "", fmt.Errorf("wget: %s", strings.TrimSpace(line))
				}
			}
		}
		return nil, "", fmt.Errorf("wget failed: %v", err)
	}

	// Read the downloaded file
	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read wget output: %v", err)
	}

	if len(content) == 0 {
		return nil, "", fmt.Errorf("wget downloaded empty file")
	}

	// Validate content
	if !isValidDocumentContent(content, ext) {
		contentStr := string(content)
		if strings.Contains(strings.ToLower(contentStr), "<html") {
			downloadURL := extractDownloadURLFromHTML(contentStr, docURL)
			if downloadURL != "" {
				console.Logv(c.Verbose, "[TIER-2] HTML redirect detected, following: %s", downloadURL)
				return c.downloadDocumentWithFallbacks(ctx, downloadURL, ext, nil)
			}
		}
		return nil, "", fmt.Errorf("invalid content type")
	}

	return content, docURL, nil
}

// downloadWithCurl - Tier 3: curl command-line tool
func (c *Config) downloadWithCurl(ctx context.Context, docURL string, ext string) ([]byte, string, error) {
	return c.downloadWithCurlUsingCookies(ctx, docURL, ext, "")
}

// downloadWithCurlUsingCookies allows passing a cookie file for authenticated fetches.
func (c *Config) downloadWithCurlUsingCookies(ctx context.Context, docURL string, ext string, cookieFile string) ([]byte, string, error) {
	// Check if curl is available
	if _, err := exec.LookPath("curl"); err != nil {
		return nil, "", fmt.Errorf("curl not available: %v", err)
	}

	var referer string
	if parsed, err := url.Parse(docURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		referer = fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host)
	}

	// Create temporary file for output
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("banshee-curl-*%s", ext))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Build curl command
	args := []string{
		"-L",                 // Follow redirects
		"--max-redirs", "10", // Max 10 redirects
		"--max-time", "90", // 90 second timeout
		"--retry", "3", // 3 retry attempts
		"--retry-delay", "2", // 2 seconds between retries
		"--compressed", // Enable compression
		"-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,application/octet-stream,*/*;q=0.8",
		"-H", "Accept-Language: en-US,en;q=0.9",
		"-H", "Sec-CH-UA: \"Google Chrome\";v=\"120\", \"Chromium\";v=\"120\", \"Not=A?Brand\";v=\"24\"",
		"-H", "Sec-CH-UA-Mobile: ?0",
		"-H", "Sec-CH-UA-Platform: \"Windows\"",
		"-H", "Sec-Fetch-Site: same-origin",
		"-H", "Sec-Fetch-Mode: navigate",
		"-H", "Sec-Fetch-Dest: document",
		"-H", "Sec-Fetch-User: ?1",
		"-H", "Upgrade-Insecure-Requests: 1",
		"-H", "Cache-Control: no-cache",
		"-H", "Pragma: no-cache",
		"-o", tmpPath, // Output to temp file
		"-s", // Silent mode
		"-S", // Show errors
	}

	// Add insecure flag if needed
	if c.Insecure {
		args = append(args, "-k")
	}
	if referer != "" {
		args = append(args, "-e", referer)
	}
	if cookieFile != "" {
		args = append(args, "-b", cookieFile)
	}

	args = append(args, docURL)

	// Execute curl
	cmd := exec.CommandContext(ctx, "curl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Clean error message (curl's stderr is often verbose)
		outputStr := strings.TrimSpace(string(output))
		if len(outputStr) > 100 {
			outputStr = outputStr[:100] + "..."
		}
		if outputStr != "" {
			return nil, "", fmt.Errorf("curl: %s", outputStr)
		}
		return nil, "", fmt.Errorf("curl failed: %v", err)
	}

	// Read the downloaded file
	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read curl output: %v", err)
	}

	if len(content) == 0 {
		return nil, "", fmt.Errorf("curl downloaded empty file")
	}

	// Validate content
	if !isValidDocumentContent(content, ext) {
		contentStr := string(content)
		if strings.Contains(strings.ToLower(contentStr), "<html") {
			downloadURL := extractDownloadURLFromHTML(contentStr, docURL)
			if downloadURL != "" {
				console.Logv(c.Verbose, "[TIER-3] HTML redirect detected, following: %s", downloadURL)
				return c.downloadDocumentWithFallbacks(ctx, downloadURL, ext, nil)
			}
		}
		return nil, "", fmt.Errorf("invalid content type")
	}

	return content, docURL, nil
}

// downloadWithStreamingExtraction - Tier 4: Stream and extract text without full download
// This is a last resort that tries to extract text directly from streaming content
func (c *Config) downloadWithStreamingExtraction(ctx context.Context, docURL string, ext string) ([]byte, string, error) {
	// Only works for PDFs with pdftotext
	if ext != ".pdf" {
		return nil, "", fmt.Errorf("streaming extraction only supported for PDFs")
	}

	// Check if required tools are available
	if _, err := exec.LookPath("curl"); err != nil {
		return nil, "", fmt.Errorf("curl not available: %v", err)
	}
	if _, err := exec.LookPath("pdftotext"); err != nil {
		return nil, "", fmt.Errorf("pdftotext not available: %v", err)
	}

	var streamReferer string
	if parsed, err := url.Parse(docURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		streamReferer = fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host)
	}

	// Create a pipe: curl | pdftotext -layout -nopgbrk - -
	// This streams the PDF and extracts text without saving to disk
	curlCmd := exec.CommandContext(ctx, "curl",
		"-L",                 // Follow redirects
		"--max-redirs", "10", // Max 10 redirects
		"--max-time", "90", // 90 second timeout
		"-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"-H", "Accept: application/pdf,application/octet-stream,*/*;q=0.8",
		"-s", // Silent mode
		"-S", // Show errors
	)
	if streamReferer != "" {
		curlCmd.Args = append(curlCmd.Args, "-e", streamReferer)
	}
	curlCmd.Args = append(curlCmd.Args, docURL)

	pdftotextCmd := exec.CommandContext(ctx, "pdftotext",
		"-layout",  // Maintain layout
		"-nopgbrk", // No page breaks
		"-",        // Read from stdin
		"-",        // Write to stdout
	)

	// Connect the pipe
	pipe, err := curlCmd.StdoutPipe()
	if err != nil {
		return nil, "", fmt.Errorf("failed to create pipe: %v", err)
	}
	pdftotextCmd.Stdin = pipe

	var extractedBuf bytes.Buffer
	pdftotextCmd.Stdout = &extractedBuf

	// Start both commands
	if err := curlCmd.Start(); err != nil {
		return nil, "", fmt.Errorf("failed to start curl: %v", err)
	}
	if err := pdftotextCmd.Start(); err != nil {
		curlCmd.Process.Kill()
		return nil, "", fmt.Errorf("failed to start pdftotext: %v", err)
	}

	// Wait for curl to finish
	if err := curlCmd.Wait(); err != nil {
		return nil, "", fmt.Errorf("curl failed: %v", err)
	}
	// Wait for pdftotext to finish
	if err := pdftotextCmd.Wait(); err != nil {
		return nil, "", fmt.Errorf("pdftotext failed: %v", err)
	}

	extractedText := extractedBuf.Bytes()

	if len(extractedText) < 50 {
		return nil, "", fmt.Errorf("insufficient text extracted (< 50 chars)")
	}

	// Return the extracted text as "content"
	// Note: This is text content, not the original PDF binary
	return extractedText, docURL, nil
}

// isHTTPStatusError detects if an error message contains a specific HTTP status code.
func isHTTPStatusError(err error, code int) bool {
	if err == nil {
		return false
	}
	statusStr := fmt.Sprintf("HTTP %d", code)
	return strings.Contains(err.Error(), statusStr)
}

// looksLikeChallengePage tries to detect common bot/WAF interstitial HTML pages.
func looksLikeChallengePage(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	snippet := strings.ToLower(string(content[:min(len(content), 4096)]))
	keywords := []string{
		"cloudflare",
		"just a moment",
		"verify you are human",
		"checking your browser",
		"attention required",
		"captcha",
		"cf-chl-",
		"request unsuccessful",
	}
	for _, kw := range keywords {
		if strings.Contains(snippet, kw) {
			return true
		}
	}
	return false
}

// exportChromeCookies exports cookies from a Chrome/Chromium profile into a temporary Netscape-format cookie file.
func exportChromeCookies(profileDir string) (string, error) {
	cookieDB := filepath.Join(profileDir, "Default", "Cookies")
	if _, err := os.Stat(cookieDB); err != nil {
		return "", fmt.Errorf("cookie DB not found: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "banshee-cookies-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp cookie file: %v", err)
	}
	defer tmpFile.Close()

	query := `
SELECT
  host_key,
  CASE WHEN host_key LIKE '.%' THEN 'TRUE' ELSE 'FALSE' END,
  path,
  CASE is_secure WHEN 1 THEN 'TRUE' ELSE 'FALSE' END,
  CASE expires_utc WHEN 0 THEN 0 ELSE (expires_utc/1000000 - 11644473600) END,
  name,
  value
FROM cookies;
`

	cmd := exec.Command("sqlite3", "-separator", "\t", cookieDB, query)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlite3 export failed: %v (%s)", err, strings.TrimSpace(string(output)))
	}

	builder := strings.Builder{}
	builder.WriteString("# Netscape HTTP Cookie File\n")
	builder.Write(output)

	if _, err := tmpFile.WriteString(builder.String()); err != nil {
		return "", fmt.Errorf("failed to write cookie file: %v", err)
	}

	return tmpFile.Name(), nil
}

// downloadWithHTTPClientUsingCookies loads cookies from a Netscape file and replays the request with the browser-like client.
func (c *Config) downloadWithHTTPClientUsingCookies(ctx context.Context, docURL string, ext string, cookieFile string) ([]byte, string, error) {
	jar, _ := cookiejar.New(nil)
	file, err := os.Open(cookieFile)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			continue
		}
		domain := parts[0]
		path := parts[2]
		name := parts[5]
		value := parts[6]
		u, err := url.Parse(docURL)
		if err != nil {
			continue
		}
		if !strings.HasSuffix(u.Hostname(), strings.TrimPrefix(domain, ".")) {
			continue
		}
		cookie := &http.Cookie{
			Name:  name,
			Value: value,
			Domain: func() string {
				if strings.HasPrefix(domain, ".") {
					return domain
				}
				return "." + domain
			}(),
			Path: path,
		}
		jar.SetCookies(u, append(jar.Cookies(u), cookie))
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.Insecure,
		},
		DisableCompression:    false,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       0,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   90 * time.Second,
		Jar:       jar,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", docURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,application/octet-stream,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	if parsed, err := url.Parse(docURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		req.Header.Set("Referer", fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	const maxSize = 30 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, "", err
	}
	if len(body) == 0 {
		return nil, "", fmt.Errorf("empty content")
	}
	if !isValidDocumentContent(body, ext) {
		return nil, "", fmt.Errorf("invalid content type")
	}

	return body, resp.Request.URL.String(), nil
}

// findHeadlessBrowser looks for a Chrome/Chromium binary that can run headless.
func findHeadlessBrowser() (string, error) {
	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"chrome",
		"msedge",
	}

	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("headless browser binary not found (google-chrome/chromium)")
}

// downloadWithHeadlessBrowser - Tier 4: use real Chrome/Chromium in headless mode
// Useful for WAF-protected endpoints that only allow fully-fledged browsers.
// Only supports PDFs (uses print-to-pdf).
func (c *Config) downloadWithHeadlessBrowser(ctx context.Context, docURL string, ext string) ([]byte, string, error) {
	if ext != ".pdf" {
		return nil, "", fmt.Errorf("headless browser fallback only supports PDFs")
	}

	browserPath, err := findHeadlessBrowser()
	if err != nil {
		return nil, "", err
	}

	tmpDir, err := os.MkdirTemp("", "banshee-headless-*")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp dir for headless browser: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	profileDir := filepath.Join(tmpDir, "profile")
	cacheDir := filepath.Join(tmpDir, "cache")

	baseUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	baseArgs := []string{
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--disable-features=IsolateOrigins,site-per-process,TranslateUI,EnableAutomation",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-default-apps",
		"--disable-sync",
		"--metrics-recording-only",
		"--disable-component-update",
		"--use-mock-keychain",
		"--password-store=basic",
		"--user-data-dir=" + profileDir,
		"--disk-cache-dir=" + cacheDir,
		"--hide-scrollbars",
		"--mute-audio",
		"--window-size=1920,1080",
		"--lang=en-US",
		"--no-first-run",
		"--enable-features=NetworkService,NetworkServiceInProcess",
		"--virtual-time-budget=20000",
		"--user-agent=" + baseUA,
	}

	if c.Insecure {
		baseArgs = append([]string{"--allow-running-insecure-content", "--ignore-certificate-errors"}, baseArgs...)
	}

	// Warm-up: visit the document URL (not just the root) to let JS challenges set cookies.
	warmArgs := append([]string{"--headless=new", "--disable-blink-features=AutomationControlled"}, baseArgs...)
	warmArgs = append(warmArgs, "--enable-features=NetworkService,NetworkServiceInProcess", docURL, "--dump-dom")

	cmdWarm := exec.CommandContext(ctx, browserPath, warmArgs...)
	cmdWarm.Env = append(os.Environ(), "LANG=en_US.UTF-8")
	// Provide extra fetch headers via env so some WAFs that test header presence pass
	cmdWarm.Env = append(cmdWarm.Env,
		"HTTP_ACCEPT=text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,application/octet-stream,*/*;q=0.8",
		"HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.9",
		"HTTP_CACHE_CONTROL=no-cache",
		"HTTP_PRAGMA=no-cache",
	)
	if output, err := cmdWarm.CombinedOutput(); err == nil {
		console.Logv(c.Verbose, "[TIER-4] Warmed headless profile via %s", docURL)
	} else {
		console.Logv(c.Verbose, "[TIER-4] Warmup visit failed (continuing): %s", strings.TrimSpace(string(output)))
	}
	time.Sleep(2 * time.Second) // allow JS challenges to complete

	// After warmup, try fetching with curl using the warmed cookies from Chrome profile.
	cookieFile, err := exportChromeCookies(profileDir)
	if err == nil {
		defer os.Remove(cookieFile)
		if content, finalURL, curlErr := c.downloadWithCurlUsingCookies(ctx, docURL, ext, cookieFile); curlErr == nil && len(content) > 0 {
			return content, finalURL, nil
		} else if curlErr != nil {
			console.Logv(c.Verbose, "[TIER-4] curl-with-cookies failed: %v", curlErr)
		}
		// Try HTTP client with imported cookies as an additional attempt
		if content, finalURL, httpErr := c.downloadWithHTTPClientUsingCookies(ctx, docURL, ext, cookieFile); httpErr == nil && len(content) > 0 {
			return content, finalURL, nil
		} else if httpErr != nil {
			console.Logv(c.Verbose, "[TIER-4] HTTP-with-cookies failed: %v", httpErr)
		}
	} else {
		console.Logv(c.Verbose, "[TIER-4] Failed to export cookies: %v", err)
	}

	attempts := []struct {
		name string
		args []string
	}{
		{
			name: "new-headless-stealth",
			args: []string{
				"--headless=new",
				"--disable-blink-features=AutomationControlled",
				"--disable-features=AutomationControlled,EnableAutomation",
			},
		},
		{
			name: "legacy-headless-stealth",
			args: []string{
				"--headless=chrome",
				"--disable-blink-features=AutomationControlled",
				"--disable-features=AutomationControlled,EnableAutomation",
			},
		},
	}

	for _, attempt := range attempts {
		outputPath := filepath.Join(tmpDir, fmt.Sprintf("capture-%s.pdf", attempt.name))
		args := append([]string{}, attempt.args...)
		args = append(args, baseArgs...)
		args = append(args, fmt.Sprintf("--print-to-pdf=%s", outputPath), docURL)

		cmd := exec.CommandContext(ctx, browserPath, args...)
		cmd.Env = append(os.Environ(), "LANG=en_US.UTF-8")

		// Allow JS/WAF to settle: give more time than navigation default using env flag
		cmd.Env = append(cmd.Env, "CHROME_HEADLESS_WAIT_MS=15000")

		output, err := cmd.CombinedOutput()
		if err != nil {
			outStr := strings.TrimSpace(string(output))
			if outStr == "" {
				outStr = err.Error()
			}
			console.Logv(c.Verbose, "[TIER-4] %s failed: %s", attempt.name, outStr)
			continue
		}

		content, err := os.ReadFile(outputPath)
		if err != nil {
			console.Logv(c.Verbose, "[TIER-4] %s failed to read output: %v", attempt.name, err)
			continue
		}

		if len(content) == 0 {
			console.Logv(c.Verbose, "[TIER-4] %s produced empty output", attempt.name)
			continue
		}

		if !isValidDocumentContent(content, ext) {
			if looksLikeChallengePage(content) {
				console.Logv(c.Verbose, "[TIER-4] %s output looks like WAF challenge HTML; retrying with alternate headless mode", attempt.name)
				continue
			}
			console.Logv(c.Verbose, "[TIER-4] %s output invalid content type", attempt.name)
			continue
		}

		// Detect PDFs that are actually challenge pages rendered as PDF
		if ext == ".pdf" {
			rawText := strings.ToLower(extractTextFromPDFRaw(content))
			if looksLikeChallengePage([]byte(rawText)) {
				console.Logv(c.Verbose, "[TIER-4] %s PDF content looks like a WAF challenge; retrying with alternate headless mode", attempt.name)
				continue
			}
		}

		return content, docURL, nil
	}

	return nil, "", fmt.Errorf("headless browser failed: all attempts blocked or invalid")
}

// analyzeDocumentForSensitiveInfo analyzes a document URL for sensitive information
func (c *Config) analyzeDocumentForSensitiveInfo(ctx context.Context, docURL string) {
	// Check if it's a document
	ext := documentExtFromURL(docURL)
	textLikeExt := textLikeDocumentExts[ext]

	if !documentExts[ext] {
		console.Logv(c.Verbose, "[DOC-ANALYZE] Skipping (not a document, ext=%s): %s", ext, docURL)
		return // Not a document, skip
	}

	// If --filter-docs is enabled, filter out non-sensitive documents
	// Text-like extensions are cheap to scan; skip filtering for those.
	if c.FilterDocs && !textLikeExt {
		// Load non-sensitive keywords (cached for performance)
		keywords, err := LoadNonSensitiveKeywords()
		if err != nil {
			console.Logv(c.Verbose, "[DOC-ANALYZE] Warning: Failed to load filter Keywords: %v", err)
		} else {
			// Check if document should be filtered out
			if ShouldFilterDocument(docURL, keywords) {
				console.Logv(c.Verbose, "[DOC-ANALYZE] Filtered out (non-sensitive): %s", docURL)
				return
			}
		}
	}

	// Add visual separator for better readability
	if c.Verbose {
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════")
	}

	// Always show that we're analyzing (for documents that pass filter)
	console.Logv(c.Verbose, "[DOC-ANALYZE] Analyzing: %s", docURL)

	// FIX: Properly encode the URL to handle spaces and special characters
	// Parse the URL to separate components
	parsedURL, err := url.Parse(docURL)
	if err != nil {
		console.Logv(c.Verbose, "[DOC-ANALYZE] ✗ Failed to parse URL: %v", err)
		return
	}

	// Re-encode the path to ensure proper encoding (spaces -> %20, etc.)
	// url.Parse doesn't automatically encode, so we need to do it manually
	// Split path into segments and encode each one
	originalURL := docURL
	pathSegments := strings.Split(parsedURL.Path, "/")
	for i, segment := range pathSegments {
		pathSegments[i] = url.PathEscape(segment)
	}
	parsedURL.Path = strings.Join(pathSegments, "/")

	// Also encode the query string if present
	if parsedURL.RawQuery != "" {
		values, _ := url.ParseQuery(parsedURL.RawQuery)
		parsedURL.RawQuery = values.Encode()
	}

	// Use the properly encoded URL for all subsequent operations
	docURL = parsedURL.String()
	// Only log if the URL actually changed
	if docURL != originalURL {
		console.Logv(c.Verbose, "[DOC-ANALYZE] Encoded URL: %s", docURL)
	}

	// Use 5-tier fallback download system
	// Tier 1: Enhanced HTTP client with browser simulation
	// Tier 2: wget command-line tool (different network stack)
	// Tier 3: curl command-line tool (alternative approach)
	// Tier 4: Headless browser print-to-PDF (real Chrome/Chromium)
	// Tier 5: Streaming extraction without full download
	content, finalURL, err := c.downloadDocumentWithFallbacks(ctx, docURL, ext, parsedURL)
	if err != nil {
		console.Logv(c.Verbose, "[DOC-ANALYZE] ✗ Failed: %v", err)
		return
	}

	// If we got a PDF that smells like a WAF challenge, force a headless fetch to try to get the real file.
	if ext == ".pdf" && looksLikeChallengePage([]byte(strings.ToLower(extractTextFromPDFRaw(content)))) {
		console.Logv(c.Verbose, "[DOC-ANALYZE] Detected possible WAF challenge in downloaded PDF; retrying with headless browser")
		if altContent, altURL, altErr := c.downloadWithHeadlessBrowser(ctx, docURL, ext); altErr == nil && len(altContent) > 0 {
			content = altContent
			finalURL = altURL
			console.Logv(c.Verbose, "[DOC-ANALYZE] Replaced PDF with headless browser download (%d bytes)", len(content))
		} else if altErr != nil {
			console.Logv(c.Verbose, "[DOC-ANALYZE] Headless retry failed, keeping original PDF: %v", altErr)
		}
	}

	console.Logv(c.Verbose, "[DOC-ANALYZE] ✓ Successfully downloaded %d bytes from: %s", len(content), finalURL)

	// Short-circuit for text-like formats (no need to write to disk)
	if textLikeExt {
		// Try decompressing if the server sent gzip-compressed bytes
		if len(content) > 2 && content[0] == 0x1f && content[1] == 0x8b {
			if gzReader, err := gzip.NewReader(bytes.NewReader(content)); err == nil {
				if decompressed, err := io.ReadAll(gzReader); err == nil {
					content = decompressed
				}
				gzReader.Close()
			}
		}

		extractedText := string(content)
		if len(extractedText) < 50 {
			console.Logv(c.Verbose, "[DOC-ANALYZE] Insufficient text after extraction (< 50 chars)")
			return
		}
		c.analyzeExtractedDocumentText(ctx, ext, docURL, extractedText)
		return
	}

	// Create domain-specific temp directory: /tmp/{domain}/
	// Using domain name (plaintext) for better organization and debugging
	domain := parsedURL.Host
	if domain == "" {
		domain = "unknown"
	}
	// Sanitize domain name for filesystem (replace invalid chars with _)
	domain = strings.ReplaceAll(domain, ":", "_")
	domain = strings.ReplaceAll(domain, "/", "_")
	tmpDir := filepath.Join("/tmp", domain)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		console.Logv(c.Verbose, "[DOC-ANALYZE] Failed to create temp directory: %v", err)
		return
	}

	// Get filename from URL path and decode it (to convert %20 back to spaces, etc.)
	filename := filepath.Base(parsedURL.Path)
	// URL decode the filename for proper filesystem naming
	if decodedFilename, err := url.PathUnescape(filename); err == nil {
		filename = decodedFilename
	}
	if filename == "" || filename == "/" {
		filename = fmt.Sprintf("document%s", ext)
	}

	// Save document with actual filename
	tmpFilePath := filepath.Join(tmpDir, filename)
	if err := os.WriteFile(tmpFilePath, content, 0644); err != nil {
		console.Logv(c.Verbose, "[DOC-ANALYZE] Failed to write document: %v", err)
		return
	}
	defer os.Remove(tmpFilePath) // Clean up after analysis

	console.Logv(c.Verbose, "[DOC-ANALYZE] Saved to: %s", tmpFilePath)

	// Extract text based on file type
	var extractedText string

	switch ext {
	case ".pdf":
		// Try pdftotext first
		if _, err := exec.LookPath("pdftotext"); err == nil {
			cmd := exec.CommandContext(ctx, "pdftotext", "-layout", "-nopgbrk", tmpFilePath, "-")
			output, err := cmd.CombinedOutput()
			if err == nil && len(output) > 50 {
				extractedText = string(output)
				console.Logv(c.Verbose, "[DOC-ANALYZE] Extracted %d chars from PDF using pdftotext", len(extractedText))
			} else {
				// pdftotext failed, use fallback immediately
				if err != nil {
					console.Logv(c.Verbose, "[DOC-ANALYZE] pdftotext failed, using fallback - error: %s", string(output))
				}
				extractedText = extractTextFromPDFRaw(content)
				console.Logv(c.Verbose, "[DOC-ANALYZE] Fallback extracted %d chars from PDF raw content", len(extractedText))
			}
		} else {
			// pdftotext not available, use fallback
			extractedText = extractTextFromPDFRaw(content)
			console.Logv(c.Verbose, "[DOC-ANALYZE] pdftotext not available, fallback extracted %d chars", len(extractedText))
		}
	case ".docx":
		// DOCX is a ZIP file containing XML
		extracted, err := extractTextFromDOCX(tmpFilePath)
		if err != nil {
			console.Logv(c.Verbose, "[DOC-ANALYZE] DOCX extraction failed: %v, using raw content", err)
			extractedText = extractTextFromPDFRaw(content) // Use same raw extraction
		} else {
			extractedText = extracted
			console.Logv(c.Verbose, "[DOC-ANALYZE] Extracted %d chars from DOCX", len(extractedText))
		}
	case ".txt", ".csv":
		extractedText = string(content)
		console.Logv(c.Verbose, "[DOC-ANALYZE] Extracted %d chars from text file", len(extractedText))
	case ".xlsx", ".xls":
		// Try to extract text from Excel files
		extracted, err := extractTextFromXLSX(tmpFilePath)
		if err != nil {
			console.Logv(c.Verbose, "[DOC-ANALYZE] XLSX extraction failed: %v, using raw content", err)
			extractedText = extractTextFromPDFRaw(content) // Use same raw extraction
		} else {
			extractedText = extracted
			console.Logv(c.Verbose, "[DOC-ANALYZE] Extracted %d chars from XLSX", len(extractedText))
		}
	case ".doc", ".pptx", ".ppt":
		// For older formats, use raw extraction
		extractedText = extractTextFromPDFRaw(content)
		console.Logv(c.Verbose, "[DOC-ANALYZE] Extracted %d chars from %s using raw method", len(extractedText), ext)
	default:
		// Unknown format - try raw content
		extractedText = string(content)
	}

	c.analyzeExtractedDocumentText(ctx, ext, docURL, extractedText)
}

// analyzeExtractedDocumentText runs AI analysis on already extracted text content
func (c *Config) analyzeExtractedDocumentText(ctx context.Context, ext string, docURL string, extractedText string) {
	// Final check: if still insufficient text, skip
	if len(extractedText) < 50 {
		console.Logv(c.Verbose, "[DOC-ANALYZE] Insufficient text after extraction (< 50 chars)")
		return
	}

	// Limit text to 4000 chars for AI analysis (to avoid token limits)
	if len(extractedText) > 4000 {
		extractedText = extractedText[:4000] + "... [truncated]"
	}

	// Analyze with AI for sensitive information
	prompt := fmt.Sprintf(`You are classifying documents for SECURITY sensitivity. Be strict and avoid false positives.

Rules:
- Sensitive ONLY if there are credentials/secrets (passwords, tokens, API keys), authentication artifacts, personal identifiers beyond public contact info (SSN, full DOB, address+name, passport, gov ID), financial/confidential data, internal configuration, or exploitable technical details.
- Public contact info alone (emails, names, phone numbers without accompanying private IDs/credentials) is NOT sensitive.
- Academic papers, marketing brochures, and public policy docs are usually NOT sensitive unless they include secrets/PII as defined above.

Analyze this document content and provide:
1. A brief summary of what the document is about (1-2 sentences)
2. Whether it contains sensitive information per the strict rules above

Document content:
%s

REQUIRED FORMAT - You must return exactly this structure:

SUMMARY: [Brief description of what the document is about]
SENSITIVE: [YES or NO]
DETAILS: [If YES, describe what sensitive information was found: API keys, credentials, PII (SSNs, full DOB, addresses), secrets, internal configs, financial data. If NO, write "None"]`, extractedText)

	// Call gemini-cli for analysis
	var args []string
	if c.AiModel != "" {
		args = []string{"--model", c.AiModel}
	} else {
		args = []string{}
	}

	cmd := exec.CommandContext(ctx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Env = os.Environ()

	output, err := cmd.Output()
	if err != nil {
		console.Logv(c.Verbose, "[DOC-ANALYZE] AI analysis failed: %v", err)
		return
	}

	result := strings.TrimSpace(string(output))
	if result == "" {
		console.Logv(c.Verbose, "[DOC-ANALYZE] Empty AI response")
		return
	}

	// Parse the structured response
	var summary, sensitive, details string
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SUMMARY:") {
			summary = strings.TrimSpace(strings.TrimPrefix(line, "SUMMARY:"))
		} else if strings.HasPrefix(line, "SENSITIVE:") {
			sensitive = strings.TrimSpace(strings.TrimPrefix(line, "SENSITIVE:"))
		} else if strings.HasPrefix(line, "DETAILS:") {
			details = strings.TrimSpace(strings.TrimPrefix(line, "DETAILS:"))
		}
	}

	// Determine if sensitive info was found
	isSensitive := strings.ToUpper(sensitive) == "YES" && details != "None" && details != ""

	// Heuristic downgrade: if AI only mentions emails/contact info without stronger indicators, treat as safe
	if isSensitive {
		lowerDetails := strings.ToLower(details)
		strongIndicators := []string{
			"password", "pwd", "passwd", "secret", "token", "api key", "apikey", "credential",
			"ssn", "social security", "passport", "driver", "national id", "dob", "date of birth",
			"private key", "jwt", "bearer", "oauth", "sso", "auth", "login", "username",
			"financial", "bank", "account number", "iban", "routing",
		}

		hasStrong := false
		for _, kw := range strongIndicators {
			if strings.Contains(lowerDetails, kw) {
				hasStrong = true
				break
			}
		}

		onlyEmails := strings.Contains(lowerDetails, "email") || strings.Contains(lowerDetails, "e-mail")
		if onlyEmails && !hasStrong {
			isSensitive = false
			if c.Verbose {
				console.Logv(c.Verbose, "[DOC-ANALYZE] Downgraded to safe: only contact emails detected without credentials/PII")
			}
		}
	}

	// Save sensitive documents to tracking files
	if isSensitive {
		// Save to sensitive-pdfs.txt (detailed tracking)
		if err := saveSensitiveDocument(docURL, summary, details); err != nil {
			console.Logv(c.Verbose, "[DOC-ANALYZE] Warning: Failed to save to tracking file: %v", err)
		}

		// Save to successful.txt (AI learning)
		// Extract concise finding type from details
		findingType := "Sensitive document"
		conciseDetails := details
		if len(details) > 100 {
			conciseDetails = details[:100] + "..."
		}
		if err := saveSuccessfulURL(docURL, findingType, conciseDetails); err != nil {
			console.Logv(c.Verbose, "[DOC-ANALYZE] Warning: Failed to save to successful.txt: %v", err)
		}
	}

	// Output based on verbose mode and sensitivity
	if c.Verbose {
		// In verbose mode: show summary for ALL documents
		if isSensitive {
			fmt.Printf("%s[RESULT] ✓ SENSITIVE%s | %sURL:%s %s\n", console.ColorRed, console.ColorReset, console.ColorYellow, console.ColorReset, docURL)
			fmt.Printf("  %sSummary:%s %s\n", console.ColorYellow, console.ColorReset, summary)
			fmt.Printf("  %s⚠  Details:%s %s\n", console.ColorRed, console.ColorReset, details)
		} else {
			fmt.Printf("%s[RESULT] ✗ Safe%s | %sURL:%s %s\n", console.ColorGreen, console.ColorReset, console.ColorCyan, console.ColorReset, docURL)
			fmt.Printf("  %sSummary:%s %s\n", console.ColorCyan, console.ColorReset, summary)
		}
		os.Stdout.Sync()
	} else {
		// In non-verbose mode: only show documents with sensitive information
		if isSensitive {
			fmt.Printf("Document contains sensitive information: %s | %s\n", docURL, details)
			os.Stdout.Sync()
		}
	}
}
