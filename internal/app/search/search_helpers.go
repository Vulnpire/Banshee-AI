package search

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
	"banshee/internal/app/utils"
)

func (c *Config) debugBraveResponse(body []byte, statusCode int) {
	if c.Verbose {
		console.LogErr("[DEBUG] Brave Response Status: %d", statusCode)
		console.LogErr("[DEBUG] Brave Response Body: %s", string(body))
	}
}

func (c *Config) readApiKeysFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		keys = append(keys, line)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("no API keys in file")
	}
	c.ApiKeys = keys
	return nil
}

func waitForKeyRefresh(ctx context.Context, engine string, verbose bool) error {
	return utils.WaitForKeyRefresh(ctx, engine, verbose)
}

func (c *Config) getRandomApiKey() (string, error) {
	available := make([]string, 0, len(c.ApiKeys))
	for _, k := range c.ApiKeys {
		if _, ex := c.ExhaustedKeys[k]; !ex {
			available = append(available, k)
		}
	}
	if len(available) == 0 {
		return "", errors.New("no available API keys left. All keys have exceeded their quota")
	}
	// Rotate pseudo-randomly by time
	idx := int(time.Now().UnixNano()) % len(available)
	return available[idx], nil
}

// --- Query builders ---

func buildExclusions(exclusions string, multiline bool) string {
	// Build exclusion string with smart detection:
	// - File extensions (pdf, doc, etc) → -ext:pdf
	// - Subdomains/domains (www, admin.example.com) → -site:xxx or -www
	var parts []string
	if fileExists(exclusions) {
		lines, _ := readLines(exclusions)
		for _, ex := range lines {
			ex = strings.TrimSpace(ex)
			if ex == "" {
				continue
			}
			parts = append(parts, ex)
		}
	} else if strings.Contains(exclusions, ",") {
		for _, ex := range strings.Split(exclusions, ",") {
			ex = strings.TrimSpace(ex)
			if ex == "" {
				continue
			}
			parts = append(parts, ex)
		}
	} else {
		parts = append(parts, strings.TrimSpace(exclusions))
	}

	// Build exclusion string with smart prefixes
	var result []string
	for _, part := range parts {
		result = append(result, formatExclusion(part))
	}

	return strings.Join(result, " ")
}

// formatExclusion determines the correct exclusion syntax based on the input
func formatExclusion(exclusion string) string {
	// Special case: "www" → just "-www"
	if exclusion == "www" {
		return "-www"
	}

	// Check if it's a file extension (no dots and common extensions)
	if !strings.Contains(exclusion, ".") && isFileExtension(exclusion) {
		return "-ext:" + exclusion
	}

	// Otherwise treat as domain/subdomain
	return "-site:" + exclusion
}

// isFileExtension checks if a string looks like a file extension
func isFileExtension(s string) bool {
	// Common file extensions to detect
	commonExts := []string{
		"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
		"txt", "csv", "xml", "json", "yml", "yaml",
		"zip", "tar", "gz", "rar", "7z",
		"jpg", "jpeg", "png", "gif", "bmp", "svg",
		"mp4", "avi", "mov", "mp3", "wav",
		"exe", "dll", "so", "bin",
		"html", "htm", "php", "asp", "aspx", "jsp",
	}

	s = strings.ToLower(s)
	for _, ext := range commonExts {
		if s == ext {
			return true
		}
	}

	// If it's 2-5 characters and alphanumeric, likely an extension
	if len(s) >= 2 && len(s) <= 5 {
		for _, c := range s {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				return false
			}
		}
		return true
	}

	return false
}

func buildContentsQuery(contents string) string {
	// Build intext:"..." OR intext:"a" OR intext:"a" OR intext:"b" style
	// When file: each line becomes its own search later; here we return a single term.
	// For a single value or comma-separated, build using logical OR (|) as Google supports OR.
	if fileExists(contents) {
		// Caller iterates per line; here return placeholder for single value path.
		lines, _ := readLines(contents)
		if len(lines) > 0 {
			// first line
			return fmt.Sprintf(`intext:"%s"`, lines[0])
		}
		return ""
	}
	if strings.Contains(contents, ",") {
		parts := []string{}
		for _, s := range strings.Split(contents, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				parts = append(parts, fmt.Sprintf(`intext:"%s"`, s))
			}
		}
		// Join with OR to broaden results similar to "+||+"
		return strings.Join(parts, " OR ")
	}
	return fmt.Sprintf(`intext:"%s"`, contents)
}

func buildInurlQuery(dict string) string {
	// Return raw terms joined with a sentinel "|||".
	// We will wrap each as inurl:"term" later per request to avoid awkward OR behavior.
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		// avoid wrapping quotes inside the value; strip surrounding quotes if provided
		s = strings.Trim(s, `"`)
		return s
	}

	var terms []string
	if fileExists(dict) {
		lines, _ := readLines(dict)
		for _, s := range lines {
			if t := clean(s); t != "" {
				terms = append(terms, t)
			}
		}
	} else if strings.Contains(dict, ",") {
		for _, s := range strings.Split(dict, ",") {
			if t := clean(s); t != "" {
				terms = append(terms, t)
			}
		}
	} else {
		if t := clean(dict); t != "" {
			terms = append(terms, t)
		}
	}
	return strings.Join(terms, "|||")
}

// --- IO helpers ---

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readLines(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s != "" {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// loadExistingOutputs loads URLs already present in the output file (if any)
func loadExistingOutputs(outputPath string) map[string]struct{} {
	existing := make(map[string]struct{})
	if outputPath == "" || !fileExists(outputPath) {
		return existing
	}

	lines, err := readLines(outputPath)
	if err != nil {
		return existing
	}

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		existing[line] = struct{}{}
	}
	return existing
}

// filterNewURLs returns URLs that are not present in the existing set
func filterNewURLs(urls []string, existing map[string]struct{}) []string {
	if len(existing) == 0 {
		return urls
	}

	var out []string
	for _, u := range urls {
		if _, ok := existing[u]; ok {
			continue
		}
		out = append(out, u)
	}
	return out
}

// loadOOSFile loads out-of-scope patterns from a file
// Returns empty slice if file doesn't exist or is empty
func loadOOSFile(path string) []string {
	if path == "" {
		return nil
	}

	// Expand tilde to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		path = filepath.Join(home, path[2:])
	}

	// Check if file exists
	if !fileExists(path) {
		return nil
	}

	// Read file
	lines, err := readLines(path)
	if err != nil {
		return nil
	}

	// Filter out comments and empty lines
	var patterns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}

	return patterns
}

// matchesOOSPattern checks if a URL matches an out-of-scope pattern
// Supports wildcards (*) in domain names and paths
// Examples:
//   - *.example.com matches subdomain.example.com, test.example.com
//   - example.com/path/* matches example.com/path/file.txt
//   - csd-*.contentsquare.com matches csd-test.contentsquare.com
func matchesOOSPattern(urlStr string, pattern string) bool {
	// Remove protocol if present in URL
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "//")

	// Remove protocol if present in pattern (shouldn't be, but just in case)
	pattern = strings.TrimPrefix(pattern, "http://")
	pattern = strings.TrimPrefix(pattern, "https://")
	pattern = strings.TrimPrefix(pattern, "//")

	// If pattern has no wildcards, do exact substring matching
	if !strings.Contains(pattern, "*") {
		// Check if URL contains the pattern as a domain or path
		// Pattern can be:
		// - A full domain: example.com
		// - A subdomain: subdomain.example.com
		// - A path: example.com/path

		// Extract domain and path from URL
		parts := strings.SplitN(urlStr, "/", 2)
		urlDomain := parts[0]
		urlPath := ""
		if len(parts) > 1 {
			urlPath = "/" + parts[1]
		}

		// Extract domain and path from pattern
		patternParts := strings.SplitN(pattern, "/", 2)
		patternDomain := patternParts[0]
		patternPath := ""
		if len(patternParts) > 1 {
			patternPath = "/" + patternParts[1]
		}

		// Match domain
		if patternPath == "" {
			// Pattern is domain-only
			// Match if URL domain equals pattern or is a subdomain of pattern
			if urlDomain == patternDomain {
				return true
			}
			// Check if it's a subdomain (e.g., www.example.com matches example.com)
			if strings.HasSuffix(urlDomain, "."+patternDomain) {
				return true
			}
			return false
		} else {
			// Pattern has a path component
			// Domain must match exactly and path must start with pattern path
			if urlDomain == patternDomain && strings.HasPrefix(urlPath, patternPath) {
				return true
			}
			return false
		}
	}

	// Pattern has wildcards - convert to regex
	// Escape special regex characters except *
	regexPattern := regexp.QuoteMeta(pattern)

	// Replace escaped \* with .* for wildcard matching
	regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")

	// Anchor the pattern
	regexPattern = "^" + regexPattern

	// Compile and match
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false // Invalid pattern
	}

	return re.MatchString(urlStr)
}

// filterOOSResults filters out URLs that match out-of-scope patterns
// Returns the filtered list and the number of URLs filtered out
func filterOOSResults(results []string, oosPatterns []string) ([]string, int) {
	if len(oosPatterns) == 0 {
		return results, 0
	}

	filtered := []string{}
	filteredCount := 0

	for _, url := range results {
		isOOS := false
		for _, pattern := range oosPatterns {
			if matchesOOSPattern(url, pattern) {
				isOOS = true
				filteredCount++
				break
			}
		}
		if !isOOS {
			filtered = append(filtered, url)
		}
	}

	return filtered, filteredCount
}

// sendURLsThroughProxy sends HTTP requests to URLs through the configured proxy
func (c *Config) sendURLsThroughProxy(ctx context.Context, urls []string) {
	if c.Proxy == "" || c.ProxyClient == nil {
		return // No proxy configured
	}

	console.Logv(c.Verbose, "[PROXY] Sending %d URLs through proxy for inspection...", len(urls))

	for i, targetURL := range urls {
		if ctx.Err() != nil {
			return // Context canceled
		}

		// Create HEAD request to minimize bandwidth
		req, err := http.NewRequestWithContext(ctx, "HEAD", targetURL, nil)
		if err != nil {
			console.Logv(c.Verbose, "[PROXY] Skip invalid URL: %s", targetURL)
			continue
		}

		// Set a reasonable user agent
		req.Header.Set("User-Agent", core.DefaultUserAgent)

		// Send request through proxy
		resp, err := c.ProxyClient.Do(req)
		if err != nil {
			console.Logv(c.Verbose, "[PROXY] %d/%d: %s [ERROR: %v]", i+1, len(urls), targetURL, err)
			continue
		}

		// Log status
		console.Logv(c.Verbose, "[PROXY] %d/%d: %s [%d]", i+1, len(urls), targetURL, resp.StatusCode)
		resp.Body.Close()

		// Small delay to avoid overwhelming the proxy
		time.Sleep(100 * time.Millisecond)
	}

	console.Logv(c.Verbose, "[PROXY] Completed sending URLs through proxy")
}

func outputOrPrintUnique(urls []string, outputPath string) {
	uniq := uniqueStrings(urls)
	sort.Strings(uniq)
	if outputPath == "" {
		for _, u := range uniq {
			fmt.Println(u)
		}
		return
	}
	// emulate "anew": append only new unique lines compared to file
	existing := map[string]struct{}{}
	if fileExists(outputPath) {
		lines, _ := readLines(outputPath)
		for _, l := range lines {
			existing[l] = struct{}{}
		}
	}
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		console.LogErr("[!] cannot open output file: %v", err)
		// fallback to stdout
		for _, u := range uniq {
			fmt.Println(u)
		}
		return
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	defer bw.Flush()
	for _, u := range uniq {
		if _, ok := existing[u]; !ok {
			bw.WriteString(u)
			bw.WriteByte('\n')
			existing[u] = struct{}{}
		}
	}
}
