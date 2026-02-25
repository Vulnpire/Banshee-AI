package analysis

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

// responseBlock represents a single collected HTTP response ready for AI analysis
type responseBlock struct {
	URL  string
	Text string
}

// parseResponseBlocks splits the collected responses file into individual response blocks
func parseResponseBlocks(responsesStr string, allowed map[string]struct{}) []responseBlock {
	parts := strings.Split(responsesStr, "=== URL:")
	var blocks []responseBlock

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		lines := strings.SplitN(part, "\n", 2)
		if len(lines) < 2 {
			continue
		}

		urlLine := strings.TrimSpace(lines[0])
		urlLine = strings.TrimSuffix(urlLine, "===")
		url := strings.TrimSpace(strings.TrimPrefix(urlLine, ":"))
		url = strings.TrimSpace(strings.TrimPrefix(url, "URL"))

		if url == "" {
			continue
		}

		if allowed != nil {
			if _, ok := allowed[url]; !ok {
				continue
			}
		}

		content := strings.TrimSpace(lines[1])
		if content == "" {
			continue
		}

		fullBlock := fmt.Sprintf("=== URL: %s ===\n%s", url, content)
		blocks = append(blocks, responseBlock{URL: url, Text: fullBlock})
	}

	return blocks
}

// batchResponseBlocks groups response blocks into size-limited batches for AI calls
func batchResponseBlocks(blocks []responseBlock, maxBatchBytes int, maxBatchURLs int) [][]responseBlock {
	var batches [][]responseBlock
	var current []responseBlock
	currentSize := 0

	for _, block := range blocks {
		blockSize := len(block.Text)
		if blockSize == 0 {
			continue
		}

		// Trim oversized single blocks to keep prompts bounded
		if blockSize > maxBatchBytes {
			limit := maxBatchBytes / 2
			if limit < 1024 {
				limit = 1024
			}
			block.Text = block.Text[:limit] + "\n[trimmed for analysis]"
			blockSize = len(block.Text)
		}

		// Start a new batch if adding this block would exceed limits
		if len(current) >= maxBatchURLs || (currentSize > 0 && currentSize+blockSize > maxBatchBytes) {
			batches = append(batches, current)
			current = nil
			currentSize = 0
		}

		current = append(current, block)
		currentSize += blockSize
	}

	if len(current) > 0 {
		batches = append(batches, current)
	}

	return batches
}

// collectHTTPResponses fetches HTTP responses from URLs and stores them temporarily
func (c *Config) collectHTTPResponses(ctx context.Context, urls []string, responsesFile string) error {
	if len(urls) == 0 {
		return nil
	}

	console.Logv(c.Verbose, "\n%s[RESPONSE-ANALYSIS]%s Collecting HTTP responses from %d URLs...", console.ColorCyan, console.ColorReset, len(urls))

	// Create responses file
	f, err := os.Create(responsesFile)
	if err != nil {
		return fmt.Errorf("failed to create responses file: %v", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	defer writer.Flush()

	// Limit concurrent requests
	semaphore := make(chan struct{}, 5) // Max 5 concurrent requests
	var wg sync.WaitGroup
	var mu sync.Mutex
	collected := 0
	skipped := 0

	for _, url := range urls {
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Per-attempt timeouts (fast then slower) to reduce deadline exceeded noise
			perAttemptTimeouts := []time.Duration{12 * time.Second, 20 * time.Second}
			maxBodyBytes := int64(100 * 1024) // cap body to 100KB to avoid huge prompts

			// Use proxy client if configured
			client := c.ProxyClient
			if client == nil {
				client = c.Client
			}

			shouldRetry := func(err error) bool {
				if err == nil {
					return false
				}
				if ctx.Err() != nil {
					return false
				}
				var netErr net.Error
				if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
					return true
				}
				errStr := strings.ToLower(err.Error())
				if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") || strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "refused") {
					return true
				}
				return false
			}

			var resp *http.Response
			var cancel context.CancelFunc
			var lastErr error

			for attempt, timeout := range perAttemptTimeouts {
				if ctx.Err() != nil {
					return
				}

				reqCtx, cCancel := context.WithTimeout(ctx, timeout)
				req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil)
				if err != nil {
					cCancel()
					lastErr = err
					break
				}

				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
				resp, lastErr = client.Do(req)

				if lastErr != nil {
					// Retry with insecure TLS if certificate errors occur
					errStr := strings.ToLower(lastErr.Error())
					if strings.Contains(errStr, "x509") || strings.Contains(errStr, "certificate") || strings.Contains(errStr, "tls") {
						if insecureClient, _ := buildHTTPClient(c.Proxy, true); insecureClient != nil {
							resp, lastErr = insecureClient.Do(req)
						}
					}

					// Fallback to HTTP if HTTPS negotiation failed
					if lastErr != nil && strings.HasPrefix(targetURL, "https://") && (strings.Contains(errStr, "tls") || strings.Contains(errStr, "handshake")) {
						httpURL := "http://" + strings.TrimPrefix(targetURL, "https://")
						if httpReq, httpErr := http.NewRequestWithContext(reqCtx, "GET", httpURL, nil); httpErr == nil {
							httpReq.Header.Set("User-Agent", req.Header.Get("User-Agent"))
							resp, lastErr = client.Do(httpReq)
						}
					}
				}

				if lastErr == nil {
					cancel = cCancel
					break
				}

				cCancel()

				// Retry transient failures with a tiny backoff
				if attempt+1 < len(perAttemptTimeouts) && shouldRetry(lastErr) {
					time.Sleep(time.Duration(250*(attempt+1)) * time.Millisecond)
					continue
				}

				break
			}

			if lastErr != nil || resp == nil {
				console.Logv(c.Verbose, "%s[RESPONSE-ANALYSIS]%s Skipping %s (fetch error after retries: %v)", console.ColorOrange, console.ColorReset, targetURL, lastErr)
				mu.Lock()
				skipped++
				mu.Unlock()
				return
			}
			defer cancel()
			defer resp.Body.Close()

			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
			if err != nil {
				console.Logv(c.Verbose, "%s[RESPONSE-ANALYSIS]%s Skipping %s (read error: %v)", console.ColorOrange, console.ColorReset, targetURL, err)
				mu.Lock()
				skipped++
				mu.Unlock()
				return
			}

			// Store response in format: URL|STATUS|BODY
			mu.Lock()
			writer.WriteString(fmt.Sprintf("=== URL: %s ===\n", targetURL))
			writer.WriteString(fmt.Sprintf("Status: %d %s\n", resp.StatusCode, resp.Status))
			writer.WriteString(fmt.Sprintf("Content-Type: %s\n", resp.Header.Get("Content-Type")))
			writer.WriteString("\n--- Response Body ---\n")
			writer.Write(bodyBytes)
			writer.WriteString("\n\n")
			collected++
			mu.Unlock()
		}(url)

		// Small delay between request initiations
		time.Sleep(100 * time.Millisecond)
	}

	wg.Wait()

	console.Logv(c.Verbose, "%s[RESPONSE-ANALYSIS]%s Successfully collected %d responses (skipped %d)", console.ColorCyan, console.ColorReset, collected, skipped)
	return nil
}

// recordResponseFindings stores critical response analysis discoveries into intelligence for later recommendations
func (c *Config) recordResponseFindings(analysis map[string]string) {
	if !c.LearnMode || c.Intelligence == nil || len(analysis) == 0 {
		return
	}

	now := time.Now()

	for url, summary := range analysis {
		if strings.HasPrefix(summary, "No findings") {
			continue
		}

		priority := classifyResponseFinding(summary)
		if priority == "" {
			continue
		}

		types := extractSensitiveTypesFromSummary(summary)
		rf := core.ResponseFinding{
			URL:            url,
			Summary:        normalizeRAOutput(summary),
			Priority:       priority,
			SensitiveTypes: types,
			FoundAt:        now,
		}

		// Dedupe by URL+summary
		updated := false
		for i, existing := range c.Intelligence.ResponseFindings {
			if existing.URL == url && existing.Summary == rf.Summary {
				c.Intelligence.ResponseFindings[i].Priority = priority
				c.Intelligence.ResponseFindings[i].SensitiveTypes = types
				c.Intelligence.ResponseFindings[i].FoundAt = now
				updated = true
				break
			}
		}

		if !updated {
			c.Intelligence.ResponseFindings = append(c.Intelligence.ResponseFindings, rf)
		}
	}

	// Keep only the most recent 200 findings to avoid unbounded growth
	const maxFindings = 200
	if len(c.Intelligence.ResponseFindings) > maxFindings {
		c.Intelligence.ResponseFindings = c.Intelligence.ResponseFindings[len(c.Intelligence.ResponseFindings)-maxFindings:]
	}
}

// documentExts defines extensions routed to document analysis.
var documentExts = map[string]bool{
	".pdf":  true,
	".docx": true,
	".doc":  true,
	".pptx": true,
	".ppt":  true,
	".xlsx": true,
	".xls":  true,
	".txt":  true,
	".csv":  true,
	".json": true,
	".log":  true,
	".conf": true,
	".yaml": true,
	".yml":  true,
	".xml":  true,
}

// textLikeDocumentExts are cheap to scan and skip non-sensitive filtering.
var textLikeDocumentExts = map[string]bool{
	".txt":  true,
	".csv":  true,
	".json": true,
	".log":  true,
	".conf": true,
	".yaml": true,
	".yml":  true,
	".xml":  true,
}

func documentExtFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	path := rawURL
	if err == nil && parsed.Path != "" {
		path = parsed.Path
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != "" {
		return ext
	}

	if err == nil {
		for _, values := range parsed.Query() {
			for _, value := range values {
				queryExt := strings.ToLower(filepath.Ext(value))
				if queryExt != "" {
					return queryExt
				}
			}
		}
	}

	return ""
}

func isDocumentURL(rawURL string) bool {
	ext := documentExtFromURL(rawURL)
	return documentExts[ext]
}

func filterDocumentAnalysisURLs(urls []string) []string {
	var docs []string
	for _, u := range urls {
		if isDocumentURL(u) {
			docs = append(docs, u)
		}
	}
	return docs
}

// filterResponseAnalysisURLs excludes obviously non-sensitive URLs (static assets, documents) from response analysis.
func filterResponseAnalysisURLs(urls []string) ([]string, []string) {
	var filtered []string
	var skippedList []string

	skipExts := []string{
		".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".csv", ".txt", ".json", ".xml", ".yaml", ".yml", ".log", ".conf",
		".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
		".css", ".js", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
	}

	shouldSkip := func(u string) bool {
		lower := strings.ToLower(u)
		for _, ext := range skipExts {
			if strings.Contains(lower, ext) {
				return true
			}
		}
		// Skip obvious static paths
		staticKeywords := []string{"/static/", "/assets/", "/images/", "/img/", "/fonts/", "/scripts/", "/styles/"}
		for _, kw := range staticKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
		// Skip obvious academic/publication pages that aren't actionable dashboards
		if strings.Contains(lower, "research.monash.edu/en/publications") ||
			strings.Contains(lower, "research.monash.edu/en/persons") ||
			strings.Contains(lower, "research.monash.edu/en/organisations") {
			return true
		}
		return false
	}

	for _, u := range urls {
		if shouldSkip(u) {
			skippedList = append(skippedList, u)
			continue
		}
		filtered = append(filtered, u)
	}

	return filtered, skippedList
}

// trimResponseForAnalysis removes unnecessary content from HTTP responses to reduce AI processing
func trimResponseForAnalysis(response string) string {
	lines := strings.Split(response, "\n")
	var result []string
	var inBody bool
	var skipTags = map[string]bool{
		"<style":  true,
		"<script": true,
		"<link":   true,
		"<meta":   true,
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines
		if trimmed == "" {
			continue
		}

		// After we see the body or content, start including
		if !inBody {
			// Keep HTTP headers and URL markers
			if strings.HasPrefix(trimmed, "===") ||
				strings.HasPrefix(trimmed, "HTTP/") ||
				strings.Contains(trimmed, "Content-Type:") ||
				strings.Contains(trimmed, "Server:") {
				result = append(result, line)
				continue
			}

			// Look for start of actual content
			if strings.Contains(trimmed, "<body") ||
				strings.Contains(trimmed, "<html") ||
				strings.Contains(trimmed, "{") ||
				strings.Contains(trimmed, "<!DOCTYPE") {
				inBody = true
			}
		}

		if inBody {
			// Skip common bloat tags
			skip := false
			for tag := range skipTags {
				if strings.Contains(strings.ToLower(trimmed), tag) {
					skip = true
					break
				}
			}

			if !skip {
				// Keep lines with potential secrets or interesting content
				keepLine := false

				// Keep if it has JSON-like content
				if strings.Contains(trimmed, `":`) || strings.Contains(trimmed, `"key`) {
					keepLine = true
				}

				// Keep if it has potential secrets keywords
				secretKeywords := []string{
					"key", "secret", "password", "token", "credential",
					"aws", "api", "access", "private", "config",
					"sentry", "dsn", "bearer", "auth", "jwt",
				}
				lowerLine := strings.ToLower(trimmed)
				for _, keyword := range secretKeywords {
					if strings.Contains(lowerLine, keyword) {
						keepLine = true
						break
					}
				}

				// Keep if it looks like a dashboard element
				dashboardKeywords := []string{"admin", "dashboard", "panel", "console", "management"}
				for _, keyword := range dashboardKeywords {
					if strings.Contains(lowerLine, keyword) {
						keepLine = true
						break
					}
				}

				if keepLine {
					result = append(result, line)
				}
			}
		}
	}

	return strings.Join(result, "\n")
}

// normalizeRAOutput deduplicates Sensitive/Proof tokens and trims noisy quotes
func normalizeRAOutput(summary string) string {
	parts := strings.Split(summary, "|")
	var cleanedParts []string
	for _, p := range parts {
		cleanedParts = append(cleanedParts, strings.TrimSpace(p))
	}

	// Helper to dedupe semicolon-separated tokens
	dedupeTokens := func(section string, prefix string) string {
		content := strings.TrimSpace(strings.TrimPrefix(section, prefix))
		if content == "" {
			return ""
		}
		tokens := strings.Split(content, ";")
		seen := make(map[string]struct{})
		var uniq []string
		for _, t := range tokens {
			t = strings.TrimSpace(t)
			t = strings.Trim(t, `"'`)
			if t == "" {
				continue
			}
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			uniq = append(uniq, t)
		}
		if len(uniq) == 0 {
			return ""
		}
		return prefix + " " + strings.Join(uniq, "; ")
	}

	var rebuilt []string
	for _, part := range cleanedParts {
		switch {
		case strings.HasPrefix(part, "Sensitive:"):
			if dedup := dedupeTokens(part, "Sensitive:"); dedup != "" {
				rebuilt = append(rebuilt, dedup)
			}
		default:
			if part != "" {
				rebuilt = append(rebuilt, part)
			}
		}
	}

	return strings.Join(rebuilt, " | ")
}

// analyzeResponsesWithAI sends collected responses to AI for analysis
func (c *Config) analyzeResponsesWithAI(ctx context.Context, responsesFile string, urls []string) (map[string]string, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	// Read collected responses
	responsesData, err := os.ReadFile(responsesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read responses file: %v", err)
	}

	if len(responsesData) == 0 {
		return nil, nil
	}

	responsesStr := string(responsesData)

	// Only keep blocks that belong to the current URL set
	allowed := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		allowed[u] = struct{}{}
	}
	blocks := parseResponseBlocks(responsesStr, allowed)
	if len(blocks) == 0 {
		return nil, nil
	}

	// Trim each block to reduce AI payload size
	const maxBlockBytes = 120 * 1024
	for i, block := range blocks {
		trimmed := trimResponseForAnalysis(block.Text)
		if trimmed == "" {
			trimmed = block.Text
		}
		if len(trimmed) > maxBlockBytes {
			trimmed = trimmed[:maxBlockBytes] + "\n[trimmed]"
		}
		blocks[i].Text = trimmed
	}

	// Batch responses to avoid oversized AI prompts
	const maxBatchBytes = 900000 // ~0.9MB to stay well under token/time limits
	const maxBatchURLs = 8
	batches := batchResponseBlocks(blocks, maxBatchBytes, maxBatchURLs)

	// Prepare AI prompt - request strict JSON with sensitive labels (no Proof to avoid clutter)
	systemPrompt := `Analyze HTTP responses for sensitive information, credentials, secrets, and PII. Return precise findings.

MUST FLAG ONLY IF PRESENT IN BODY:
• Secrets/credentials: passwords, tokens, API keys, AWS keys, DB creds, private keys
• Auth/session artifacts: session keys, JWTs, cookies
• PII: SSN, passport, DOB+name, address+name (not just public emails)
• Error tracking creds (Sentry DSN, etc.)
• Admin/debug dashboards with leaked data (not marketing/news)

IGNORE:
• Marketing/news/articles, research/person/org profile pages
• Public emails/contact info alone
• Generic login forms without leaks

OUTPUT FORMAT (STRICT JSON OBJECT):
{}
OR
{
  "https://url1": "Finding 1 | Sensitive: TYPE:VALUE; TYPE2:VALUE2",
  "https://url2": "Another finding | Sensitive: ...",
  "https://url3": "Interesting dashboard (Admin panel)"
}

Rules:
- JSON object only. No markdown, no code fences, no extra text.
- Include Sensitive: TYPE:VALUE entries (e.g., AWS_KEY:..., AWS_SECRET:..., TOKEN:..., PASSWORD:..., SESSION_KEY:..., DSN:...).
- If multiple findings for a URL, concatenate them in the value separated by "; " (semicolon + space).

Examples:
{}
{"https://site.com/app": "AWS credentials exposed | Sensitive: AWS_KEY:AKIA...BFL; AWS_SECRET:Qs4r...ki3"}
{"https://site.com/config": "Sentry DSN exposed | Sensitive: DSN:https://...@sentry.io/..."}
{"https://admin.site.com": "Interesting dashboard (Admin panel)"}`

	results := make(map[string]string)
	var resultsMutex sync.Mutex

	// Use only 3 workers for analysis to avoid 429 rate limit errors
	maxWorkers := 3
	if c.Workers < maxWorkers {
		maxWorkers = c.Workers
	}

	// Process batches in parallel using worker pool
	if c.Verbose && len(batches) > 1 {
		console.Logv(true, "%s[RESPONSE-ANALYSIS]%s Processing %d batches with %d workers", console.ColorCyan, console.ColorReset, len(batches), maxWorkers)
	}

	// Create batch processor function
	processBatch := func(ctx context.Context, batchIdx int, batch []responseBlock) map[string]string {
		if ctx.Err() != nil {
			return nil
		}

		if c.Verbose {
			console.Logv(true, "%s[RESPONSE-ANALYSIS]%s Analyzing batch %d/%d (%d URLs)", console.ColorCyan, console.ColorReset, batchIdx+1, len(batches), len(batch))
		}

		var batchTextBuilder strings.Builder
		var batchURLs []string
		for _, block := range batch {
			batchTextBuilder.WriteString(block.Text)
			batchTextBuilder.WriteString("\n\n")
			batchURLs = append(batchURLs, block.URL)
		}
		batchText := batchTextBuilder.String()

		userPrompt := fmt.Sprintf("Batch %d/%d - Analyze ONLY these URLs: %s. Return strict JSON per rules.\n\n%s",
			batchIdx+1, len(batches), strings.Join(batchURLs, ", "), batchText)

		// Call AI model with large data support (avoids "argument list too long" error)
		analysisResult, err := c.callGeminiCLIWithLargeData(ctx, systemPrompt, userPrompt)
		if err != nil {
			if c.Verbose {
				console.Logv(true, "%s[RESPONSE-ANALYSIS]%s AI error: %v", console.ColorRed, console.ColorReset, err)
			}
			// Fall back to heuristic detection for this batch
			return c.fallbackResponseAnalysis(batchText, batchURLs)
		}

		analysisResult = strings.TrimSpace(analysisResult)
		if analysisResult == "" || analysisResult == "{}" || analysisResult == "{ }" {
			return c.fallbackResponseAnalysis(batchText, batchURLs)
		}

		// Parse JSON response
		var parsed map[string]string

		// Clean up JSON (remove markdown code blocks if present)
		cleanedResult := analysisResult
		if strings.Contains(analysisResult, "```json") {
			start := strings.Index(analysisResult, "```json") + 7
			end := strings.Index(analysisResult[start:], "```")
			if end > 0 {
				cleanedResult = strings.TrimSpace(analysisResult[start : start+end])
			}
		} else if strings.Contains(analysisResult, "```") {
			start := strings.Index(analysisResult, "```") + 3
			end := strings.Index(analysisResult[start:], "```")
			if end > 0 {
				cleanedResult = strings.TrimSpace(analysisResult[start : start+end])
			}
		}

		// Extract JSON object from response (look for { ... })
		if !strings.HasPrefix(cleanedResult, "{") {
			startIdx := strings.Index(cleanedResult, "{")
			endIdx := strings.LastIndex(cleanedResult, "}")
			if startIdx >= 0 && endIdx > startIdx {
				cleanedResult = cleanedResult[startIdx : endIdx+1]
			}
		}

		cleanedResult = strings.TrimSpace(cleanedResult)

		// Try to parse as JSON
		if err := json.Unmarshal([]byte(cleanedResult), &parsed); err != nil || len(parsed) == 0 {
			// Attempt to salvage URL-specific analysis from free-form text before heuristics
			parsed = c.extractAnalysisFromText(cleanedResult, batchURLs)
			if len(parsed) == 0 {
				if c.Verbose {
					console.Logv(true, "%s[RESPONSE-ANALYSIS]%s JSON parse failed, using fallback heuristics", console.ColorOrange, console.ColorReset)
				}
				parsed = c.fallbackResponseAnalysis(batchText, batchURLs)
			}
		}

		return parsed
	}

	// Convert batches to interface{} for worker pool
	// Create batch items with index to avoid slice comparison
	type batchWithIndex struct {
		index int
		batch []responseBlock
	}
	batchItems := make([]interface{}, len(batches))
	for i, batch := range batches {
		batchItems[i] = batchWithIndex{index: i, batch: batch}
	}

	// Process batches in parallel with rate limiting
	batchProcessor := func(ctx context.Context, item interface{}) (interface{}, error) {
		bwi := item.(batchWithIndex)

		// Add delay between batches to avoid rate limiting (429 errors)
		// Each batch waits based on its index to stagger AI calls
		if bwi.index > 0 {
			delay := time.Duration(bwi.index) * 2 * time.Second
			time.Sleep(delay)
		}

		return processBatch(ctx, bwi.index, bwi.batch), nil
	}

	batchResults, _ := processWithWorkerPool(ctx, batchItems, maxWorkers, batchProcessor)

	// Merge results from all batches
	for _, result := range batchResults {
		if result != nil {
			if parsed, ok := result.(map[string]string); ok {
				for k, v := range parsed {
					resultsMutex.Lock()
					results[k] = v
					resultsMutex.Unlock()
				}
			}
		}
	}

	// Add placeholders for URLs the AI skipped so that every analyzed URL is reported
	for _, u := range urls {
		if _, ok := results[u]; !ok {
			results[u] = "No findings (AI reported nothing for this URL)"
		}
	}

	return results, nil
}

// extractAnalysisFromText attempts to extract URL-specific analysis from AI text response
func (c *Config) extractAnalysisFromText(text string, urls []string) map[string]string {
	results := make(map[string]string)

	// Pattern 1: Look for "URL: analysis" format
	urlPattern := regexp.MustCompile(`(?m)^.*?(https?://[^\s]+)[\s:]+(.+)$`)
	matches := urlPattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			url := match[1]
			analysis := strings.TrimSpace(match[2])

			// Verify this URL is in our list
			for _, validURL := range urls {
				if strings.Contains(url, validURL) || strings.Contains(validURL, url) {
					results[validURL] = analysis
					break
				}
			}
		}
	}

	// Pattern 2: Look for bullet points or numbered lists with URLs
	listPattern := regexp.MustCompile(`(?m)^[\s-*•\d.]+\s*(https?://[^\s]+)[\s:-]+(.+)$`)
	matches = listPattern.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			url := match[1]
			analysis := strings.TrimSpace(match[2])

			// Verify this URL is in our list and not already added
			for _, validURL := range urls {
				if _, exists := results[validURL]; !exists {
					if strings.Contains(url, validURL) || strings.Contains(validURL, url) {
						results[validURL] = analysis
						break
					}
				}
			}
		}
	}

	return results
}

// fallbackResponseAnalysis performs simple heuristic-based analysis when AI is unavailable
func (c *Config) fallbackResponseAnalysis(responsesData string, urls []string) map[string]string {
	results := make(map[string]string)

	blocks := strings.Split(responsesData, "=== URL:")

	securityPatterns := map[string]string{
		`(?i)(AKIA[0-9A-Z]{16})`: "Potential AWS Access Key",
		`(?i)"?(?:secretAccessKey|secret_access_key|aws_secret_access_key)"?\s*[:=]\s*"?([A-Za-z0-9+/]{40})"?`: "AWS Secret Access Key",
		`(?i)(sk_live_[0-9a-zA-Z]{24,})`: "Potential Stripe Live Secret Key",
		`(?i)-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`: "Private Key Found",
		`(?i)"?(?:password|db_password|database_password)"?\s*[:=]\s*"?[^"'\s]{8,}`: "Possible Password in Config",
		`(?i)secret[\s]*[:=][\s]*["']?[^"'\s]{16,}`: "Possible Secret",
		`(?i)token[\s]*[:=][\s]*["']?[^"'\s]{20,}`: "Possible Token",
		`(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`: "GitHub Token",
		`(?i)mysql://[^@\s]+@[^@\s]+`: "MySQL Connection String",
		`(?i)mongodb(\+srv)?://[^@\s]+@[^@\s]+`: "MongoDB Connection String",
	}

	for _, block := range blocks {
		if len(block) < 10 {
			continue
		}
		lines := strings.Split(block, "\n")
		if len(lines) < 2 {
			continue
		}
		blockURL := strings.TrimSpace(lines[0])
		blockContent := strings.Join(lines[1:], "\n")

		for pattern, description := range securityPatterns {
			re := regexp.MustCompile(pattern)
			if re.MatchString(blockContent) {
				for _, url := range urls {
					if strings.Contains(blockURL, url) || strings.Contains(url, blockURL) {
						if _, exists := results[url]; !exists {
							results[url] = fmt.Sprintf("[Heuristic] %s detected", description)
						} else {
							results[url] += fmt.Sprintf(" | %s detected", description)
						}
						break
					}
				}
			}
		}
	}

	if len(results) == 0 {
		return nil
	}
	return results
}

// highlightSensitiveFindings colors only the values under "Sensitive:" without hard-coded keywords
func highlightSensitiveFindings(summary string) string {
	idx := strings.Index(summary, "Sensitive:")
	if idx == -1 {
		return summary
	}

	prefix := summary[:idx]
	rest := summary[idx:]

	segments := strings.Split(rest, "|")
	for i, seg := range segments {
		seg = strings.TrimSpace(seg)
		if !strings.HasPrefix(seg, "Sensitive:") {
			segments[i] = seg
			continue
		}

		values := strings.TrimSpace(strings.TrimPrefix(seg, "Sensitive:"))
		tokens := strings.Split(values, ";")
		for j, tok := range tokens {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			parts := strings.SplitN(tok, ":", 2)
			if len(parts) != 2 {
				continue
			}
			label := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if len(val) > 8 {
				val = val[:4] + "..." + val[len(val)-4:]
			}
			// Color: label and colon yellow, value red
			tokens[j] = console.ColorYellow + label + ":" + console.ColorRed + val + console.ColorReset
		}
		segments[i] = "Sensitive: " + strings.Join(tokens, "; ")
	}

	return prefix + strings.Join(segments, " | ")
}

// analyzeResponseOnly_handler handles the --analyze-response-only flag
func (c *Config) analyzeResponseOnly_handler(ctx context.Context) error {
	// Create a temporary file to store the response
	tmpFile, err := os.CreateTemp("", "banshee-response-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Fetch the URL response
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.AnalyzeResponseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", core.DefaultUserAgent)

	// Build HTTP client (reuse existing logic with proxy support)
	client, err := buildHTTPClient(c.Proxy, c.Insecure)
	if err != nil {
		return fmt.Errorf("failed to build HTTP Client: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Write response to temp file in the same format as collectHTTPResponses
	fmt.Fprintf(tmpFile, "=== URL: %s ===\n", c.AnalyzeResponseURL)
	fmt.Fprintf(tmpFile, "Status: %d\n", resp.StatusCode)
	fmt.Fprintf(tmpFile, "Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Fprintf(tmpFile, "\n%s\n\n", string(bodyBytes))

	tmpFile.Close() // Close before reading

	// Analyze the response with AI
	analysis, err := c.analyzeResponsesWithAI(ctx, tmpFile.Name(), []string{c.AnalyzeResponseURL})
	if err != nil {
		return fmt.Errorf("AI analysis failed: %v", err)
	}

	// Display results
	if len(analysis) > 0 {
		for url, summary := range analysis {
			// Output format: URL | [RA] - summary (with color coding and red highlighting for sensitive data)
			summaryColor := console.ColorGreen
			if strings.Contains(strings.ToLower(summary), "error") || strings.Contains(strings.ToLower(summary), "failed") || strings.Contains(strings.ToLower(summary), "parsing") {
				summaryColor = console.ColorOrange
			} else if strings.Contains(strings.ToLower(summary), "sensitive") || strings.Contains(strings.ToLower(summary), "admin") ||
				strings.Contains(strings.ToLower(summary), "api") || strings.Contains(strings.ToLower(summary), "credential") ||
				strings.Contains(strings.ToLower(summary), "dashboard") {
				summaryColor = console.ColorYellow
			}

			// Highlight sensitive findings in red (within the yellow text)
			highlightedSummary := highlightSensitiveFindings(summary)

			fmt.Printf("%s | %s[RA]%s - %s%s%s\n", url, console.ColorCyan, console.ColorReset, summaryColor, highlightedSummary, console.ColorReset)
		}
	}
	// If no findings, output nothing (silent when clean)

	return nil
}
