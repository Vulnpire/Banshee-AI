package wayback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

// =============================================================================
// DATA STRUCTURES
// =============================================================================

// WaybackURL represents a single URL from Wayback Machine
type WaybackURL struct {
	URL        string
	Timestamp  string
	StatusCode string
	MimeType   string
}

// URLCategory represents the categorization of a URL
type URLCategory struct {
	IsAdmin       bool
	IsAPI         bool
	IsBackup      bool
	IsConfig      bool
	IsSensitive   bool
	HasParams     bool
	FileExtension string
	TechIndicator string // WordPress, Joomla, etc.
}

// WaybackCache manages caching of Wayback results
type WaybackCache struct {
	cachePath string
	mutex     sync.RWMutex
}

// =============================================================================
// WAYBACK CDX API CLIENT
// =============================================================================

// queryWaybackCDX queries the Wayback CDX API for a domain
func queryWaybackCDX(ctx context.Context, domain string, statusCodes []string, verbose bool) ([]WaybackURL, error) {
	// Check cache first
	cache := NewWaybackCache()
	cacheKey := fmt.Sprintf("%s_%s", domain, strings.Join(statusCodes, ","))
	if cached, err := cache.Get(cacheKey); err == nil && len(cached) > 0 {
		console.Logv(verbose, "[WAYBACK] Using cached results for %s", domain)
		return cached, nil
	}

	console.Logv(verbose, "[WAYBACK] Querying Wayback Machine for %s...", domain)

	// Build CDX API URL - use matchType=domain to capture all subdomains
	// collapse=urlkey groups by URL key (deduplicates), but we prioritize subdomain diversity
	// by collapsing on digest instead, which groups identical responses
	cdxURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&matchType=domain&output=json&collapse=digest&fl=original,timestamp,statuscode,mimetype", domain)

	// Add status code filter if specified
	if len(statusCodes) > 0 && !contains(statusCodes, "all") {
		for _, code := range statusCodes {
			cdxURL += fmt.Sprintf("&filter=statuscode:%s", code)
		}
	}

	// Increase limit for better subdomain coverage
	cdxURL += "&limit=50000"

	// Make request with retry logic
	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	var resp *http.Response
	var err error
	maxRetries := 3

	// Polite crawl delay before first request
	time.Sleep(2 * time.Second)

	for i := 0; i < maxRetries; i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, "GET", cdxURL, nil)
		if err != nil {
			return nil, err
		}

		// Use standard browser User-Agent to avoid being flagged
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			break
		}

		if resp != nil {
			// Check for rate limit specifically
			if resp.StatusCode == 429 {
				resp.Body.Close()
				if i < maxRetries-1 {
					// Longer backoff for rate limits: 10s, 30s, 60s
					waitTime := time.Duration(10*(i+1)*(i+1)) * time.Second
					console.Logv(verbose, "[WAYBACK] Rate limited (429), waiting %v before retry...", waitTime)
					time.Sleep(waitTime)
					continue
				}
			}
			resp.Body.Close()
		}

		// Standard exponential backoff for other errors
		if i < maxRetries-1 {
			waitTime := time.Duration(5*(i+1)) * time.Second
			console.Logv(verbose, "[WAYBACK] Request failed, retrying in %v...", waitTime)
			time.Sleep(waitTime)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("CDX API request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CDX API returned status %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	// Parse JSON response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rawData [][]string
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse CDX response: %v", err)
	}

	// Convert to WaybackURL structs (skip header row)
	var urls []WaybackURL
	for i, row := range rawData {
		if i == 0 {
			continue // Skip header
		}
		if len(row) >= 4 {
			urls = append(urls, WaybackURL{
				URL:        row[0],
				Timestamp:  row[1],
				StatusCode: row[2],
				MimeType:   row[3],
			})
		}
	}

	console.Logv(verbose, "[WAYBACK] Found %d historical URLs", len(urls))

	// Filter noise
	urls = filterNoiseURLs(urls, verbose)
	console.Logv(verbose, "[WAYBACK] After filtering noise: %d URLs", len(urls))

	// Cache results
	cache.Set(cacheKey, urls)

	return urls, nil
}

// filterNoiseURLs removes common noise (CSS, JS libraries, images, etc.)
func filterNoiseURLs(urls []WaybackURL, verbose bool) []WaybackURL {
	noisePatterns := []string{
		// Common libraries and frameworks
		"jquery", "bootstrap", "angular", "react", "vue",
		// Static assets
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".ttf",
		// CDN and external resources
		"cloudflare", "akamai", "googleapis", "gstatic", "cloudfront",
		// Analytics and tracking
		"google-analytics", "gtag", "facebook.com/tr", "doubleclick",
		// Common noise paths
		"/assets/", "/static/", "/dist/", "/build/", "/node_modules/",
	}

	var filtered []WaybackURL
	for _, u := range urls {
		isNoise := false
		lowerURL := strings.ToLower(u.URL)

		for _, pattern := range noisePatterns {
			if strings.Contains(lowerURL, pattern) {
				isNoise = true
				break
			}
		}

		// Skip binary mime types
		if strings.HasPrefix(u.MimeType, "image/") ||
		   strings.HasPrefix(u.MimeType, "video/") ||
		   strings.HasPrefix(u.MimeType, "audio/") ||
		   strings.HasPrefix(u.MimeType, "font/") {
			isNoise = true
		}

		if !isNoise {
			filtered = append(filtered, u)
		}
	}

	return filtered
}

// filterExcludedURLs removes URLs matching user-specified exclusions
func filterExcludedURLs(urls []WaybackURL, exclusions string, verbose bool) []WaybackURL {
	if exclusions == "" {
		return urls
	}

	// Parse exclusions (can be comma-separated or from file)
	var excludePatterns []string

	if strings.Contains(exclusions, ",") {
		for _, ex := range strings.Split(exclusions, ",") {
			ex = strings.TrimSpace(ex)
			if ex != "" {
				excludePatterns = append(excludePatterns, strings.ToLower(ex))
			}
		}
	} else {
		ex := strings.TrimSpace(exclusions)
		if ex != "" {
			excludePatterns = append(excludePatterns, strings.ToLower(ex))
		}
	}

	if len(excludePatterns) == 0 {
		return urls
	}

	var filtered []WaybackURL
	excludedCount := 0

	for _, u := range urls {
		shouldExclude := false
		lowerURL := strings.ToLower(u.URL)

		// Parse URL to check components
		parsed, err := url.Parse(u.URL)
		if err != nil {
			// If can't parse, keep it
			filtered = append(filtered, u)
			continue
		}

		for _, pattern := range excludePatterns {
			// Check for "www" special case
			if pattern == "www" && strings.HasPrefix(parsed.Host, "www.") {
				shouldExclude = true
				break
			}

			// Check for subdomain exclusion (e.g., "admin")
			if strings.Contains(parsed.Host, pattern+".") || strings.HasPrefix(parsed.Host, pattern) {
				shouldExclude = true
				break
			}

			// Check for path exclusion (e.g., "/api", "/admin")
			if strings.HasPrefix(pattern, "/") && strings.Contains(parsed.Path, pattern) {
				shouldExclude = true
				break
			}

			// Check for file extension exclusion (e.g., "pdf", ".pdf")
			ext := strings.TrimPrefix(pattern, ".")
			if strings.HasSuffix(lowerURL, "."+ext) {
				shouldExclude = true
				break
			}

			// Check for wildcard pattern (e.g., "*.backup")
			if strings.HasPrefix(pattern, "*.") {
				ext := strings.TrimPrefix(pattern, "*.")
				if strings.Contains(lowerURL, "."+ext) {
					shouldExclude = true
					break
				}
			}

			// Generic substring match for other patterns
			if strings.Contains(lowerURL, pattern) {
				shouldExclude = true
				break
			}
		}

		if !shouldExclude {
			filtered = append(filtered, u)
		} else {
			excludedCount++
		}
	}

	if excludedCount > 0 {
		console.Logv(verbose, "[WAYBACK] Excluded %d URLs based on -x filters", excludedCount)
	}

	return filtered
}

// =============================================================================
// PATTERN EXTRACTION ENGINE (PHASE 1 & 2)
// =============================================================================

// extractWaybackIntelligence performs comprehensive pattern extraction
func extractWaybackIntelligence(domain string, urls []WaybackURL, verbose bool) *core.WaybackIntelligence {
	console.Logv(verbose, "[WAYBACK] Extracting patterns...")

	intel := &core.WaybackIntelligence{
		Domain:         domain,
		Subdomains:     []string{},
		SensitivePaths: []string{},
		Parameters:     make(map[string][]string),
		FilePatterns:   make(map[string][]string),
		TechStack:      []string{},
		APIEndpoints:   []string{},
		AdminPaths:     []string{},
		BackupFiles:    []string{},
		ConfigFiles:    []string{},
		TotalURLs:      len(urls),
		ProcessedAt:    time.Now(),
	}

	subdomainSet := make(map[string]struct{})
	pathSet := make(map[string]struct{})
	techSet := make(map[string]struct{})

	for _, u := range urls {
		parsed, err := url.Parse(u.URL)
		if err != nil {
			continue
		}

		// Extract subdomain
		host := strings.ToLower(parsed.Hostname())
		domainLower := strings.ToLower(domain)

		// Match: api.example.com for domain=example.com
		// Match: www.example.com for domain=example.com
		// Don't match: example.com for domain=example.com (that's the root)
		if host != domainLower {
			// Check if it's a subdomain: ends with .domain
			if strings.HasSuffix(host, "."+domainLower) {
				subdomainSet[host] = struct{}{}
			} else if host == "www."+domainLower {
				// Special case for www
				subdomainSet[host] = struct{}{}
			}
		}

		// Categorize URL
		category := categorizeURL(u.URL)

		// Extract parameters
		if category.HasParams {
			params := parsed.Query()
			for param := range params {
				if !isCommonParam(param) {
					intel.Parameters[param] = append(intel.Parameters[param], u.URL)
				}
			}
		}

		// Extract file patterns
		if category.FileExtension != "" {
			ext := category.FileExtension
			path := parsed.Path
			intel.FilePatterns[ext] = append(intel.FilePatterns[ext], path)
		}

		// Extract technology indicators
		if category.TechIndicator != "" {
			techSet[category.TechIndicator] = struct{}{}
		}

		// Extract admin paths
		if category.IsAdmin {
			intel.AdminPaths = append(intel.AdminPaths, parsed.Path)
		}

		// Extract API endpoints
		if category.IsAPI {
			intel.APIEndpoints = append(intel.APIEndpoints, parsed.Path)
		}

		// Extract backup files
		if category.IsBackup {
			intel.BackupFiles = append(intel.BackupFiles, parsed.Path)
		}

		// Extract config files
		if category.IsConfig {
			intel.ConfigFiles = append(intel.ConfigFiles, parsed.Path)
		}

		// Extract sensitive paths
		if category.IsSensitive {
			pathSet[parsed.Path] = struct{}{}
		}
	}

	// Convert sets to slices
	for subdomain := range subdomainSet {
		intel.Subdomains = append(intel.Subdomains, subdomain)
	}
	for path := range pathSet {
		intel.SensitivePaths = append(intel.SensitivePaths, path)
	}
	for tech := range techSet {
		intel.TechStack = append(intel.TechStack, tech)
	}

	// Sort for consistency
	sort.Strings(intel.Subdomains)
	sort.Strings(intel.SensitivePaths)
	sort.Strings(intel.TechStack)

	// Extract directory patterns (advanced)
	intel.DirectoryPatterns = extractDirectoryPatterns(urls, verbose)

	// Extract temporal patterns (advanced)
	intel.TemporalPatterns = extractTemporalPatterns(urls, verbose)

	// Deduplicate and limit
	intel = deduplicateIntelligence(intel)

	console.Logv(verbose, "[WAYBACK] Extracted: %d subdomains, %d parameters, %d file types, %d tech stack",
		len(intel.Subdomains), len(intel.Parameters), len(intel.FilePatterns), len(intel.TechStack))

	return intel
}

// categorizeURL categorizes a URL into various types
// isValidFileExtension checks if a file extension is valid
// Valid extensions are alphanumeric, start with a letter, and match common patterns
func isValidFileExtension(ext string) bool {
	// Remove leading dot for validation
	if strings.HasPrefix(ext, ".") {
		ext = ext[1:]
	}

	// Empty or contains special characters (excluding dot) - invalid
	if ext == "" {
		return false
	}

	// Check each character is alphanumeric
	for _, ch := range ext {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
			return false
		}
	}

	// Must start with a letter (not a number)
	if ext[0] >= '0' && ext[0] <= '9' {
		return false
	}

	return true
}

func categorizeURL(urlStr string) URLCategory {
	lowerURL := strings.ToLower(urlStr)
	category := URLCategory{}

	// Admin detection
	adminKeywords := []string{"/admin", "/administrator", "/wp-admin", "/cpanel", "/control-panel",
		"/dashboard", "/manage", "/panel", "/backend", "/console"}
	for _, kw := range adminKeywords {
		if strings.Contains(lowerURL, kw) {
			category.IsAdmin = true
			break
		}
	}

	// API detection
	apiKeywords := []string{"/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/", "/json"}
	for _, kw := range apiKeywords {
		if strings.Contains(lowerURL, kw) {
			category.IsAPI = true
			break
		}
	}

	// Backup detection
	backupKeywords := []string{"backup", ".bak", ".old", ".save", ".backup", "_backup", ".zip", ".tar", ".gz"}
	for _, kw := range backupKeywords {
		if strings.Contains(lowerURL, kw) {
			category.IsBackup = true
			break
		}
	}

	// Config detection
	configKeywords := []string{"config", "configuration", "settings", ".env", ".ini", ".yaml", ".yml", ".toml", "web.config"}
	for _, kw := range configKeywords {
		if strings.Contains(lowerURL, kw) {
			category.IsConfig = true
			break
		}
	}

	// Sensitive detection
	sensitiveKeywords := []string{"/private/", "/internal/", "/secret/", "/confidential/", "/.git/", "/.svn/",
		"/debug/", "/test/", "/temp/", "/phpinfo", "/server-status"}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lowerURL, kw) {
			category.IsSensitive = true
			break
		}
	}

	// Parameter detection
	if strings.Contains(urlStr, "?") {
		category.HasParams = true
	}

	// File extension
	parsed, err := url.Parse(urlStr)
	if err == nil {
		path := parsed.Path
		if idx := strings.LastIndex(path, "."); idx > 0 && idx < len(path)-1 {
			ext := strings.ToLower(path[idx:])
			// Validate Extension: alphanumeric only, reasonable length, doesn't start with number
			if len(ext) >= 2 && len(ext) <= 6 && isValidFileExtension(ext) {
				category.FileExtension = ext
			}
		}
	}

	// Technology detection
	techPatterns := map[string]string{
		"wordpress":  "/wp-",
		"joomla":     "/administrator/",
		"drupal":     "/sites/default/",
		"magento":    "/magento/",
		"laravel":    "/public/",
		"django":     "/django/",
		"rails":      "/rails/",
		"asp.net":    ".aspx",
		"php":        ".php",
	}
	for tech, pattern := range techPatterns {
		if strings.Contains(lowerURL, pattern) {
			category.TechIndicator = tech
			break
		}
	}

	return category
}

// extractDirectoryPatterns finds structural patterns in directory organization
func extractDirectoryPatterns(urls []WaybackURL, verbose bool) []core.DirectoryPattern {
	pathCounts := make(map[string]int)
	pathExamples := make(map[string][]string)

	// Common patterns to look for
	yearPattern := regexp.MustCompile(`/(\d{4})/`)
	monthPattern := regexp.MustCompile(`/(\d{2})/`)
	datePattern := regexp.MustCompile(`/(\d{4}-\d{2}-\d{2})/`)

	for _, u := range urls {
		parsed, err := url.Parse(u.URL)
		if err != nil {
			continue
		}
		path := parsed.Path

		// Detect /YEAR/ pattern
		if yearPattern.MatchString(path) {
			template := yearPattern.ReplaceAllString(path, "/{YEAR}/")
			pathCounts[template]++
			if len(pathExamples[template]) < 5 {
				pathExamples[template] = append(pathExamples[template], path)
			}
		}

		// Detect /YEAR/MONTH/ pattern
		if yearPattern.MatchString(path) && monthPattern.MatchString(path) {
			template := yearPattern.ReplaceAllString(path, "/{YEAR}/")
			template = monthPattern.ReplaceAllString(template, "/{MONTH}/")
			pathCounts[template]++
			if len(pathExamples[template]) < 5 {
				pathExamples[template] = append(pathExamples[template], path)
			}
		}

		// Detect /DATE/ pattern
		if datePattern.MatchString(path) {
			template := datePattern.ReplaceAllString(path, "/{DATE}/")
			pathCounts[template]++
			if len(pathExamples[template]) < 5 {
				pathExamples[template] = append(pathExamples[template], path)
			}
		}
	}

	var patterns []core.DirectoryPattern
	for template, count := range pathCounts {
		if count >= 3 { // Only include patterns seen at least 3 times
			vars := []string{}
			if strings.Contains(template, "{YEAR}") {
				vars = append(vars, "YEAR")
			}
			if strings.Contains(template, "{MONTH}") {
				vars = append(vars, "MONTH")
			}
			if strings.Contains(template, "{DATE}") {
				vars = append(vars, "DATE")
			}

			patterns = append(patterns, core.DirectoryPattern{
				Template:  template,
				Variables: vars,
				Examples:  pathExamples[template],
				Count:     count,
			})
		}
	}

	// Sort by count (most common first)
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Count > patterns[j].Count
	})

	return patterns
}

// extractTemporalPatterns finds time-based patterns (e.g., backup_2020.zip, backup_2021.zip)
func extractTemporalPatterns(urls []WaybackURL, verbose bool) []core.TemporalPattern {
	yearPattern := regexp.MustCompile(`(backup|db|dump|archive|export)_?(\d{4})\.(zip|sql|tar|gz|bak)`)
	patterns := make(map[string]*core.TemporalPattern)

	for _, u := range urls {
		matches := yearPattern.FindStringSubmatch(u.URL)
		if len(matches) >= 4 {
			prefix := matches[1]
			yearStr := matches[2]
			ext := matches[3]
			patternKey := fmt.Sprintf("%s_{YEAR}.%s", prefix, ext)

			timestamp, _ := time.Parse("20060102150405", u.Timestamp)

			if p, exists := patterns[patternKey]; exists {
				if timestamp.Before(p.FirstSeen) {
					p.FirstSeen = timestamp
				}
				if timestamp.After(p.LastSeen) {
					p.LastSeen = timestamp
				}
				// Add year to seen years
				year := atoi(yearStr)
				if !containsInt(p.SeenYears, year) {
					p.SeenYears = append(p.SeenYears, year)
				}
			} else {
				year := atoi(yearStr)
				patterns[patternKey] = &core.TemporalPattern{
					Pattern:   patternKey,
					FirstSeen: timestamp,
					LastSeen:  timestamp,
					SeenYears: []int{year},
				}
			}
		}
	}

	// Calculate missing years for each pattern
	var result []core.TemporalPattern
	for _, p := range patterns {
		if len(p.SeenYears) >= 2 {
			sort.Ints(p.SeenYears)
			minYear := p.SeenYears[0]
			maxYear := p.SeenYears[len(p.SeenYears)-1]

			// Find missing years in range
			for year := minYear; year <= maxYear; year++ {
				if !containsInt(p.SeenYears, year) {
					p.MissingYears = append(p.MissingYears, year)
				}
			}

			result = append(result, *p)
		}
	}

	return result
}

// deduplicateIntelligence removes duplicates and limits results
func deduplicateIntelligence(intel *core.WaybackIntelligence) *core.WaybackIntelligence {
	// Limit parameters to most common ones
	if len(intel.Parameters) > 100 {
		// Keep top 100 parameters by occurrence count
		type paramCount struct {
			param string
			count int
		}
		var counts []paramCount
		for param, urls := range intel.Parameters {
			counts = append(counts, paramCount{param, len(urls)})
		}
		sort.Slice(counts, func(i, j int) bool {
			return counts[i].count > counts[j].count
		})

		newParams := make(map[string][]string)
		for i := 0; i < 100 && i < len(counts); i++ {
			param := counts[i].param
			newParams[param] = intel.Parameters[param]
		}
		intel.Parameters = newParams
	}

	// Limit file patterns per extension
	for ext, paths := range intel.FilePatterns {
		if len(paths) > 50 {
			intel.FilePatterns[ext] = paths[:50]
		}
	}

	// Limit admin paths
	if len(intel.AdminPaths) > 50 {
		intel.AdminPaths = intel.AdminPaths[:50]
	}

	// Limit API endpoints
	if len(intel.APIEndpoints) > 50 {
		intel.APIEndpoints = intel.APIEndpoints[:50]
	}

	return intel
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

func isCommonParam(param string) bool {
	common := []string{"utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid", "ref", "source"}
	param = strings.ToLower(param)
	for _, c := range common {
		if param == c {
			return true
		}
	}
	return false
}

// =============================================================================
// CACHING SYSTEM
// =============================================================================

// NewWaybackCache creates a new cache instance
func NewWaybackCache() *WaybackCache {
	home, _ := os.UserHomeDir()
	cachePath := filepath.Join(home, ".config", "banshee", ".wayback_cache")
	os.MkdirAll(cachePath, 0755)
	return &WaybackCache{
		cachePath: cachePath,
	}
}

// Get retrieves cached results
func (c *WaybackCache) Get(key string) ([]WaybackURL, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	hash := hashKey(key)
	cacheFile := filepath.Join(c.cachePath, hash+".json")

	// Check if cache exists and is less than 24 hours old
	info, err := os.Stat(cacheFile)
	if err != nil {
		return nil, err
	}
	if time.Since(info.ModTime()) > 24*time.Hour {
		return nil, fmt.Errorf("cache expired")
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, err
	}

	var urls []WaybackURL
	if err := json.Unmarshal(data, &urls); err != nil {
		return nil, err
	}

	return urls, nil
}

// Set stores results in cache
func (c *WaybackCache) Set(key string, urls []WaybackURL) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	hash := hashKey(key)
	cacheFile := filepath.Join(c.cachePath, hash+".json")

	data, err := json.Marshal(urls)
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFile, data, 0644)
}

func hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// =============================================================================
// DORK GENERATION FROM PATTERNS (PHASE 3)
// =============================================================================

// generateDorksFromWayback generates targeted dorks from Wayback intelligence
// If aiPrompt is provided, generates contextual dorks matching the user's intent
func generateDorksFromWayback(domain string, intel *core.WaybackIntelligence, aiPrompt string, verbose bool) []string {
	console.Logv(verbose, "[WAYBACK] Generating targeted dorks...")

	var allDorks []string

	// If AI prompt is provided, generate contextual dorks
	if aiPrompt != "" {
		promptLower := strings.ToLower(aiPrompt)

		// Detect user intent from prompt
		wantsXSS := strings.Contains(promptLower, "xss") || strings.Contains(promptLower, "cross-site")
		wantsSQLi := strings.Contains(promptLower, "sql") || strings.Contains(promptLower, "injection") || strings.Contains(promptLower, "sqli")
		wantsLFI := strings.Contains(promptLower, "lfi") || strings.Contains(promptLower, "file inclusion") || strings.Contains(promptLower, "path traversal")
		wantsRedirect := strings.Contains(promptLower, "redirect") || strings.Contains(promptLower, "open redirect")
		wantsAdmin := strings.Contains(promptLower, "admin") || strings.Contains(promptLower, "login") || strings.Contains(promptLower, "dashboard") || strings.Contains(promptLower, "panel")
		wantsAPI := strings.Contains(promptLower, "api") || strings.Contains(promptLower, "endpoint") || strings.Contains(promptLower, "rest") || strings.Contains(promptLower, "graphql")
		wantsFiles := strings.Contains(promptLower, "file") || strings.Contains(promptLower, "pdf") || strings.Contains(promptLower, "document") || strings.Contains(promptLower, "backup")
		wantsConfig := strings.Contains(promptLower, "config") || strings.Contains(promptLower, "env") || strings.Contains(promptLower, "settings")

		console.Logv(verbose, "[WAYBACK] Generating contextual dorks for prompt: %s", aiPrompt)

		// Generate only relevant dorks based on intent
		if wantsXSS || wantsSQLi || wantsLFI || wantsRedirect {
			allDorks = append(allDorks, generateContextualParamDorks(domain, intel, wantsXSS, wantsSQLi, wantsLFI, wantsRedirect)...)
		}
		if wantsAdmin {
			allDorks = append(allDorks, generateSensitivePathDorks(domain, intel)...)
			allDorks = append(allDorks, generateSubdomainDorks(intel)...) // Include subdomain dorks for admin hunting
		}
		if wantsAPI {
			allDorks = append(allDorks, generateAPIDorks(domain, intel)...)
		}
		if wantsFiles {
			allDorks = append(allDorks, generateFileBasedDorks(domain, intel)...)
		}
		if wantsConfig {
			allDorks = append(allDorks, generateConfigDorks(domain, intel)...)
		}

		// If no specific intent detected, inform user
		if !wantsXSS && !wantsSQLi && !wantsLFI && !wantsRedirect && !wantsAdmin && !wantsAPI && !wantsFiles && !wantsConfig {
			console.Logv(verbose, "[WAYBACK] No specific vulnerability type detected in prompt, generating comprehensive dorks")
			// Generate all types
			allDorks = append(allDorks, generateContextualParamDorks(domain, intel, true, true, true, true)...)
			allDorks = append(allDorks, generateSubdomainDorks(intel)...)
			allDorks = append(allDorks, generateSensitivePathDorks(domain, intel)...)
			allDorks = append(allDorks, generateAPIDorks(domain, intel)...)
		}
	} else {
		// No AI prompt - generate comprehensive dorks
		console.Logv(verbose, "[WAYBACK] No AI prompt provided, generating comprehensive dorks")

		// 1. File-based dorks
		allDorks = append(allDorks, generateFileBasedDorks(domain, intel)...)

		// 2. Parameter-based dorks
		allDorks = append(allDorks, generateParamBasedDorks(domain, intel)...)

		// 3. Subdomain-specific dorks
		allDorks = append(allDorks, generateSubdomainDorks(intel)...)

		// 4. Technology-specific dorks
		allDorks = append(allDorks, generateTechDorks(domain, intel)...)

		// 5. Temporal prediction dorks
		allDorks = append(allDorks, generateTemporalDorks(domain, intel)...)

		// 6. Directory pattern dorks
		allDorks = append(allDorks, generateDirectoryPatternDorks(domain, intel)...)

		// 7. API endpoint dorks
		allDorks = append(allDorks, generateAPIDorks(domain, intel)...)

		// 8. Admin/sensitive path dorks
		allDorks = append(allDorks, generateSensitivePathDorks(domain, intel)...)
	}

	// Deduplicate
	allDorks = deduplicateDorks(allDorks)

	console.Logv(verbose, "[WAYBACK] Generated %d unique targeted dorks", len(allDorks))

	return allDorks
}

// generateFileBasedDorks creates dorks for file types found in Wayback
func generateFileBasedDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string

	// Document types
	docExts := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}
	for ext, paths := range intel.FilePatterns {
		if containsStr(docExts, ext) && len(paths) > 0 {
			// Extract common path components
			commonDirs := extractCommonDirectories(paths)
			for _, dir := range commonDirs {
				if dir != "" {
					dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s filetype:%s", domain, dir, strings.TrimPrefix(ext, ".")))
				}
			}

			// Generic file type dork
			dorks = append(dorks, fmt.Sprintf("site:%s filetype:%s", domain, strings.TrimPrefix(ext, ".")))
		}
	}

	// Backup files
	if len(intel.BackupFiles) > 0 {
		dorks = append(dorks, fmt.Sprintf("site:%s (backup | db | dump | archive) (filetype:zip | filetype:sql | filetype:tar)", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s (inurl:backup | inurl:db | inurl:dump)", domain))

		// Extract years from backup filenames
		yearPattern := regexp.MustCompile(`\d{4}`)
		years := make(map[string]struct{})
		for _, backup := range intel.BackupFiles {
			matches := yearPattern.FindAllString(backup, -1)
			for _, year := range matches {
				if len(year) == 4 && year >= "2015" && year <= "2025" {
					years[year] = struct{}{}
				}
			}
		}

		// Generate year-specific backup dorks
		currentYear := time.Now().Year()
		for year := currentYear - 2; year <= currentYear+1; year++ {
			yearStr := fmt.Sprintf("%d", year)
			dorks = append(dorks, fmt.Sprintf("site:%s (backup | db | dump)_%s (filetype:zip | filetype:sql)", domain, yearStr))
		}
	}

	// Config files
	if len(intel.ConfigFiles) > 0 {
		dorks = append(dorks, fmt.Sprintf("site:%s (config | configuration | settings) (filetype:php | filetype:ini | filetype:yaml | filetype:env)", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s (inurl:config | inurl:settings) ext:bak", domain))
	}

	return dorks
}

// generateParamBasedDorks creates dorks for URL parameters found in Wayback
func generateParamBasedDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string

	// Categorize parameters by vulnerability type
	sqliParams := []string{}
	xssParams := []string{}
	lfiParams := []string{}
	redirectParams := []string{}

	sqliKeywords := []string{"id", "user", "product", "category", "item", "page_id", "post_id"}
	xssKeywords := []string{"q", "search", "query", "s", "keyword", "message", "comment", "name"}
	lfiKeywords := []string{"file", "path", "page", "include", "template", "doc", "document"}
	redirectKeywords := []string{"url", "redirect", "return", "next", "goto", "destination", "redir"}

	for param := range intel.Parameters {
		paramLower := strings.ToLower(param)

		// SQLi candidates
		for _, kw := range sqliKeywords {
			if strings.Contains(paramLower, kw) {
				sqliParams = append(sqliParams, param)
				break
			}
		}

		// XSS candidates
		for _, kw := range xssKeywords {
			if strings.Contains(paramLower, kw) {
				xssParams = append(xssParams, param)
				break
			}
		}

		// LFI candidates
		for _, kw := range lfiKeywords {
			if strings.Contains(paramLower, kw) {
				lfiParams = append(lfiParams, param)
				break
			}
		}

		// Open Redirect candidates
		for _, kw := range redirectKeywords {
			if strings.Contains(paramLower, kw) {
				redirectParams = append(redirectParams, param)
				break
			}
		}
	}

	// Generate dorks for each vulnerability class
	if len(sqliParams) > 0 {
		paramList := strings.Join(limitStrings(sqliParams, 10), " | ")
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:id= (users | admin | product | edit | delete)", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s (%s)", domain, paramList))
	}

	if len(xssParams) > 0 {
		paramList := strings.Join(limitStrings(xssParams, 10), " | ")
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:search=", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s (%s)", domain, paramList))
	}

	if len(lfiParams) > 0 {
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:file= (download | view | include)", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:page= (admin | config | etc)", domain))
	}

	if len(redirectParams) > 0 {
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:redirect= -inurl:login", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:url= (http | https)", domain))
	}

	return dorks
}

// generateContextualParamDorks creates contextual parameter dorks based on user intent
func generateContextualParamDorks(domain string, intel *core.WaybackIntelligence, wantsXSS, wantsSQLi, wantsLFI, wantsRedirect bool) []string {
	var dorks []string

	// Categorize parameters by vulnerability type
	sqliParams := []string{}
	xssParams := []string{}
	lfiParams := []string{}
	redirectParams := []string{}

	sqliKeywords := []string{"id", "user", "product", "category", "item", "page_id", "post_id", "article", "news"}
	xssKeywords := []string{"q", "search", "query", "s", "keyword", "message", "comment", "name", "title", "text"}
	lfiKeywords := []string{"file", "path", "page", "include", "template", "doc", "document", "load", "read"}
	redirectKeywords := []string{"url", "redirect", "return", "next", "goto", "destination", "redir", "continue", "target"}

	for param := range intel.Parameters {
		paramLower := strings.ToLower(param)

		// SQLi candidates
		if wantsSQLi {
			for _, kw := range sqliKeywords {
				if strings.Contains(paramLower, kw) {
					sqliParams = append(sqliParams, param)
					break
				}
			}
		}

		// XSS candidates
		if wantsXSS {
			for _, kw := range xssKeywords {
				if strings.Contains(paramLower, kw) {
					xssParams = append(xssParams, param)
					break
				}
			}
		}

		// LFI candidates
		if wantsLFI {
			for _, kw := range lfiKeywords {
				if strings.Contains(paramLower, kw) {
					lfiParams = append(lfiParams, param)
					break
				}
			}
		}

		// Open Redirect candidates
		if wantsRedirect {
			for _, kw := range redirectKeywords {
				if strings.Contains(paramLower, kw) {
					redirectParams = append(redirectParams, param)
					break
				}
			}
		}
	}

	// Generate dorks only for requested vulnerability types
	if wantsSQLi && len(sqliParams) > 0 {
		// Use actual parameters found in Wayback
		for _, param := range limitStrings(sqliParams, 5) {
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s=", domain, param))
		}
		dorks = append(dorks, fmt.Sprintf("site:%s (inurl:id= | inurl:user= | inurl:product=)", domain))
	}

	if wantsXSS && len(xssParams) > 0 {
		// Use actual parameters found in Wayback
		for _, param := range limitStrings(xssParams, 5) {
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s=", domain, param))
		}
		dorks = append(dorks, fmt.Sprintf("site:%s (inurl:search= | inurl:q= | inurl:query=)", domain))
	}

	if wantsLFI && len(lfiParams) > 0 {
		for _, param := range limitStrings(lfiParams, 5) {
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s=", domain, param))
		}
		dorks = append(dorks, fmt.Sprintf("site:%s (inurl:file= | inurl:page= | inurl:path=)", domain))
	}

	if wantsRedirect && len(redirectParams) > 0 {
		for _, param := range limitStrings(redirectParams, 5) {
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s=http", domain, param))
		}
		dorks = append(dorks, fmt.Sprintf("site:%s (inurl:redirect= | inurl:url=)", domain))
	}

	return dorks
}

// generateConfigDorks creates dorks for configuration files
func generateConfigDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string

	// Config file dorks
	if len(intel.ConfigFiles) > 0 {
		dorks = append(dorks, fmt.Sprintf("site:%s (config | configuration | settings) (filetype:php | filetype:ini | filetype:yaml | filetype:env)", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s (inurl:config | inurl:settings) ext:bak", domain))
		dorks = append(dorks, fmt.Sprintf("site:%s filetype:env (DB_ | API_ | KEY_ | SECRET_)", domain))
	}

	// Environment files
	dorks = append(dorks, fmt.Sprintf("site:%s (filetype:env | filetype:ini | filetype:yaml | filetype:toml)", domain))
	dorks = append(dorks, fmt.Sprintf("site:%s inurl:.env", domain))

	return dorks
}

// generateSubdomainDorks creates targeted dorks for discovered subdomains
func generateSubdomainDorks(intel *core.WaybackIntelligence) []string {
	var dorks []string

	for _, subdomain := range intel.Subdomains {
		subLower := strings.ToLower(subdomain)

		// Admin subdomains
		if strings.Contains(subLower, "admin") || strings.Contains(subLower, "portal") {
			dorks = append(dorks, fmt.Sprintf("site:%s (login | signin | dashboard)", subdomain))
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:login", subdomain))
		}

		// API subdomains
		if strings.Contains(subLower, "api") {
			dorks = append(dorks, fmt.Sprintf("site:%s (swagger | docs | v1 | v2 | graphql)", subdomain))
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:api intitle:documentation", subdomain))
		}

		// Dev/staging subdomains
		if strings.Contains(subLower, "dev") || strings.Contains(subLower, "staging") || 
		   strings.Contains(subLower, "test") || strings.Contains(subLower, "uat") {
			dorks = append(dorks, fmt.Sprintf("site:%s (debug | test | phpinfo | config)", subdomain))
			dorks = append(dorks, fmt.Sprintf("site:%s ext:log (error | debug)", subdomain))
		}

		// Old/legacy subdomains
		if strings.Contains(subLower, "old") || strings.Contains(subLower, "legacy") || 
		   strings.Contains(subLower, "archive") {
			dorks = append(dorks, fmt.Sprintf("site:%s intitle:\"index of\"", subdomain))
			dorks = append(dorks, fmt.Sprintf("site:%s (backup | old | archive)", subdomain))
		}
	}

	return dorks
}

// generateTechDorks creates technology-specific dorks
func generateTechDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string

	for _, tech := range intel.TechStack {
		switch strings.ToLower(tech) {
		case "wordpress":
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:wp-content/uploads filetype:sql", domain))
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:wp-config.php ext:bak", domain))
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:wp-admin inurl:install", domain))

		case "joomla":
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:configuration.php", domain))
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:/administrator/ intitle:login", domain))

		case "drupal":
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:sites/default/files", domain))
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:settings.php ext:bak", domain))

		case "php":
			dorks = append(dorks, fmt.Sprintf("site:%s ext:php inurl:config", domain))
			dorks = append(dorks, fmt.Sprintf("site:%s phpinfo()", domain))
		}
	}

	return dorks
}

// generateTemporalDorks generates dorks based on temporal patterns
func generateTemporalDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string
	currentYear := time.Now().Year()

	for _, pattern := range intel.TemporalPatterns {
		// Generate dorks for missing years
		for _, year := range pattern.MissingYears {
			if year >= currentYear-5 && year <= currentYear {
				actual := strings.ReplaceAll(pattern.Pattern, "{YEAR}", fmt.Sprintf("%d", year))
				dorks = append(dorks, fmt.Sprintf("site:%s %s", domain, actual))
			}
		}

		// Generate dorks for current and next year (prediction)
		for year := currentYear; year <= currentYear+1; year++ {
			actual := strings.ReplaceAll(pattern.Pattern, "{YEAR}", fmt.Sprintf("%d", year))
			dorks = append(dorks, fmt.Sprintf("site:%s %s", domain, actual))
		}
	}

	return dorks
}

// generateDirectoryPatternDorks generates dorks from directory patterns
func generateDirectoryPatternDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string
	currentYear := time.Now().Year()

	for _, pattern := range intel.DirectoryPatterns {
		// Generate for current year
		template := pattern.Template
		if strings.Contains(template, "{YEAR}") {
			for year := currentYear - 1; year <= currentYear+1; year++ {
				actual := strings.ReplaceAll(template, "{YEAR}", fmt.Sprintf("%d", year))
				
				if strings.Contains(actual, "{MONTH}") {
					// Generate for each month
					for month := 1; month <= 12; month++ {
						monthStr := fmt.Sprintf("%02d", month)
						monthActual := strings.ReplaceAll(actual, "{MONTH}", monthStr)
						dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s", domain, monthActual))
					}
				} else {
					dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s", domain, actual))
				}
			}
		}

		// Index of directories
		if pattern.Count >= 5 {
			baseDir := extractBaseDirectory(pattern.Template)
			if baseDir != "" {
				dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s intitle:\"index of\"", domain, baseDir))
			}
		}
	}

	return dorks
}

// generateAPIDorks generates API enumeration dorks
func generateAPIDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string

	if len(intel.APIEndpoints) > 0 {
		// Detect API versioning
		versions := make(map[string]struct{})
		versionPattern := regexp.MustCompile(`/v(\d+)/`)

		for _, endpoint := range intel.APIEndpoints {
			matches := versionPattern.FindStringSubmatch(endpoint)
			if len(matches) >= 2 {
				versions[matches[1]] = struct{}{}
			}
		}

		// Generate dorks for detected versions + potential new versions
		maxVersion := 0
		for v := range versions {
			ver := atoi(v)
			if ver > maxVersion {
				maxVersion = ver
			}
		}

		// Try up to 2 versions ahead
		for v := 1; v <= maxVersion+2; v++ {
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:api/v%d", domain, v))
		}

		// Common API endpoints
		commonEndpoints := []string{"users", "admin", "config", "internal", "debug", "test"}
		for _, endpoint := range commonEndpoints {
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:api inurl:%s", domain, endpoint))
		}

		// API documentation
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:api (swagger | docs | documentation)", domain))
	}

	return dorks
}

// generateSensitivePathDorks generates dorks for admin/sensitive paths
func generateSensitivePathDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string

	// Admin paths
	if len(intel.AdminPaths) > 0 {
		commonAdminDirs := extractCommonDirectories(intel.AdminPaths)
		for _, dir := range limitStrings(commonAdminDirs, 10) {
			if dir != "" && dir != "/" {
				dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s (login | dashboard | panel)", domain, dir))
			}
		}
	}

	// Generic sensitive paths
	sensitiveDirs := []string{"/admin", "/backup", "/private", "/internal", "/debug", "/test", "/.git", "/.env"}
	for _, dir := range sensitiveDirs {
		dorks = append(dorks, fmt.Sprintf("site:%s inurl:%s", domain, dir))
	}

	return dorks
}

// =============================================================================
// UTILITY FUNCTIONS FOR DORK GENERATION
// =============================================================================

func extractCommonDirectories(paths []string) []string {
	dirCounts := make(map[string]int)

	for _, path := range paths {
		parts := strings.Split(path, "/")
		for i := 1; i < len(parts)-1; i++ { // Skip empty first and filename last
			if parts[i] != "" {
				dirCounts[parts[i]]++
			}
		}
	}

	var common []string
	for dir, count := range dirCounts {
		if count >= 3 { // Appear at least 3 times
			common = append(common, dir)
		}
	}

	return common
}

func extractBaseDirectory(template string) string {
	// Extract the base directory from a template like /uploads/{YEAR}/{MONTH}/
	parts := strings.Split(template, "/")
	for _, part := range parts {
		if part != "" && !strings.Contains(part, "{") {
			return part
		}
	}
	return ""
}

func deduplicateDorks(dorks []string) []string {
	seen := make(map[string]struct{})
	var unique []string

	for _, dork := range dorks {
		if _, exists := seen[dork]; !exists {
			seen[dork] = struct{}{}
			unique = append(unique, dork)
		}
	}

	return unique
}

func limitStrings(strs []string, max int) []string {
	if len(strs) <= max {
		return strs
	}
	return strs[:max]
}

func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// =============================================================================
// INTELLIGENCE STORAGE (Integration with existing intelligence system)
// =============================================================================

// saveWaybackIntelligence saves Wayback intelligence to .intel/ directory
func saveWaybackIntelligence(domain string, intel *core.WaybackIntelligence) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	intelDir := filepath.Join(home, ".config", "banshee", ".intel")
	os.MkdirAll(intelDir, 0755)

	filename := filepath.Join(intelDir, fmt.Sprintf("%s_wayback.json", sanitizeFilename(domain)))

	data, err := json.MarshalIndent(intel, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// loadWaybackIntelligence loads cached Wayback intelligence
func loadWaybackIntelligence(domain string) (*core.WaybackIntelligence, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	filename := filepath.Join(home, ".config", "banshee", ".intel", fmt.Sprintf("%s_wayback.json", sanitizeFilename(domain)))

	// Check if cache is less than 7 days old
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if time.Since(info.ModTime()) > 7*24*time.Hour {
		return nil, fmt.Errorf("intelligence cache expired")
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var intel core.WaybackIntelligence
	if err := json.Unmarshal(data, &intel); err != nil {
		return nil, err
	}

	return &intel, nil
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "*", "_")
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.ReplaceAll(s, "\"", "_")
	s = strings.ReplaceAll(s, "<", "_")
	s = strings.ReplaceAll(s, ">", "_")
	s = strings.ReplaceAll(s, "|", "_")
	return s
}

// =============================================================================
// CACHE MANAGEMENT (LRU + TTL)
// =============================================================================

// clearAllWaybackCache removes all Wayback cache (URLs + intelligence)
func clearAllWaybackCache() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cacheDir := filepath.Join(homeDir, ".config", "banshee", ".wayback_cache")
	intelDir := filepath.Join(homeDir, ".config", "banshee", ".intel")

	var errors []string

	// Remove URL cache
	if err := os.RemoveAll(cacheDir); err != nil && !os.IsNotExist(err) {
		errors = append(errors, fmt.Sprintf("URL cache: %v", err))
	}

	// Remove intelligence cache (only .wayback.json files)
	if _, err := os.Stat(intelDir); err == nil {
		files, err := filepath.Glob(filepath.Join(intelDir, "*.wayback.json"))
		if err == nil {
			for _, file := range files {
				if err := os.Remove(file); err != nil {
					errors = append(errors, fmt.Sprintf("%s: %v", filepath.Base(file), err))
				}
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during cleanup: %s", strings.Join(errors, "; "))
	}

	return nil
}

// cleanupWaybackCache performs LRU + TTL cleanup
// Returns number of entries removed
func cleanupWaybackCache(maxAgeDays int, maxSizeBytes int64) (int, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return 0, err
	}

	cacheDir := filepath.Join(homeDir, ".config", "banshee", ".wayback_cache")
	intelDir := filepath.Join(homeDir, ".config", "banshee", ".intel")

	removed := 0

	// Cleanup URL cache
	if r, err := cleanupDirectory(cacheDir, maxAgeDays, maxSizeBytes/2); err == nil {
		removed += r
	}

	// Cleanup intelligence cache (only .wayback.json files)
	if r, err := cleanupWaybackIntelligence(intelDir, maxAgeDays, maxSizeBytes/2); err == nil {
		removed += r
	}

	return removed, nil
}

// cleanupDirectory removes old files based on TTL and LRU
func cleanupDirectory(dir string, maxAgeDays int, maxSizeBytes int64) (int, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return 0, nil
	}

	type fileInfo struct {
		path    string
		modTime time.Time
		size    int64
	}

	var files []fileInfo
	var totalSize int64

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() {
			files = append(files, fileInfo{
				path:    path,
				modTime: info.ModTime(),
				size:    info.Size(),
			})
			totalSize += info.Size()
		}
		return nil
	})

	if err != nil {
		return 0, err
	}

	removed := 0
	cutoffTime := time.Now().AddDate(0, 0, -maxAgeDays)

	// Phase 1: Remove files older than maxAgeDays (TTL)
	for _, f := range files {
		if f.modTime.Before(cutoffTime) {
			if err := os.Remove(f.path); err == nil {
				removed++
				totalSize -= f.size
			}
		}
	}

	// Phase 2: If still over size limit, remove oldest files (LRU)
	if totalSize > maxSizeBytes {
		// Sort by modification time (oldest first)
		sort.Slice(files, func(i, j int) bool {
			return files[i].modTime.Before(files[j].modTime)
		})

		for _, f := range files {
			if totalSize <= maxSizeBytes {
				break
			}
			// Check if file still exists (might have been removed in Phase 1)
			if _, err := os.Stat(f.path); err == nil {
				if err := os.Remove(f.path); err == nil {
					removed++
					totalSize -= f.size
				}
			}
		}
	}

	return removed, nil
}

// cleanupWaybackIntelligence removes old .wayback.json files
func cleanupWaybackIntelligence(dir string, maxAgeDays int, maxSizeBytes int64) (int, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return 0, nil
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.wayback.json"))
	if err != nil {
		return 0, err
	}

	type fileInfo struct {
		path    string
		modTime time.Time
		size    int64
	}

	var fileInfos []fileInfo
	var totalSize int64

	cutoffTime := time.Now().AddDate(0, 0, -maxAgeDays)
	removed := 0

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		// Phase 1: Remove old files (TTL)
		if info.ModTime().Before(cutoffTime) {
			if err := os.Remove(file); err == nil {
				removed++
			}
			continue
		}

		fileInfos = append(fileInfos, fileInfo{
			path:    file,
			modTime: info.ModTime(),
			size:    info.Size(),
		})
		totalSize += info.Size()
	}

	// Phase 2: If over size limit, remove oldest (LRU)
	if totalSize > maxSizeBytes {
		sort.Slice(fileInfos, func(i, j int) bool {
			return fileInfos[i].modTime.Before(fileInfos[j].modTime)
		})

		for _, f := range fileInfos {
			if totalSize <= maxSizeBytes {
				break
			}
			if err := os.Remove(f.path); err == nil {
				removed++
				totalSize -= f.size
			}
		}
	}

	return removed, nil
}

// =============================================================================
// AI-POWERED DORK GENERATION
// =============================================================================

// UserIntent represents the analyzed user intent from AI prompt
type UserIntent struct {
	VulnerabilityTypes []string          // e.g., ["XSS", "SQLi", "LFI"]
	TargetKeywords     []string          // e.g., ["search", "input", "query"]
	AvoidKeywords      []string          // e.g., ["pagination", "size", "sorting"]
	Priority           string            // "high", "medium", "low"
	Context            map[string]string // Additional context from AI
}

// ParameterAnalysis represents AI analysis of a parameter
type ParameterAnalysis struct {
	Parameter      string
	Purpose        string  // e.g., "search input", "pagination", "filtering"
	VulnRelevance  float64 // 0.0 to 1.0 confidence for vulnerability
	RelevantFor    []string
	SampleURLs     []string
	Recommendation string
}

// analyzeUserIntentWithAI uses AI to understand what the user wants to find
func analyzeUserIntentWithAI(aiPrompt string, verbose bool) (*UserIntent, error) {
	if aiPrompt == "" {
		return &UserIntent{
			VulnerabilityTypes: []string{"XSS", "SQLi", "LFI", "OpenRedirect"},
			Priority:           "medium",
		}, nil
	}

	systemPrompt := `You are a security researcher assistant. Analyze the user's prompt and extract their intent.

CRITICAL: Output ONLY valid JSON. NO explanations, NO markdown, NO code blocks, NO extra text.
Just the raw JSON object starting with { and ending with }.

Expected format:
{
  "vulnerability_types": ["XSS", "SQLi", "LFI", "OpenRedirect", "Admin", "API", "Secrets", "Documents", "RCE"],
  "target_keywords": ["search", "query", "input"],
  "avoid_keywords": ["size", "page", "limit", "sort"],
  "priority": "high",
  "context": {"focus": "user input fields"}
}

Vulnerability types you can detect:
- XSS: Cross-site scripting, DOM XSS, reflected XSS
- SQLi: SQL injection, database queries
- LFI: Local file inclusion, path traversal, directory traversal
- RCE: Remote code execution, command injection, shell injection
- XXE: XML external entity injection
- SSRF: Server-side request forgery
- IDOR: Insecure direct object reference
- OpenRedirect: URL redirection vulnerabilities
- Admin: Admin panels, dashboards, login pages, authentication bypass
- API: API endpoints, REST APIs, GraphQL, webhooks
- Secrets: API keys, tokens, credentials, passwords, config files, .env files
- Documents: Sensitive documents (PDF, DOC, DOCX, PPT, PPTX, XLS, XLSX, TXT, CSV)
- Backup: Backup files, database dumps, archives (ZIP, TAR, SQL, BAK, OLD)

IMPORTANT RULES:
1. If user mentions a specific vulnerability type (RCE, XXE, SSRF, IDOR, etc.), use EXACTLY that type in the output
2. If user says "documents" or "files", set vulnerability_types to ["Documents"]
3. If user says "sensitive documents", set to ["Documents", "Secrets"]
4. If user asks for multiple types, include ALL of them
5. Be LITERAL - don't replace user's terms with different ones

Target Keywords: Parameters/paths that are LIKELY vulnerable
Avoid Keywords: Parameters that are UNLIKELY to be vulnerable (pagination, styling, etc.)

Examples:
User: "find XSS vulnerabilities"
Output: {"vulnerability_types":["XSS"],"target_keywords":["search","query","q","keyword","input","message"],"avoid_keywords":["page","size","limit","offset","sort"],"priority":"high","context":{}}

User: "look for admin panels"
Output: {"vulnerability_types":["Admin"],"target_keywords":["admin","login","dashboard","panel"],"avoid_keywords":["search","query"],"priority":"high","context":{}}

User: "find sensitive documents"
Output: {"vulnerability_types":["Documents","Secrets"],"target_keywords":["pdf","doc","docx","ppt","pptx","xls","xlsx","report","confidential","internal"],"avoid_keywords":["blog","news","public"],"priority":"high","context":{}}

User: "find RCE"
Output: {"vulnerability_types":["RCE"],"target_keywords":["cmd","exec","command","shell","eval","system"],"avoid_keywords":["search","query"],"priority":"high","context":{}}

User: "find SSRF or XXE"
Output: {"vulnerability_types":["SSRF","XXE"],"target_keywords":["url","uri","xml","feed","import"],"avoid_keywords":["search"],"priority":"high","context":{}}`

	userPrompt := fmt.Sprintf("User's security testing goal: %s", aiPrompt)

	response, err := callAIWithRetry(systemPrompt, userPrompt, 10000, verbose)
	if err != nil {
		console.Logv(verbose, "[WAYBACK] AI intent analysis failed: %v, using defaults", err)
		return &UserIntent{
			VulnerabilityTypes: []string{"XSS", "SQLi", "LFI"},
			Priority:           "medium",
		}, nil
	}

	// Parse JSON response
	var result struct {
		VulnerabilityTypes []string          `json:"vulnerability_types"`
		TargetKeywords     []string          `json:"target_keywords"`
		AvoidKeywords      []string          `json:"avoid_keywords"`
		Priority           string            `json:"priority"`
		Context            map[string]string `json:"context"`
	}

	if err := json.Unmarshal([]byte(response), &result); err != nil {
		console.Logv(verbose, "[WAYBACK] Failed to parse AI intent: %v", err)
		return &UserIntent{
			VulnerabilityTypes: []string{"XSS", "SQLi"},
			Priority:           "medium",
		}, nil
	}

	return &UserIntent{
		VulnerabilityTypes: result.VulnerabilityTypes,
		TargetKeywords:     result.TargetKeywords,
		AvoidKeywords:      result.AvoidKeywords,
		Priority:           result.Priority,
		Context:            result.Context,
	}, nil
}

// analyzeParametersWithAI uses AI to analyze parameter relevance and purpose
func analyzeParametersWithAI(domain string, parameters map[string][]string, intent *UserIntent, verbose bool) []ParameterAnalysis {
	if len(parameters) == 0 {
		return nil
	}

	// Build parameter context for AI
	paramList := make([]string, 0, len(parameters))
	paramURLs := make(map[string][]string)

	for param, urls := range parameters {
		paramList = append(paramList, param)
		// Limit to 3 example URLs per parameter
		if len(urls) > 3 {
			paramURLs[param] = urls[:3]
		} else {
			paramURLs[param] = urls
		}
	}

	// Limit to top 20 parameters to avoid token limits
	if len(paramList) > 20 {
		paramList = paramList[:20]
	}

	systemPrompt := `You are a web security expert. Analyze URL parameters and determine their relevance for security testing.

CRITICAL: Output ONLY a valid JSON array. NO explanations, NO markdown, NO code blocks, NO extra text.
Just the raw JSON array starting with [ and ending with ].

For each parameter, output JSON with:
{
  "parameter": "param_name",
  "purpose": "description of what this parameter does",
  "vuln_relevance": 0.0-1.0 (confidence it's vulnerable),
  "relevant_for": ["XSS", "SQLi"],
  "recommendation": "test for XSS" or "skip - pagination"
}

HIGH relevance (0.8-1.0): search, query, id, user, file, path, url, redirect
MEDIUM relevance (0.4-0.7): name, email, message, comment, title
LOW relevance (0.0-0.3): page, size, limit, sort, offset, lang, view, tab`

	userPrompt := fmt.Sprintf(`Domain: %s
User intent: %v
Parameters to analyze:
%s

Analyze each parameter's security relevance.`, domain, intent.VulnerabilityTypes, buildParameterContext(paramList, paramURLs))

	response, err := callAIWithRetry(systemPrompt, userPrompt, 15000, verbose)
	if err != nil {
		console.Logv(verbose, "[WAYBACK] Parameter analysis failed: %v", err)
		return filterParametersBasic(paramList, intent)
	}

	// Parse JSON - handle both array and single object responses
	type paramResult struct {
		Parameter      string   `json:"parameter"`
		Purpose        string   `json:"purpose"`
		VulnRelevance  float64  `json:"vuln_relevance"`
		RelevantFor    []string `json:"relevant_for"`
		Recommendation string   `json:"recommendation"`
	}

	var results []paramResult

	// Try parsing as array first
	if err := json.Unmarshal([]byte(response), &results); err != nil {
		// If that fails, try parsing as single object
		var singleResult paramResult
		if err2 := json.Unmarshal([]byte(response), &singleResult); err2 != nil {
			console.Logv(verbose, "[WAYBACK] Failed to parse parameter analysis: %v", err)
			return filterParametersBasic(paramList, intent)
		}
		// Wrap single object in array
		results = []paramResult{singleResult}
	}

	analyses := make([]ParameterAnalysis, 0, len(results))
	for _, r := range results {
		if r.VulnRelevance >= 0.5 { // Only include relevant parameters
			analyses = append(analyses, ParameterAnalysis{
				Parameter:      r.Parameter,
				Purpose:        r.Purpose,
				VulnRelevance:  r.VulnRelevance,
				RelevantFor:    r.RelevantFor,
				SampleURLs:     paramURLs[r.Parameter],
				Recommendation: r.Recommendation,
			})
		}
	}

	return analyses
}

// buildParameterContext creates a context string for AI analysis
func buildParameterContext(params []string, urls map[string][]string) string {
	var sb strings.Builder
	for _, param := range params {
		sb.WriteString(fmt.Sprintf("\n- %s", param))
		if examples, ok := urls[param]; ok && len(examples) > 0 {
			sb.WriteString(fmt.Sprintf(" (found in: %s)", examples[0]))
		}
	}
	return sb.String()
}

// filterParametersBasic is a fallback when AI fails
func filterParametersBasic(params []string, intent *UserIntent) []ParameterAnalysis {
	highValue := []string{"search", "q", "query", "id", "user", "file", "path", "url", "redirect", "page_id", "post_id"}
	skipParams := []string{"page", "size", "limit", "offset", "sort", "order", "view", "tab", "lang"}

	var analyses []ParameterAnalysis
	for _, param := range params {
		paramLower := strings.ToLower(param)

		// Skip noise parameters
		shouldSkip := false
		for _, skip := range skipParams {
			if strings.Contains(paramLower, skip) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
			continue
		}

		// Check for high-value parameters
		relevance := 0.5
		for _, hv := range highValue {
			if strings.Contains(paramLower, hv) {
				relevance = 0.9
				break
			}
		}

		if relevance >= 0.5 {
			analyses = append(analyses, ParameterAnalysis{
				Parameter:     param,
				Purpose:       "unknown (AI analysis failed)",
				VulnRelevance: relevance,
				RelevantFor:   intent.VulnerabilityTypes,
			})
		}
	}

	return analyses
}

// isSimplePrompt detects if a prompt is simple enough to skip intent analysis
func isSimplePrompt(prompt string) bool {
	if prompt == "" {
		return true
	}

	// Simple prompts are:
	// 1. Short (< 50 characters)
	// 2. Don't contain complex sentence structures (no commas, semicolons, multiple sentences)
	// 3. Clear and direct (e.g., "find XSS", "find documents", "find admin panels")

	promptLower := strings.ToLower(prompt)

	// Check length - long prompts are complex
	if len(prompt) > 50 {
		return false
	}

	// Check for multiple sentences (periods followed by space)
	if strings.Contains(prompt, ". ") {
		return false
	}

	// Check for complex structures (multiple clauses)
	complexIndicators := []string{", ", "; ", " and ", " or ", " that ", " which ", " where "}
	for _, indicator := range complexIndicators {
		if strings.Contains(promptLower, indicator) {
			return false
		}
	}

	// Simple patterns like "find X", "search X", "look for X"
	simplePatterns := []string{"find ", "search ", "look for ", "get ", "show "}
	for _, pattern := range simplePatterns {
		if strings.HasPrefix(promptLower, pattern) {
			// Check if rest is simple (single word or short phrase)
			rest := strings.TrimPrefix(promptLower, pattern)
			if len(strings.Fields(rest)) <= 3 {
				return true
			}
		}
	}

	// If just 1-3 words, it's simple
	if len(strings.Fields(prompt)) <= 3 {
		return true
	}

	return false
}

// generateAIPoweredWaybackDorks creates high-quality dorks using AI analysis
func generateAIPoweredWaybackDorks(domain string, intel *core.WaybackIntelligence, aiPrompt string, quantity int, verbose bool, wafBypass bool) []string {
	var dorks []string

	// Smart intent analysis: skip for simple prompts, use for complex ones
	if isSimplePrompt(aiPrompt) {
		// FAST PATH: Simple prompt - skip intent analysis, go directly to dork generation
		dorks = generateAICreativeDorksDirectly(domain, intel, aiPrompt, quantity, verbose)
	} else {
		// COMPLEX PATH: Complex prompt - use intent analysis for better understanding
		console.Logv(verbose, "[WAYBACK-AI] Analyzing user intent (complex prompt detected)...")

		intent, err := analyzeUserIntentWithAI(aiPrompt, verbose)
		if err != nil {
			console.Logv(verbose, "[WAYBACK-AI] Intent analysis failed: %v, falling back to direct generation", err)
			// Fallback to direct generation if intent analysis fails
			dorks = generateAICreativeDorksDirectly(domain, intel, aiPrompt, quantity, verbose)
		} else {
			console.Logv(verbose, "[WAYBACK-AI] User wants to find: %v", intent.VulnerabilityTypes)
			console.Logv(verbose, "[WAYBACK-AI] Studying target architecture from Wayback intelligence...")
			dorks = generateAICreativeDorksFromIntelligence(domain, intel, intent, aiPrompt, quantity, verbose)

			if len(dorks) == 0 {
				console.Logv(verbose, "[WAYBACK-AI] AI generation produced no dorks, using fallback")
				dorks = generateFallbackDorks(domain, intel, intent, quantity)
			}
		}
	}

	// Deduplicate
	dorks = deduplicateDorks(dorks)

	// Step 3: Apply WAF bypass techniques if enabled
	if wafBypass {
		console.Logv(verbose, "[WAYBACK-WAF] Applying WAF bypass techniques...")
		var bypassDorks []string
		for _, dork := range dorks {
			variations := applyWAFBypass(dork)
			bypassDorks = append(bypassDorks, variations...)
		}
		dorks = deduplicateDorks(bypassDorks)
		console.Logv(verbose, "[WAYBACK-WAF] Generated %d dork variations with WAF bypass", len(dorks))
	}

	// Limit to requested quantity
	if quantity > 0 && len(dorks) > quantity {
		dorks = dorks[:quantity]
	}

	return dorks
}

// generateAICreativeDorksDirectly generates dorks directly from prompt without intent analysis (for simple prompts)
func generateAICreativeDorksDirectly(domain string, intel *core.WaybackIntelligence, aiPrompt string, quantity int, verbose bool) []string {
	// Build comprehensive intelligence summary for AI
	var intelSummary strings.Builder

	// Parameters discovered
	if len(intel.Parameters) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nPARAMETERS (%d discovered):\n", len(intel.Parameters)))
		count := 0
		for param := range intel.Parameters {
			if count < 20 {
				intelSummary.WriteString(fmt.Sprintf("- %s\n", param))
				count++
			}
		}
		if len(intel.Parameters) > 20 {
			intelSummary.WriteString(fmt.Sprintf("... and %d more\n", len(intel.Parameters)-20))
		}
	}

	// File patterns
	if len(intel.FilePatterns) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nFILE TYPES (%d types):\n", len(intel.FilePatterns)))
		count := 0
		for ext, paths := range intel.FilePatterns {
			if count < 15 {
				intelSummary.WriteString(fmt.Sprintf("- %s (%d files)\n", ext, len(paths)))
				count++
			}
		}
	}

	// Technology stack
	if len(intel.TechStack) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nTECHNOLOGY STACK:\n"))
		for _, tech := range intel.TechStack {
			intelSummary.WriteString(fmt.Sprintf("- %s\n", tech))
		}
	}

	// Directory patterns
	if len(intel.DirectoryPatterns) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nDIRECTORY PATTERNS (%d patterns):\n", len(intel.DirectoryPatterns)))
		count := 0
		for _, dp := range intel.DirectoryPatterns {
			if count < 10 {
				intelSummary.WriteString(fmt.Sprintf("- %s (seen %d times)\n", dp.Template, dp.Count))
				count++
			}
		}
	}

	// API endpoints
	if len(intel.APIEndpoints) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nAPI ENDPOINTS (%d endpoints):\n", len(intel.APIEndpoints)))
		count := 0
		for _, ep := range intel.APIEndpoints {
			if count < 10 {
				intelSummary.WriteString(fmt.Sprintf("- %s\n", ep))
				count++
			}
		}
	}

	// Admin paths
	if len(intel.AdminPaths) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nADMIN/SENSITIVE PATHS (%d paths):\n", len(intel.AdminPaths)))
		count := 0
		for _, ap := range intel.AdminPaths {
			if count < 10 {
				intelSummary.WriteString(fmt.Sprintf("- %s\n", ap))
				count++
			}
		}
	}

	// Subdomains
	if len(intel.Subdomains) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nSUBDOMAINS (%d discovered):\n", len(intel.Subdomains)))
		count := 0
		for _, sub := range intel.Subdomains {
			if count < 15 {
				intelSummary.WriteString(fmt.Sprintf("- %s\n", sub))
				count++
			}
		}
	}

	// Build AI prompt for creative dork generation (direct approach without intent analysis)
	prompt := fmt.Sprintf(`You are a security researcher analyzing Wayback Machine intelligence for %s.

TARGET: %s
USER GOAL: %s

WAYBACK INTELLIGENCE (Historical Data):
%s

YOUR TASK:
Study this intelligence to understand the target's:
1. Architecture patterns (how they structure URLs, paths, parameters)
2. Technology stack and frameworks being used
3. Naming conventions and organizational patterns
4. Potential vulnerability surfaces based on these patterns

Generate %d creative Google dorks that help achieve the user's goal.

Guidelines:
- Use the intelligence to understand WHERE relevant content/vulnerabilities might exist
- Create DIFFERENT search strategies (not just copying the Wayback patterns)
- Target similar architectural patterns in creative ways
- Use diverse operators: site:, inurl:, filetype:, intitle:, intext:, ext:, OR, AND, ()
- Combine multiple patterns to find related content

IMPORTANT RULES:
- DO NOT just copy exact Wayback URLs/parameters
- BE CREATIVE - use the intelligence to infer similar patterns
- Generate dorks that would find SIMILAR but DIFFERENT pages
- Think about what OTHER pages might exist with similar architecture
- Use Google dork operators creatively

Output format (plain text, one dork per line, no numbering):
site:%s ...
site:%s ...`,
		domain,
		domain,
		aiPrompt,
		intelSummary.String(),
		quantity,
		domain,
		domain)

	// Call AI to generate creative dorks
	console.Logv(verbose, "[WAYBACK-AI] Asking AI to generate %d creative dorks from intelligence...", quantity)
	dorks, err := callAIForDorks(prompt, verbose)

	if err != nil {
		console.Logv(verbose, "[WAYBACK-AI] Creative generation failed: %v", err)
		return nil
	}

	console.Logv(verbose, "[WAYBACK-AI] AI generated %d creative dorks based on architecture analysis", len(dorks))
	return dorks
}

// generateAICreativeDorksFromIntelligence uses AI to study Wayback intelligence and generate creative dorks
func generateAICreativeDorksFromIntelligence(domain string, intel *core.WaybackIntelligence, intent *UserIntent, aiPrompt string, quantity int, verbose bool) []string {
	// Build comprehensive intelligence summary for AI
	var intelSummary strings.Builder

	// Parameters discovered
	if len(intel.Parameters) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nPARAMETERS (%d discovered):\n", len(intel.Parameters)))
		count := 0
		for param := range intel.Parameters {
			if count < 20 { // Limit to avoid token overflow
				intelSummary.WriteString(fmt.Sprintf("- %s\n", param))
				count++
			}
		}
		if len(intel.Parameters) > 20 {
			intelSummary.WriteString(fmt.Sprintf("... and %d more\n", len(intel.Parameters)-20))
		}
	}

	// File patterns
	if len(intel.FilePatterns) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nFILE TYPES (%d types):\n", len(intel.FilePatterns)))
		count := 0
		for ext, paths := range intel.FilePatterns {
			if count < 15 {
				intelSummary.WriteString(fmt.Sprintf("- %s (%d files)\n", ext, len(paths)))
				count++
			}
		}
	}

	// Technology stack
	if len(intel.TechStack) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nTECHNOLOGY STACK:\n"))
		for _, tech := range intel.TechStack {
			intelSummary.WriteString(fmt.Sprintf("- %s\n", tech))
		}
	}

	// Directory patterns
	if len(intel.DirectoryPatterns) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nDIRECTORY PATTERNS (%d patterns):\n", len(intel.DirectoryPatterns)))
		count := 0
		for _, dp := range intel.DirectoryPatterns {
			if count < 10 {
				intelSummary.WriteString(fmt.Sprintf("- %s (seen %d times)\n", dp.Template, dp.Count))
				count++
			}
		}
	}

	// API endpoints
	if len(intel.APIEndpoints) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nAPI ENDPOINTS (%d endpoints):\n", len(intel.APIEndpoints)))
		count := 0
		for _, ep := range intel.APIEndpoints {
			if count < 10 {
				intelSummary.WriteString(fmt.Sprintf("- %s\n", ep))
				count++
			}
		}
	}

	// Admin paths
	if len(intel.AdminPaths) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nADMIN/SENSITIVE PATHS (%d paths):\n", len(intel.AdminPaths)))
		count := 0
		for _, ap := range intel.AdminPaths {
			if count < 10 {
				intelSummary.WriteString(fmt.Sprintf("- %s\n", ap))
				count++
			}
		}
	}

	// Subdomains
	if len(intel.Subdomains) > 0 {
		intelSummary.WriteString(fmt.Sprintf("\nSUBDOMAINS (%d discovered):\n", len(intel.Subdomains)))
		count := 0
		for _, sub := range intel.Subdomains {
			if count < 15 {
				intelSummary.WriteString(fmt.Sprintf("- %s\n", sub))
				count++
			}
		}
	}

	// Build AI prompt for creative dork generation
	prompt := fmt.Sprintf(`You are a security researcher analyzing Wayback Machine intelligence for %s.

TARGET: %s
USER GOAL: %s
VULNERABILITIES TO FIND: %s

WAYBACK INTELLIGENCE (Historical Data):
%s

YOUR TASK:
Study this intelligence to understand the target's:
1. Architecture patterns (how they structure URLs, paths, parameters)
2. Technology stack and frameworks being used
3. Naming conventions and organizational patterns
4. Potential vulnerability surfaces based on these patterns

Generate %d creative Google dorks that:
- Use the intelligence to understand WHERE vulnerabilities might exist
- Create DIFFERENT search strategies (not just copying the Wayback patterns)
- Target similar architectural patterns in creative ways
- Use diverse operators: site:, inurl:, filetype:, intitle:, intext:, ext:, OR, AND, ()
- Combine multiple patterns to find related vulnerabilities

IMPORTANT RULES:
- DO NOT just copy exact Wayback URLs/parameters
- BE CREATIVE - use the intelligence to infer similar patterns
- Generate dorks that would find SIMILAR but DIFFERENT pages
- Think about what OTHER pages might exist with similar architecture
- Use Google dork operators creatively

Output format (plain text, one dork per line, no numbering):
site:%s ...
site:%s ...`,
		domain,
		domain,
		aiPrompt,
		strings.Join(intent.VulnerabilityTypes, ", "),
		intelSummary.String(),
		quantity,
		domain,
		domain)

	// Call AI to generate creative dorks
	console.Logv(verbose, "[WAYBACK-AI] Asking AI to generate %d creative dorks from intelligence...", quantity)
	dorks, err := callAIForDorks(prompt, verbose)

	if err != nil {
		console.Logv(verbose, "[WAYBACK-AI] Creative generation failed: %v", err)
		return nil
	}

	console.Logv(verbose, "[WAYBACK-AI] AI generated %d creative dorks based on architecture analysis", len(dorks))
	return dorks
}

// generateDorksForParameter uses AI to create creative, contextual dorks for a specific parameter
func generateDorksForParameter(domain string, analysis ParameterAnalysis, intent *UserIntent, intel *core.WaybackIntelligence, verbose bool) []string {
	// Build rich context for AI
	param := analysis.Parameter

	// Build AI prompt for creative dork generation - SIMPLIFIED to avoid timeouts
	prompt := fmt.Sprintf(`Generate 2 creative Google dorks for %s vulnerabilities on %s.

Parameter: %s
Purpose: %s

Rules:
- Use: site:, inurl:, filetype:, OR, AND, ()
- Focus on paths and URLs, minimal intext:/intitle:
- Target hidden endpoints, APIs, admin panels

Output format (plain text, one per line):
site:%s inurl:...
site:%s inurl:...`,
		strings.Join(intent.VulnerabilityTypes, "/"),
		domain,
		param,
		analysis.Purpose,
		domain,
		domain)

	// Call AI to generate creative dorks
	dorks, err := callAIForDorks(prompt, verbose)
	if err != nil {
		console.Logv(verbose, "[WAYBACK-AI] Dork generation failed for parameter %s: %v, using smart fallback", param, err)
		// Smart fallback: generate one creative dork based on context
		return []string{
			fmt.Sprintf(`site:%s inurl:%s= inurl:?`, domain, param),
		}
	}

	// Limit to 2 dorks per parameter
	if len(dorks) > 2 {
		dorks = dorks[:2]
	}

	return dorks
}

// callAIForDorks calls gemini-cli to generate creative dorks
func callAIForDorks(prompt string, verbose bool) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get AI model from config file or use default
	aiModel := getAIModelFromConfig()
	if aiModel == "" {
		aiModel = "gemini-2.0-flash-exp" // fallback default
	}

	// Use gemini-cli for dork generation with configured model
	cmd := exec.CommandContext(ctx, "gemini-cli", "--model", aiModel)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Env = os.Environ()

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("AI call failed: %v", err)
	}

	// Parse dorks from output (one per line)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var dorks []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines, comments, markdown code blocks, and lines without site:
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "```") && strings.Contains(line, "site:") {
			dorks = append(dorks, line)
		}
	}

	if len(dorks) == 0 {
		return nil, fmt.Errorf("AI generated no valid dorks")
	}

	return dorks, nil
}

// generateFileTypeDorks creates dorks targeting specific file types found in Wayback
func generateFileTypeDorks(domain string, intel *core.WaybackIntelligence, intent *UserIntent) []string {
	var dorks []string
	targetExtensions := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".log", ".json", ".xml", ".env", ".sql", ".bak"}

	for ext := range intel.FilePatterns {
		// Only target interesting file types
		for _, target := range targetExtensions {
			if ext == target {
				dorks = append(dorks, fmt.Sprintf(`site:%s filetype:%s`, domain, strings.TrimPrefix(ext, ".")))
				break
			}
		}
	}

	return dorks
}

// generateAPIEndpointDorks creates dorks targeting API endpoints found in Wayback
func generateAPIEndpointDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string
	if len(intel.APIEndpoints) == 0 {
		return dorks
	}

	// Extract common API path patterns
	apiPaths := make(map[string]int)
	for _, path := range intel.APIEndpoints {
		// Extract first 2-3 path segments as pattern
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) >= 2 {
			pattern := "/" + parts[0] + "/" + parts[1]
			apiPaths[pattern]++
		}
	}

	// Generate dorks for most common API patterns
	count := 0
	for pattern := range apiPaths {
		if count >= 2 {
			break
		}
		dorks = append(dorks, fmt.Sprintf(`site:%s inurl:%s`, domain, pattern))
		count++
	}

	return dorks
}

// generateAdminPathDorks creates dorks targeting admin paths found in Wayback
func generateAdminPathDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string
	if len(intel.AdminPaths) == 0 {
		return dorks
	}

	// Use first few admin paths for targeted dorks
	count := 0
	for _, path := range intel.AdminPaths {
		if count >= 2 {
			break
		}
		dorks = append(dorks, fmt.Sprintf(`site:%s inurl:%s`, domain, path))
		count++
	}

	return dorks
}

// generateSensitiveFileDorks creates dorks targeting backup and config files
func generateSensitiveFileDorks(domain string, intel *core.WaybackIntelligence) []string {
	var dorks []string

	// Backup files
	if len(intel.BackupFiles) > 0 {
		dorks = append(dorks, fmt.Sprintf(`site:%s (inurl:backup OR inurl:.bak OR inurl:.old)`, domain))
	}

	// Config files
	if len(intel.ConfigFiles) > 0 {
		dorks = append(dorks, fmt.Sprintf(`site:%s (inurl:config OR inurl:.env OR inurl:settings)`, domain))
	}

	return dorks
}

// generateSmartSubdomainDorks creates intelligent subdomain-targeted dorks
func generateSmartSubdomainDorks(intel *core.WaybackIntelligence, intent *UserIntent) []string {
	var dorks []string

	for _, subdomain := range intel.Subdomains {
		subLower := strings.ToLower(subdomain)

		// Admin hunting
		if containsAny(intent.VulnerabilityTypes, []string{"Admin"}) {
			if strings.Contains(subLower, "admin") || strings.Contains(subLower, "portal") || strings.Contains(subLower, "manage") {
				dorks = append(dorks, fmt.Sprintf(`site:%s (login OR signin OR dashboard)`, subdomain))
			}
		}

		// API hunting
		if containsAny(intent.VulnerabilityTypes, []string{"API"}) {
			if strings.Contains(subLower, "api") {
				dorks = append(dorks, fmt.Sprintf(`site:%s (inurl:/v1/ OR inurl:/v2/ OR inurl:/api/)`, subdomain))
				dorks = append(dorks, fmt.Sprintf(`site:%s (graphql OR swagger OR openapi)`, subdomain))
			}
		}
	}

	return dorks
}

// generateSmartPathDorks creates path-based dorks for sensitive areas
func generateSmartPathDorks(domain string, intel *core.WaybackIntelligence, intent *UserIntent) []string {
	var dorks []string

	// Admin paths
	if containsAny(intent.VulnerabilityTypes, []string{"Admin"}) && len(intel.AdminPaths) > 0 {
		uniquePaths := deduplicateStrings(intel.AdminPaths)
		for i, path := range uniquePaths {
			if i >= 3 {
				break
			}
			dorks = append(dorks, fmt.Sprintf(`site:%s inurl:%s`, domain, path))
		}
	}

	// API paths
	if containsAny(intent.VulnerabilityTypes, []string{"API"}) && len(intel.APIEndpoints) > 0 {
		uniquePaths := deduplicateStrings(intel.APIEndpoints)
		for i, path := range uniquePaths {
			if i >= 3 {
				break
			}
			dorks = append(dorks, fmt.Sprintf(`site:%s inurl:%s (json OR xml OR api)`, domain, path))
		}
	}

	return dorks
}

// generateFallbackDorks creates basic dorks when parameter analysis yields nothing
func generateFallbackDorks(domain string, intel *core.WaybackIntelligence, intent *UserIntent, quantity int) []string {
	var dorks []string

	// Generate basic dorks based on intent
	for _, vulnType := range intent.VulnerabilityTypes {
		if quantity > 0 && len(dorks) >= quantity {
			break
		}

		switch vulnType {
		case "XSS":
			dorks = append(dorks, fmt.Sprintf(`site:%s (inurl:search= OR inurl:q= OR inurl:query=)`, domain))
		case "SQLi":
			dorks = append(dorks, fmt.Sprintf(`site:%s (inurl:id= OR inurl:user= OR inurl:product=)`, domain))
		case "Admin":
			dorks = append(dorks, fmt.Sprintf(`site:%s (inurl:admin OR inurl:login OR inurl:dashboard)`, domain))
		case "API":
			dorks = append(dorks, fmt.Sprintf(`site:%s (inurl:/api/ OR inurl:/v1/ OR inurl:graphql)`, domain))
		}
	}

	// Limit to requested quantity
	if quantity > 0 && len(dorks) > quantity {
		dorks = dorks[:quantity]
	}

	return dorks
}

// Helper functions

// callAIWithRetry calls the AI model for analysis
func callAIWithRetry(systemPrompt, userPrompt string, maxTokens int, verbose bool) (string, error) {
	// Get AI model from config file or use default
	aiModel := getAIModelFromConfig()
	if aiModel == "" {
		aiModel = "gemini-2.0-flash-exp" // fallback default
	}

	// Simplified args - just model and prompt, no system or max-tokens
	args := []string{
		"--model", aiModel,
	}

	// Combine system and user prompt for simpler call
	fullPrompt := systemPrompt + "\n\n" + userPrompt

	cmd := exec.Command("gemini-cli", args...)
	cmd.Stdin = strings.NewReader(fullPrompt)
	cmd.Env = os.Environ()

	// Retry logic for transient errors
	maxRetries := 3
	var lastErr error
	var output []byte
	var err error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Re-create command for each attempt
		cmd := exec.Command("gemini-cli", args...)
		cmd.Stdin = strings.NewReader(fullPrompt)
		cmd.Env = os.Environ()

		output, err = cmd.CombinedOutput()
		if err != nil {
			lastErr = err
			errStr := err.Error()
			outputStr := string(output)

			// Check if this is a retryable error
			isRetryable := strings.Contains(errStr, "signal: killed") ||
				strings.Contains(errStr, "killed") ||
				strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "connection") ||
				strings.Contains(errStr, "429") ||
				strings.Contains(outputStr, "429") ||
				strings.Contains(outputStr, "Resource exhausted")

			if !isRetryable {
				// Non-retryable error - fail immediately
				return "", fmt.Errorf("AI call failed: %v, output: %s", err, outputStr)
			}

			// Retryable error - log and retry with backoff
			if attempt < maxRetries {
				backoff := time.Duration(attempt*2) * time.Second
				console.Logv(verbose, "[WAYBACK-AI] Attempt %d failed (%v), retrying in %v...", attempt, errStr, backoff)
				time.Sleep(backoff)
				continue
			}

			// All retries exhausted
			return "", fmt.Errorf("AI call failed after %d attempts: %v, output: %s", maxRetries, lastErr, outputStr)
		}

		// Success!
		break
	}

	// Extract JSON from response (handle markdown code blocks and extra text)
	response := strings.TrimSpace(string(output))
	response = extractJSON(response)

	return response, nil
}

// extractJSON extracts JSON from AI responses that may contain markdown or extra text
func extractJSON(text string) string {
	// Remove markdown code blocks
	if strings.Contains(text, "```json") {
		start := strings.Index(text, "```json")
		if start != -1 {
			text = text[start+7:]
			end := strings.Index(text, "```")
			if end != -1 {
				text = text[:end]
			}
		}
	} else if strings.Contains(text, "```") {
		start := strings.Index(text, "```")
		if start != -1 {
			text = text[start+3:]
			end := strings.Index(text, "```")
			if end != -1 {
				text = text[:end]
			}
		}
	}

	// Find JSON object or array
	text = strings.TrimSpace(text)

	// Look for JSON object
	if idx := strings.Index(text, "{"); idx != -1 {
		// Find matching closing brace
		depth := 0
		for i := idx; i < len(text); i++ {
			if text[i] == '{' {
				depth++
			} else if text[i] == '}' {
				depth--
				if depth == 0 {
					return text[idx : i+1]
				}
			}
		}
	}

	// Look for JSON array
	if idx := strings.Index(text, "["); idx != -1 {
		// Find matching closing bracket
		depth := 0
		for i := idx; i < len(text); i++ {
			if text[i] == '[' {
				depth++
			} else if text[i] == ']' {
				depth--
				if depth == 0 {
					return text[idx : i+1]
				}
			}
		}
	}

	return text
}

func containsAny(slice []string, items []string) bool {
	for _, item := range items {
		for _, s := range slice {
			if strings.EqualFold(s, item) {
				return true
			}
		}
	}
	return false
}

func deduplicateStrings(slice []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// getAIModelFromConfig reads the AI model from the config file
func getAIModelFromConfig() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	configPath := filepath.Join(homeDir, ".config", "banshee", ".config")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	// Parse config file for model= line
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "model=") {
			model := strings.TrimPrefix(line, "model=")
			model = strings.TrimSpace(model)
			if model != "" && model != "default" {
				return model
			}
		}
	}

	return ""
}

// applyWAFBypass applies WAF bypass techniques to a dork
// Returns multiple variations of the dork with different bypass techniques
func applyWAFBypass(dork string) []string {
	variations := []string{dork} // Always include original

	// Extract the domain from site: operator
	sitePattern := regexp.MustCompile(`site:([^\s]+)`)
	siteMatch := sitePattern.FindStringSubmatch(dork)
	if len(siteMatch) < 2 {
		return variations
	}
	domain := siteMatch[1]

	// Technique 1: Use wildcard subdomains
	if !strings.HasPrefix(domain, "*.") {
		wildcardDork := strings.Replace(dork, "site:"+domain, "site:*."+domain, 1)
		variations = append(variations, wildcardDork)
	}

	// Technique 2: Replace inurl: with intitle: for some queries
	if strings.Contains(dork, "inurl:") && !strings.Contains(dork, "intitle:") {
		titleDork := strings.Replace(dork, "inurl:", "intitle:", 1)
		variations = append(variations, titleDork)
	}

	// Technique 3: Add wildcard matching for parameters
	// Convert "inurl:param=" to "inurl:param=*"
	paramPattern := regexp.MustCompile(`inurl:([a-zA-Z_]+)=`)
	if paramPattern.MatchString(dork) {
		wildcardParamDork := paramPattern.ReplaceAllString(dork, "inurl:$1=*")
		if wildcardParamDork != dork {
			variations = append(variations, wildcardParamDork)
		}
	}

	// Technique 4: Use allinurl: instead of multiple inurl: operators
	inurlCount := strings.Count(dork, "inurl:")
	if inurlCount > 1 {
		// Extract all inurl: values
		inurlPattern := regexp.MustCompile(`inurl:([^\s)]+)`)
		matches := inurlPattern.FindAllStringSubmatch(dork, -1)
		if len(matches) > 1 {
			var inurlValues []string
			for _, match := range matches {
				if len(match) > 1 {
					inurlValues = append(inurlValues, match[1])
				}
			}
			// Remove all inurl: operators and add allinurl:
			cleanDork := inurlPattern.ReplaceAllString(dork, "")
			cleanDork = strings.TrimSpace(cleanDork)
			allinurlDork := cleanDork + " allinurl:" + strings.Join(inurlValues, " ")
			variations = append(variations, allinurlDork)
		}
	}

	// Technique 5: Use cache: operator to find cached versions
	cacheDork := "cache:" + domain + " " + strings.Replace(dork, "site:"+domain, "", 1)
	variations = append(variations, strings.TrimSpace(cacheDork))

	// Limit to 3 most effective variations to avoid overwhelming the user
	if len(variations) > 3 {
		variations = variations[:3]
	}

	return variations
}
