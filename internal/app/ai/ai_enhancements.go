package ai

import (
	"bytes"
	"context"
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
	"time"
	"unicode"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"
)

// ========== SMART MODE: Context-Aware Dork Chaining ==========

// analyzeResultsForFollowUp analyzes search results and generates contextual follow-up dorks
// Learns from ACTUAL patterns found in successful results, not just repeating original prompt
func (c *Config) analyzeResultsForFollowUp(ctx context.Context, results []string, aiPrompt string) []string {
	if !c.SmartMode || len(results) == 0 || c.NoFollowUp {
		return nil
	}

	var followUpDorks []string
	discoveredAssets := make(map[string]bool)

	// Extract patterns from successful results
	successPatterns := extractPatternsFromResults(results)

	// Update intelligence with success patterns
	if c.LearnMode && c.Intelligence != nil {
		for _, pattern := range successPatterns {
			// Check if pattern already exists
			found := false
			for i, existing := range c.Intelligence.SuccessPatterns {
				if existing.Pattern == pattern.Pattern && existing.Context == pattern.Context {
					c.Intelligence.SuccessPatterns[i].SuccessCount += pattern.SuccessCount
					c.Intelligence.SuccessPatterns[i].LastSeen = pattern.LastSeen
					found = true
					break
				}
			}
			if !found {
				c.Intelligence.SuccessPatterns = append(c.Intelligence.SuccessPatterns, pattern)
			}
		}
	}

	// Extract interesting patterns from results
	for _, url := range results {
		// Discover new subdomains and generate PATTERN-BASED follow-up dorks
		subdomain := extractSubdomain(url, c.Target)
		if subdomain != "" && !discoveredAssets["subdomain:"+subdomain] {
			discoveredAssets["subdomain:"+subdomain] = true

			// IMPROVED: Instead of repeating prompt, use patterns found in results
			// Extract path patterns from successful URLs
			pathPattern := extractPathPattern(url)
			if pathPattern != "" {
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s inurl:%s", subdomain, pathPattern),
				)
			}

			// Extract parameter patterns from successful URLs
			params := extractParameters(url)
			for _, param := range params {
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s inurl:?%s=", subdomain, param),
				)
			}

			// If URL has dashboard in path, target dashboard on this subdomain
			if strings.Contains(strings.ToLower(url), "dashboard") {
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s inurl:dashboard", subdomain),
				)
			}

			// If URL has login in path, target login on this subdomain
			if strings.Contains(strings.ToLower(url), "login") {
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s inurl:login", subdomain),
				)
			}

			// If URL has admin context, generate admin-specific dorks
			context := detectContext(url)
			if context == "admin" {
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s inurl:admin (inurl:? OR inurl:&)", subdomain),
				)
			} else if context == "api" {
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s inurl:api (inurl:v1 OR inurl:v2 OR inurl:v3)", subdomain),
				)
			}

			// Extract file type from successful URL
			fileType := extractFileType(url)
			if fileType != "" {
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s filetype:%s", subdomain, fileType),
				)
			}
		}
	}

	// Use top success patterns from intelligence if available
	if c.LearnMode && c.Intelligence != nil && len(c.Intelligence.SuccessPatterns) > 0 {
		// Sort patterns by success count
		patterns := make([]core.SuccessPattern, len(c.Intelligence.SuccessPatterns))
		copy(patterns, c.Intelligence.SuccessPatterns)
		// Simple sort by success count (descending)
		for i := 0; i < len(patterns)-1; i++ {
			for j := i + 1; j < len(patterns); j++ {
				if patterns[j].SuccessCount > patterns[i].SuccessCount {
					patterns[i], patterns[j] = patterns[j], patterns[i]
				}
			}
		}

		// Apply top patterns to newly discovered subdomains
		for subdomain := range discoveredAssets {
			subdomain = strings.TrimPrefix(subdomain, "subdomain:")
			for i, pattern := range patterns {
				if i >= 3 { // Limit to top 3 patterns
					break
				}
				followUpDorks = append(followUpDorks,
					fmt.Sprintf("site:%s %s", subdomain, pattern.Pattern),
				)
			}
		}
	}

	if len(followUpDorks) > 0 {
		console.Logv(c.Verbose, "[SMART-PATTERN] Generated %d pattern-based follow-up dorks from discoveries", len(followUpDorks))
	}

	// Remove duplicates
	followUpDorks = removeDuplicates(followUpDorks)

	// Limit to configured maximum (default 5, configurable via --max-followup)
	if c.MaxFollowUp > 0 && len(followUpDorks) > c.MaxFollowUp {
		console.Logv(c.Verbose, "[SMART-PATTERN] Limiting to %d follow-up dorks (use --max-followup to change)", c.MaxFollowUp)
		followUpDorks = followUpDorks[:c.MaxFollowUp]
	}

	return followUpDorks
}

// ========== MULTI-LAYER INTELLIGENCE CORRELATION ==========

// DiscoveryContext tracks correlated discoveries for cross-layer intelligence
type DiscoveryContext struct {
	Subdomains      []string
	Paths           []string
	FileTypes       []string
	Parameters      []string
	Environments    []string // staging, dev, test, etc.
	AssetCategories []string // admin, api, config, etc.
}

// correlateDiscoveries performs multi-layer intelligence correlation
// Cross-correlates subdomains, paths, file types, and parameters to generate targeted dorks
// When --smart mode is enabled, uses AI for creative dork generation; otherwise uses templates
func (c *Config) correlateDiscoveries(ctx context.Context, results []string) []string {
	if !c.SmartMode || len(results) == 0 {
		return nil
	}

	console.Logv(c.Verbose, "[SMART-CORRELATION] Analyzing %d results for cross-layer patterns...", len(results))

	// Build discovery context
	discoveryCtx := &DiscoveryContext{
		Subdomains:      make([]string, 0),
		Paths:           make([]string, 0),
		FileTypes:       make([]string, 0),
		Parameters:      make([]string, 0),
		Environments:    make([]string, 0),
		AssetCategories: make([]string, 0),
	}

	// Track unique discoveries
	subdomainSet := make(map[string]bool)
	pathSet := make(map[string]bool)
	fileTypeSet := make(map[string]bool)
	paramSet := make(map[string]bool)
	envSet := make(map[string]bool)
	categorySet := make(map[string]bool)

	// Extract all discovery types from results
	for _, url := range results {
		urlLower := strings.ToLower(url)

		// Extract subdomain
		subdomain := extractSubdomain(url, c.Target)
		if subdomain != "" && !subdomainSet[subdomain] {
			subdomainSet[subdomain] = true
			discoveryCtx.Subdomains = append(discoveryCtx.Subdomains, subdomain)
		}

		// Extract path segments
		pathPatterns := extractPathPatterns(url)
		for _, path := range pathPatterns {
			if !pathSet[path] {
				pathSet[path] = true
				discoveryCtx.Paths = append(discoveryCtx.Paths, path)
			}
		}

		// Extract file type
		if strings.Contains(urlLower, ".") {
			parts := strings.Split(urlLower, ".")
			if len(parts) > 0 {
				ext := parts[len(parts)-1]
				// Clean extension (remove query params)
				ext = strings.Split(ext, "?")[0]
				ext = strings.Split(ext, "#")[0]
				if len(ext) >= 2 && len(ext) <= 5 && !fileTypeSet[ext] {
					fileTypeSet[ext] = true
					discoveryCtx.FileTypes = append(discoveryCtx.FileTypes, ext)
				}
			}
		}

		// Detect parameters
		if strings.Contains(url, "?") {
			paramPart := strings.Split(url, "?")[1]
			params := strings.Split(paramPart, "&")
			for _, param := range params {
				if strings.Contains(param, "=") {
					paramName := strings.Split(param, "=")[0]
					if !paramSet[paramName] {
						paramSet[paramName] = true
						discoveryCtx.Parameters = append(discoveryCtx.Parameters, paramName)
					}
				}
			}
		}

		// Detect environment keywords
		envKeywords := []string{"staging", "stage", "stg", "dev", "develop", "test", "testing", "uat", "qa", "demo", "sandbox"}
		for _, keyword := range envKeywords {
			if strings.Contains(urlLower, keyword) && !envSet[keyword] {
				envSet[keyword] = true
				discoveryCtx.Environments = append(discoveryCtx.Environments, keyword)
			}
		}

		// Categorize asset type
		categories := map[string][]string{
			"admin":  {"admin", "administrator", "dashboard", "panel"},
			"api":    {"api", "rest", "graphql", "endpoint"},
			"config": {"config", "configuration", "settings", ".env"},
			"backup": {"backup", "bak", "old", "save", "dump"},
			"upload": {"upload", "uploads", "files", "media"},
			"auth":   {"login", "auth", "authenticate", "signin", "sso", "oauth"},
		}
		for category, keywords := range categories {
			for _, keyword := range keywords {
				if strings.Contains(urlLower, keyword) && !categorySet[category] {
					categorySet[category] = true
					discoveryCtx.AssetCategories = append(discoveryCtx.AssetCategories, category)
				}
			}
		}
	}

	// If smart mode is enabled, try AI-driven dork generation first
	if c.SmartMode {
		aiDorks := c.generateAICorrelatedDorks(ctx, discoveryCtx)
		if len(aiDorks) > 0 {
			// AI generation succeeded, return AI-generated dorks
			return aiDorks
		}
		// AI failed or returned nothing, fall through to template-based approach
		console.Logv(c.Verbose, "[SMART-AI] Falling back to template-based correlation dorks")
	}

	// Generate correlated dorks per subdomain (template-based fallback)
	var allSubdomainDorks [][]string

	// Sort subdomains alphabetically for consistent processing
	sort.Strings(discoveryCtx.Subdomains)

	// Process one subdomain at a time (alphabetically)
	// This ensures organized correlation and prevents overwhelming output
	for _, subdomain := range discoveryCtx.Subdomains {
		var subdomainDorks []string

		// CORRELATION 1: Subdomain + Asset Category
		// Example: Found admin.dell.com + discovered /api paths → target admin.dell.com specifically for sensitive endpoints
		for _, category := range discoveryCtx.AssetCategories {
			switch category {
			case "admin":
				subdomainDorks = append(subdomainDorks,
					fmt.Sprintf("site:%s (inurl:config OR inurl:backup OR inurl:keys OR inurl:credentials)", subdomain),
					fmt.Sprintf("site:%s (inurl:? OR inurl:&) (inurl:user OR inurl:id OR inurl:admin)", subdomain),
				)
			case "api":
				subdomainDorks = append(subdomainDorks,
					fmt.Sprintf("site:%s inurl:api (inurl:v1 OR inurl:v2 OR inurl:v3) (inurl:users OR inurl:admin OR inurl:config)", subdomain),
					fmt.Sprintf("site:%s (inurl:swagger OR inurl:docs OR inurl:api-docs)", subdomain),
				)
			case "config":
				subdomainDorks = append(subdomainDorks,
					fmt.Sprintf("site:%s (filetype:json OR filetype:yml OR filetype:yaml OR filetype:xml)", subdomain),
					fmt.Sprintf("site:%s (intext:password OR intext:secret OR intext:key OR intext:token)", subdomain),
				)
			}
		}

		// CORRELATION 4: Subdomain + File Type + Sensitive Keywords
		// Example: Found staging subdomain + SQL files → target for database dumps
		for _, fileType := range discoveryCtx.FileTypes {
			if fileType == "sql" || fileType == "db" || fileType == "dump" || fileType == "backup" {
				subdomainDorks = append(subdomainDorks,
					fmt.Sprintf("site:%s filetype:%s (intext:INSERT OR intext:CREATE TABLE OR intext:password)", subdomain, fileType),
				)
			}
			if fileType == "env" || fileType == "ini" || fileType == "conf" || fileType == "yaml" || fileType == "yml" {
				subdomainDorks = append(subdomainDorks,
					fmt.Sprintf("site:%s filetype:%s (intext:API_KEY OR intext:SECRET OR intext:PASSWORD OR intext:TOKEN)", subdomain, fileType),
				)
			}
		}

		// Remove duplicates for this subdomain
		subdomainDorks = removeDuplicates(subdomainDorks)

		// Limit to maxCorrelation dorks per subdomain
		if len(subdomainDorks) > c.MaxCorrelation {
			subdomainDorks = subdomainDorks[:c.MaxCorrelation]
			console.Logv(c.Verbose, "[SMART-CORRELATION] Limited %s to %d dorks (max-correlation)", subdomain, c.MaxCorrelation)
		}

		// Collect per-subdomain dorks for round-robin execution
		if len(subdomainDorks) > 0 {
			allSubdomainDorks = append(allSubdomainDorks, subdomainDorks)
			console.Logv(c.Verbose, "[SMART-CORRELATION] Generated %d dorks for subdomain: %s", len(subdomainDorks), subdomain)
		}
	}

	// Interleave dorks from all subdomains (round-robin)
	// This saves API quota if user presses Ctrl+C - they see results from multiple subdomains
	var correlatedDorks []string
	maxDorks := 0
	for _, dorks := range allSubdomainDorks {
		if len(dorks) > maxDorks {
			maxDorks = len(dorks)
		}
	}

	// Round-robin: Pick one dork from each subdomain, then repeat
	// Order: aaa.dell.com dork1, abc.dell.com dork1, ccc.dell.com dork1, aaa.dell.com dork2, ...
	for i := 0; i < maxDorks; i++ {
		for _, dorks := range allSubdomainDorks {
			if i < len(dorks) {
				correlatedDorks = append(correlatedDorks, dorks[i])
			}
		}
	}

	if len(correlatedDorks) > 0 {
		console.Logv(c.Verbose, "[SMART-CORRELATION] Generated %d correlated dorks from multi-layer intelligence (round-robin order)", len(correlatedDorks))
	}

	return correlatedDorks
}

// generateAICorrelatedDorks uses AI to generate creative, unique correlated dorks
// This is used when --smart mode is enabled for intelligent dork generation
func (c *Config) generateAICorrelatedDorks(ctx context.Context, discoveryCtx *DiscoveryContext) []string {
	console.Logv(c.Verbose, "[SMART-AI] Generating creative correlated dorks with AI...")

	// Build discovery intelligence summary
	intelSummary := fmt.Sprintf(`DISCOVERED ASSETS:
Subdomains: %s
Paths: %s
File Types: %s
Parameters: %s
Environments: %s
Asset Categories: %s`,
		strings.Join(discoveryCtx.Subdomains, ", "),
		strings.Join(discoveryCtx.Paths, ", "),
		strings.Join(discoveryCtx.FileTypes, ", "),
		strings.Join(discoveryCtx.Parameters, ", "),
		strings.Join(discoveryCtx.Environments, ", "),
		strings.Join(discoveryCtx.AssetCategories, ", "))

	systemPrompt := fmt.Sprintf(`You are an elite Google dorking expert specializing in creative, powerful dork generation.

TARGET: %s

%s

YOUR MISSION:
Generate UNIQUE, CREATIVE, and POWERFUL Google dorks that correlate the discovered assets to find:
1. Critical vulnerabilities (SQLi, XSS, RCE, authentication bypass)
2. Sensitive data exposure (credentials, API keys, PII, database dumps)
3. Misconfigurations (debug modes, exposed admin panels, backup files)
4. Hidden attack surface (forgotten endpoints, staging environments, internal tools)

CRITICAL RULES FOR CREATIVITY:
1. DO NOT generate obvious/generic dorks like "site:domain.com inurl:admin"
2. CORRELATE multiple discoveries together (subdomain + path + filetype + parameter)
3. Think like an attacker - what COMBINATION of patterns reveals secrets?
4. Use discovered patterns to find SIMILAR assets (not just repeat what was found)
5. Generate dorks that find things the target DOESN'T want you to find

CREATIVE DORK STRATEGIES:

Strategy 1: CROSS-LAYER CORRELATION
Combine discoveries from different categories:
- If found: api subdomain + /v1 path + .json filetype + id parameter
  Generate: site:api.%s inurl:/v1/ filetype:json inurl:?id= intext:(password OR token OR key)
- If found: staging environment + admin category + .env file
  Generate: site:staging*.%s (inurl:admin OR inurl:panel) (ext:env OR ext:ini) intext:DATABASE_URL

Strategy 2: PATTERN EXPLOITATION
Use discovered patterns to find MORE of the same:
- If found subdomain: api-prod-us-east.%s
  Discover more: site:*-*-*.%s (pattern matching)
- If found path: /api/v1/users
  Find more versioned APIs: site:%s inurl:/api/ (inurl:v1 OR inurl:v2 OR inurl:v3) (inurl:users OR inurl:admin OR inurl:internal)

Strategy 3: VULNERABILITY-FOCUSED TARGETING
Target specific vulnerability classes based on asset types:
- Admin panels: site:%s inurl:admin (inurl:? OR inurl:&) (inurl:id OR inurl:user OR inurl:page) -login
- API endpoints: site:%s inurl:api (inurl:swagger OR inurl:docs OR inurl:debug) (filetype:json OR filetype:yaml)
- Config files: site:%s (ext:env OR ext:ini OR ext:conf OR ext:yaml) (intext:password OR intext:secret OR intext:api_key OR intext:token)

Strategy 4: ENVIRONMENT EXPLOITATION
If staging/dev/test environments discovered, find secrets they leak:
- site:dev*.%s OR site:test*.%s OR site:staging*.%s (intext:password OR intext:api_key OR intext:token)
- site:dev*.%s (ext:log OR ext:sql OR ext:backup) (intext:error OR intext:exception OR intext:stack)

Strategy 5: PARAMETER ATTACK SURFACE
If parameters discovered (id, user, page, etc.), find SQLi/XSS vectors:
- site:%s inurl:?id= (inurl:& OR inurl:=) -site:www.%s (non-www subdomains more likely vulnerable)
- site:%s inurl:?search= OR inurl:?q= OR inurl:?query= (inurl:admin OR inurl:user)

Strategy 6: FILETYPE + KEYWORD GOLDMINES
Creative combinations of filetypes with sensitive Keywords:
- site:%s (filetype:xls OR filetype:xlsx OR filetype:csv) (intext:password OR intext:email OR intext:ssn OR intext:credit)
- site:%s filetype:sql (intext:INSERT INTO OR intext:CREATE TABLE) (intext:user OR intext:password OR intext:admin)
- site:%s filetype:log intext:(error OR exception OR fatal) intext:(password OR token OR key OR secret)

Strategy 7: BACKUP & ARCHIVE HUNTING
Find forgotten backups and archives with secrets:
- site:%s (inurl:backup OR inurl:bak OR inurl:old OR inurl:archive) (filetype:zip OR filetype:tar OR filetype:sql OR filetype:7z)
- site:%s (ext:bak OR ext:old OR ext:backup OR ext:save OR ext:tmp) (intext:database OR intext:config OR intext:password)

Strategy 8: TECHNOLOGY-SPECIFIC PATTERNS
If you detect technology patterns, exploit framework-specific weaknesses:
- Laravel: site:%s (inurl:storage OR inurl:telescope) OR ext:env intext:APP_KEY
- Django: site:%s inurl:__debug__ OR inurl:admin intext:django
- WordPress: site:%s inurl:wp-json OR inurl:wp-content/debug.log

OUTPUT FORMAT:
Generate %d highly creative, unique Google dorks (one per line).
Each dork MUST:
- Start with site: operator
- Combine 2-3+ discovered asset types
- Target specific vulnerabilities or sensitive data
- Be UNIQUE and CREATIVE (no generic patterns)

Output ONLY the dorks, one per line. NO numbering, NO explanations, NO markdown.`,
		c.Target, intelSummary, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.MaxCorrelation*len(discoveryCtx.Subdomains))

	userPrompt := fmt.Sprintf("Generate %d creative, powerful correlation dorks for %s based on the discovered assets. Think like an elite penetration tester finding hidden vulnerabilities.",
		c.MaxCorrelation*len(discoveryCtx.Subdomains), c.Target)

	// Call gemini-cli
	output, err := c.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		console.Logv(c.Verbose, "[SMART-AI] AI generation failed, falling back to template-based dorks: %v", err)
		return nil // Caller will use template-based fallback
	}

	// Parse dorks from output
	var aiDorks []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Remove numbering if present (1. 2. etc.)
		line = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(line, "")

		// Remove markdown if present
		line = strings.TrimPrefix(line, "- ")
		line = strings.TrimPrefix(line, "* ")

		// Validate dork starts with site:
		if strings.HasPrefix(line, "site:") {
			aiDorks = append(aiDorks, line)
		}
	}

	if len(aiDorks) > 0 {
		console.Logv(c.Verbose, "[SMART-AI] Generated %d creative AI-powered dorks", len(aiDorks))
	}

	return aiDorks
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(strs []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}
	return result
}

// extractPathPatterns extracts interesting path patterns from a URL
func extractPathPatterns(url string) []string {
	var patterns []string

	// Parse URL to get path
	parts := strings.Split(url, "/")
	if len(parts) < 4 {
		return patterns
	}

	// Extract meaningful path segments (skip protocol and domain)
	pathStart := 3 // Skip https:// and domain
	for i := pathStart; i < len(parts)-1; i++ { // -1 to skip filename
		segment := parts[i]
		if segment == "" || len(segment) < 2 {
			continue
		}

		// Skip common noise
		if segment == "index" || segment == "default" || segment == "home" {
			continue
		}

		patterns = append(patterns, segment)
	}

	return patterns
}

// generatePathMutations generates intelligent mutations for a discovered path
func generatePathMutations(target, path string) []string {
	var mutations []string

	// Common path mutation patterns
	mutationRules := map[string][]string{
		"user":     {"users", "user/profile", "user/edit", "user/settings", "user/delete", "userinfo"},
		"admin":    {"administrator", "admin/login", "admin/config", "admin/panel", "admin/dashboard"},
		"api":      {"api/v1", "api/v2", "api/docs", "api/swagger", "api/graphql"},
		"login":    {"signin", "auth", "authenticate", "login.php", "login.asp"},
		"register": {"signup", "registration", "create-account", "register.php"},
		"profile":  {"account", "user/profile", "my-account", "settings"},
		"config":   {"configuration", "settings", "config.php", "config.json", "config.yml"},
		"backup":   {"backups", "backup.sql", "backup.zip", "bak"},
		"upload":   {"uploads", "files", "media", "uploader.php"},
		"download": {"downloads", "files", "get"},
		"search":   {"find", "query", "lookup", "s"},
		"delete":   {"remove", "del", "destroy"},
		"edit":     {"update", "modify", "change"},
		"view":     {"show", "display", "details"},
		"list":     {"index", "all", "browse"},
		"test":     {"testing", "dev", "debug", "staging"},
		"internal": {"private", "restricted", "confidential"},
	}

	// Check if path matches any rule
	lowerPath := strings.ToLower(path)
	for key, variants := range mutationRules {
		if strings.Contains(lowerPath, key) {
			for _, variant := range variants {
				mutations = append(mutations, fmt.Sprintf("site:%s inurl:%s", target, variant))
			}
			// Add plural/singular variations
			if strings.HasSuffix(lowerPath, "s") {
				singular := strings.TrimSuffix(lowerPath, "s")
				mutations = append(mutations, fmt.Sprintf("site:%s inurl:%s", target, singular))
			} else {
				mutations = append(mutations, fmt.Sprintf("site:%s inurl:%ss", target, lowerPath))
			}
			break
		}
	}

	// Generic mutations for any path
	if len(mutations) == 0 {
		mutations = append(mutations,
			fmt.Sprintf("site:%s inurl:%s/admin", target, path),
			fmt.Sprintf("site:%s inurl:%s/config", target, path),
			fmt.Sprintf("site:%s inurl:%s.bak", target, path),
		)
	}

	return mutations
}

// ========== SAVE MODE: Smart Pagination ==========

// shouldStopPagination checks if pagination should stop based on diminishing returns
func shouldStopPagination(previousUnique, currentUnique int, pageNum int) bool {
	// Must have at least 3 pages of data to analyze trend
	if pageNum < 3 {
		return false
	}

	// Stop if last two pages had zero new results
	if currentUnique == 0 && previousUnique == 0 {
		return true
	}

	// Stop if diminishing returns below 10% of first page
	// (This would be tracked across pages in the calling function)
	return false
}

// ========== INCLUDE-DATES: Strategic Date Operators ==========

// CompanyTimeline stores important dates for a company
type CompanyTimeline struct {
	Founded      int
	MajorEvents  []TimelineEvent
}

type TimelineEvent struct {
	Year        int
	Description string
	Type        string // "breach", "founding", "acquisition", etc.
}

// detectCompanyTimeline uses AI to research company timeline
func (c *Config) detectCompanyTimeline(ctx context.Context) *CompanyTimeline {
	if !c.IncludeDates {
		return nil
	}

	// Use AI to research company timeline
	// TODO: Implement with gemini-cli similar to research mode
	// Example prompt:
	// fmt.Sprintf(`Research %s and provide ONLY:
	// 1. Founded year (just the number)
	// 2. Major security incidents/breaches with years
	// 3. Significant changes/acquisitions with years
	//
	// Format as:
	// FOUNDED: YYYY
	// BREACH: YYYY - description
	// ACQUISITION: YYYY - description
	//
	// Keep it brief and factual.`, c.Target)

	// For now, return nil and let it work without dates
	// Users can manually test with years they know
	console.Logv(c.Verbose, "[DATES] Timeline detection requires AI research (implement with --research)")
	return nil
}

// addDateOperators adds strategic date operators to dorks
func addDateOperators(dork string, timeline *CompanyTimeline) string {
	if timeline == nil {
		return dork
	}

	// Add date operators targeting early infrastructure
	if timeline.Founded > 0 {
		earlyYears := fmt.Sprintf(" after:%d before:%d", timeline.Founded, timeline.Founded+3)
		return dork + earlyYears
	}

	return dork
}

// ========== TECH-DETECT: Technology Stack Detection ==========

// DetectedTech stores detected technologies
type DetectedTech struct {
	CMS        string   // WordPress, Drupal, etc.
	Framework  string   // Django, Laravel, Rails, etc.
	Server     string   // Apache, Nginx, IIS
	Language   string   // PHP, Python, Ruby, etc.
	Libraries  []string // jQuery, React, etc.
}

// detectTechStack detects the technology stack of the target
func (c *Config) detectTechStack(ctx context.Context) *DetectedTech {
	if !c.TechDetect {
		return nil
	}

	console.Logv(c.Verbose, "[TECH-DETECT] Analyzing %s...", c.Target)

	tech := &DetectedTech{}

	// Fetch homepage
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allow redirects
		},
	}

	url := "https://" + c.Target
	resp, err := client.Get(url)
	if err != nil {
		// Try http
		url = "http://" + c.Target
		resp, err = client.Get(url)
		if err != nil {
			console.Logv(c.Verbose, "[TECH-DETECT] Failed to fetch %s: %v", c.Target, err)
			return nil
		}
	}
	defer resp.Body.Close()

	// Analyze HTTP headers
	tech.Server = resp.Header.Get("Server")
	xPoweredBy := resp.Header.Get("X-Powered-By")

	if strings.Contains(strings.ToLower(xPoweredBy), "php") {
		tech.Language = "PHP"
	} else if strings.Contains(strings.ToLower(xPoweredBy), "asp.net") {
		tech.Language = "ASP.NET"
		tech.Framework = "ASP.NET"
	}

	// Read body for content analysis
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		console.Logv(c.Verbose, "[TECH-DETECT] Failed to read body: %v", err)
		return tech
	}

	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	// Detect CMS
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wordpress") {
		tech.CMS = "WordPress"
		tech.Language = "PHP"
	} else if strings.Contains(bodyLower, "/drupal") {
		tech.CMS = "Drupal"
		tech.Language = "PHP"
	} else if strings.Contains(bodyLower, "joomla") {
		tech.CMS = "Joomla"
		tech.Language = "PHP"
	}

	// Detect frameworks
	if strings.Contains(bodyLower, "django") || strings.Contains(bodyLower, "csrfmiddlewaretoken") {
		tech.Framework = "Django"
		tech.Language = "Python"
	} else if strings.Contains(bodyLower, "laravel") {
		tech.Framework = "Laravel"
		tech.Language = "PHP"
	} else if strings.Contains(bodyLower, "ruby on rails") || strings.Contains(bodyLower, "csrf-token") && strings.Contains(bodyLower, "rails") {
		tech.Framework = "Rails"
		tech.Language = "Ruby"
	} else if strings.Contains(bodyLower, "next.js") {
		tech.Framework = "Next.js"
		tech.Language = "JavaScript"
	} else if strings.Contains(bodyLower, "react") {
		tech.Libraries = append(tech.Libraries, "React")
	}

	// Log detected tech
	if tech.CMS != "" {
		console.Logv(c.Verbose, "[TECH-DETECT] CMS: %s", tech.CMS)
	}
	if tech.Framework != "" {
		console.Logv(c.Verbose, "[TECH-DETECT] Framework: %s", tech.Framework)
	}
	if tech.Language != "" {
		console.Logv(c.Verbose, "[TECH-DETECT] Language: %s", tech.Language)
	}

	return tech
}

// generateTechSpecificDorks generates dorks based on detected technology
// ENHANCED: Deep vulnerability chains for comprehensive infrastructure fingerprinting
func (c *Config) generateTechSpecificDorks(tech *DetectedTech) []string {
	if tech == nil {
		return nil
	}

	var dorks []string

	// WordPress-specific dorks - DEEP CHAIN
	if tech.CMS == "WordPress" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating WordPress vulnerability chain...")
		dorks = append(dorks,
			// REST API exploitation
			fmt.Sprintf("site:%s inurl:wp-json/wp/v2/users", c.Target),
			fmt.Sprintf("site:%s inurl:wp-json/wp/v2/posts", c.Target),
			fmt.Sprintf("site:%s inurl:wp-json/wp/v2/pages", c.Target),
			fmt.Sprintf("site:%s inurl:wp-json/wp/v2/media", c.Target),

			// Debug & log files
			fmt.Sprintf("site:%s inurl:wp-content/debug.log", c.Target),
			fmt.Sprintf("site:%s inurl:wp-content/uploads (filetype:sql OR filetype:log OR filetype:txt)", c.Target),
			fmt.Sprintf("site:%s inurl:wp-content/backup", c.Target),
			fmt.Sprintf("site:%s inurl:wp-content/backups", c.Target),

			// Configuration & sensitive files
			fmt.Sprintf("site:%s inurl:wp-config.php.bak", c.Target),
			fmt.Sprintf("site:%s inurl:wp-config.php~", c.Target),
			fmt.Sprintf("site:%s inurl:wp-config.php.old", c.Target),
			fmt.Sprintf("site:%s inurl:wp-config.php.save", c.Target),

			// Plugin vulnerabilities
			fmt.Sprintf("site:%s inurl:wp-content/plugins (inurl:readme.txt OR inurl:readme.md)", c.Target),
			fmt.Sprintf("site:%s inurl:wp-content/plugins inurl:upload", c.Target),
			fmt.Sprintf("site:%s inurl:wp-content/plugins inurl:download", c.Target),

			// Theme vulnerabilities
			fmt.Sprintf("site:%s inurl:wp-content/themes (inurl:readme.txt OR filetype:log)", c.Target),

			// Admin & authentication
			fmt.Sprintf("site:%s inurl:wp-admin inurl:install.php", c.Target),
			fmt.Sprintf("site:%s inurl:wp-login.php inurl:redirect_to", c.Target),
			fmt.Sprintf("site:%s inurl:xmlrpc.php", c.Target),

			// Database exports & backups
			fmt.Sprintf("site:%s filetype:sql (intext:wp_users OR intext:wp_posts)", c.Target),
			fmt.Sprintf("site:%s inurl:wp-content (filetype:sql OR filetype:zip OR filetype:tar OR filetype:gz)", c.Target),

			// Exposed installation files
			fmt.Sprintf("site:%s inurl:wp-admin/setup-config.php", c.Target),
			fmt.Sprintf("site:%s inurl:wp-includes", c.Target),
		)
	}

	// Drupal-specific dorks - DEEP CHAIN
	if tech.CMS == "Drupal" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating Drupal vulnerability chain...")
		dorks = append(dorks,
			// Admin access
			fmt.Sprintf("site:%s inurl:/user/login", c.Target),
			fmt.Sprintf("site:%s inurl:/user/register", c.Target),
			fmt.Sprintf("site:%s inurl:/admin", c.Target),
			fmt.Sprintf("site:%s inurl:/admin/config", c.Target),

			// File uploads
			fmt.Sprintf("site:%s inurl:sites/default/files", c.Target),
			fmt.Sprintf("site:%s inurl:sites/all/modules", c.Target),

			// Configuration files
			fmt.Sprintf("site:%s inurl:sites/default/settings.php", c.Target),
			fmt.Sprintf("site:%s inurl:sites/default/settings.php.bak", c.Target),

			// Changelog & version detection
			fmt.Sprintf("site:%s inurl:CHANGELOG.txt", c.Target),
			fmt.Sprintf("site:%s inurl:INSTALL.txt", c.Target),

			// Database backups
			fmt.Sprintf("site:%s inurl:sites/default (filetype:sql OR filetype:dump)", c.Target),
		)
	}

	// Django-specific dorks - DEEP CHAIN
	if tech.Framework == "Django" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating Django vulnerability chain...")
		dorks = append(dorks,
			// Admin panel
			fmt.Sprintf("site:%s inurl:/admin/", c.Target),
			fmt.Sprintf("site:%s inurl:/admin/login/", c.Target),

			// Debug mode exposures
			fmt.Sprintf("site:%s intext:\"DEBUG = True\"", c.Target),
			fmt.Sprintf("site:%s intext:\"DJANGO_SETTINGS_MODULE\"", c.Target),
			fmt.Sprintf("site:%s intext:\"You're seeing this error because you have DEBUG = True\"", c.Target),

			// Static & media files
			fmt.Sprintf("site:%s inurl:/static/ (filetype:py OR filetype:pyc)", c.Target),
			fmt.Sprintf("site:%s inurl:/media/", c.Target),

			// Configuration files
			fmt.Sprintf("site:%s filetype:py (intext:SECRET_KEY OR intext:DATABASE)", c.Target),
			fmt.Sprintf("site:%s inurl:settings.py", c.Target),
			fmt.Sprintf("site:%s inurl:local_settings.py", c.Target),

			// Database files
			fmt.Sprintf("site:%s filetype:sqlite", c.Target),
			fmt.Sprintf("site:%s filetype:db", c.Target),
		)
	}

	// Laravel-specific dorks - DEEP CHAIN
	if tech.Framework == "Laravel" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating Laravel vulnerability chain...")
		dorks = append(dorks,
			// Environment files (critical)
			fmt.Sprintf("site:%s inurl:/.env", c.Target),
			fmt.Sprintf("site:%s inurl:/.env.backup", c.Target),
			fmt.Sprintf("site:%s inurl:/.env.old", c.Target),
			fmt.Sprintf("site:%s inurl:/.env.save", c.Target),
			fmt.Sprintf("site:%s inurl:/.env.example (intext:DB_PASSWORD OR intext:APP_KEY)", c.Target),

			// Debug tools (should be disabled in production)
			fmt.Sprintf("site:%s inurl:/telescope", c.Target),
			fmt.Sprintf("site:%s inurl:/telescope/requests", c.Target),
			fmt.Sprintf("site:%s inurl:/horizon", c.Target),
			fmt.Sprintf("site:%s inurl:/horizon/dashboard", c.Target),
			fmt.Sprintf("site:%s inurl:/_ignition/health-check", c.Target),

			// Storage & logs
			fmt.Sprintf("site:%s inurl:/storage/logs", c.Target),
			fmt.Sprintf("site:%s inurl:/storage/framework", c.Target),
			fmt.Sprintf("site:%s inurl:/storage (filetype:log OR filetype:sql)", c.Target),

			// Public directory exposures
			fmt.Sprintf("site:%s inurl:/public/storage", c.Target),
			fmt.Sprintf("site:%s inurl:/public/uploads", c.Target),

			// Config files
			fmt.Sprintf("site:%s intext:\"APP_KEY\" (intext:base64 OR intext:production)", c.Target),
			fmt.Sprintf("site:%s intext:\"DB_PASSWORD\" (intext:database OR intext:mysql)", c.Target),

			// Vendor exposures
			fmt.Sprintf("site:%s inurl:/vendor", c.Target),
			fmt.Sprintf("site:%s inurl:composer.json", c.Target),
		)
	}

	// Rails-specific dorks - DEEP CHAIN
	if tech.Framework == "Rails" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating Rails vulnerability chain...")
		dorks = append(dorks,
			// Configuration
			fmt.Sprintf("site:%s filetype:rb (intext:secret_key_base OR intext:database)", c.Target),
			fmt.Sprintf("site:%s inurl:config/database.yml", c.Target),
			fmt.Sprintf("site:%s inurl:config/secrets.yml", c.Target),

			// Rails routes & assets
			fmt.Sprintf("site:%s inurl:/rails/info", c.Target),
			fmt.Sprintf("site:%s inurl:/assets/", c.Target),

			// Logs
			fmt.Sprintf("site:%s inurl:log/ (filetype:log OR intext:error)", c.Target),

			// Database
			fmt.Sprintf("site:%s inurl:db/seeds.rb", c.Target),
			fmt.Sprintf("site:%s (filetype:sqlite OR filetype:sqlite3)", c.Target),
		)
	}

	// React/Next.js-specific dorks - DEEP CHAIN
	if tech.Framework == "Next.js" || contains(tech.Libraries, "React") {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating React/Next.js vulnerability chain...")
		dorks = append(dorks,
			// Source maps (expose original source code)
			fmt.Sprintf("site:%s filetype:map", c.Target),
			fmt.Sprintf("site:%s inurl:.js.map", c.Target),

			// Next.js specific paths
			fmt.Sprintf("site:%s inurl:_next/static", c.Target),
			fmt.Sprintf("site:%s inurl:.next/server", c.Target),
			fmt.Sprintf("site:%s inurl:_next/data", c.Target),

			// Build artifacts
			fmt.Sprintf("site:%s inurl:/build/", c.Target),
			fmt.Sprintf("site:%s inurl:/dist/", c.Target),

			// Config files
			fmt.Sprintf("site:%s inurl:next.config.js", c.Target),
			fmt.Sprintf("site:%s inurl:.env.local", c.Target),
			fmt.Sprintf("site:%s inurl:.env.production", c.Target),

			// Package files
			fmt.Sprintf("site:%s inurl:package.json", c.Target),
			fmt.Sprintf("site:%s inurl:package-lock.json", c.Target),
		)
	}

	// ASP.NET-specific dorks - DEEP CHAIN
	if tech.Framework == "ASP.NET" || tech.Language == "ASP.NET" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating ASP.NET vulnerability chain...")
		dorks = append(dorks,
			// Config files
			fmt.Sprintf("site:%s inurl:web.config", c.Target),
			fmt.Sprintf("site:%s inurl:web.config.bak", c.Target),
			fmt.Sprintf("site:%s inurl:app.config", c.Target),

			// Error pages
			fmt.Sprintf("site:%s intext:\"Server Error in '/' Application\"", c.Target),
			fmt.Sprintf("site:%s intext:\"Runtime Error\"", c.Target),

			// Trace & debug
			fmt.Sprintf("site:%s inurl:trace.axd", c.Target),
			fmt.Sprintf("site:%s inurl:elmah.axd", c.Target),

			// Database connections
			fmt.Sprintf("site:%s filetype:config (intext:connectionString OR intext:password)", c.Target),

			// Admin paths
			fmt.Sprintf("site:%s inurl:/admin/ filetype:aspx", c.Target),
		)
	}

	// PHP-specific dorks (if language detected but no specific framework) - DEEP CHAIN
	if tech.Language == "PHP" && tech.Framework == "" && tech.CMS == "" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating PHP vulnerability chain...")
		dorks = append(dorks,
			// Config files
			fmt.Sprintf("site:%s inurl:config.php", c.Target),
			fmt.Sprintf("site:%s inurl:config.php.bak", c.Target),
			fmt.Sprintf("site:%s inurl:configuration.php", c.Target),
			fmt.Sprintf("site:%s inurl:db_config.php", c.Target),
			fmt.Sprintf("site:%s inurl:database.php", c.Target),

			// Info pages
			fmt.Sprintf("site:%s inurl:phpinfo.php", c.Target),
			fmt.Sprintf("site:%s inurl:info.php", c.Target),
			fmt.Sprintf("site:%s intext:\"PHP Version\"", c.Target),

			// Admin panels
			fmt.Sprintf("site:%s inurl:admin.php", c.Target),
			fmt.Sprintf("site:%s inurl:login.php", c.Target),

			// Upload scripts
			fmt.Sprintf("site:%s inurl:upload.php", c.Target),
			fmt.Sprintf("site:%s inurl:uploader.php", c.Target),

			// Database tools
			fmt.Sprintf("site:%s inurl:phpmyadmin", c.Target),
			fmt.Sprintf("site:%s inurl:pma", c.Target),
			fmt.Sprintf("site:%s inurl:adminer.php", c.Target),

			// Backup files
			fmt.Sprintf("site:%s (filetype:php.bak OR filetype:php~ OR filetype:php.old)", c.Target),
		)
	}

	// Python-specific dorks (if not Django)
	if tech.Language == "Python" && tech.Framework != "Django" {
		console.Logv(c.Verbose, "[TECH-DETECT] Generating Python vulnerability chain...")
		dorks = append(dorks,
			// Flask common paths
			fmt.Sprintf("site:%s inurl:/static/", c.Target),
			fmt.Sprintf("site:%s inurl:app.py", c.Target),

			// Config & requirements
			fmt.Sprintf("site:%s inurl:requirements.txt", c.Target),
			fmt.Sprintf("site:%s inurl:config.py", c.Target),

			// Virtual environment exposures
			fmt.Sprintf("site:%s inurl:venv/", c.Target),

			// Python files
			fmt.Sprintf("site:%s filetype:py", c.Target),
		)
	}

	if len(dorks) > 0 {
		console.Logv(c.Verbose, "[TECH-DETECT] Generated %d deep vulnerability chain dorks", len(dorks))
	}

	return dorks
}

// ========== ADAPTIVE: Adaptive Rate Limiting ==========

// ResponseMetrics tracks response metrics for adaptive rate limiting
type ResponseMetrics struct {
	responseTimes []time.Duration
	lastDelay     time.Duration
	slowResponses int
	fastResponses int
}

// trackResponse records response time and adjusts delay
func (c *Config) trackResponse(responseTime time.Duration) {
	if !c.AdaptiveMode {
		return
	}

	// Fast response (< 1s) - can speed up
	if responseTime < time.Second {
		if c.DynamicDelay > 0.5 {
			c.DynamicDelay = c.DynamicDelay * 0.9 // Reduce by 10%
			if c.DynamicDelay < 0.5 {
				c.DynamicDelay = 0.5 // Min 0.5s
			}
			console.Logv(c.Verbose, "[ADAPTIVE] Fast response, reduced delay to %.1fs", c.DynamicDelay)
		}
	}

	// Slow response (> 5s) - slow down
	if responseTime > 5*time.Second {
		c.DynamicDelay = c.DynamicDelay * 1.5 // Increase by 50%
		if c.DynamicDelay > 10 {
			c.DynamicDelay = 10 // Max 10s
		}
		console.Logv(c.Verbose, "[ADAPTIVE] Slow response, increased delay to %.1fs", c.DynamicDelay)
	}
}

// detectCaptcha checks if response contains captcha/block indicators
func detectCaptcha(body string) bool {
	bodyLower := strings.ToLower(body)
	captchaIndicators := []string{
		"recaptcha",
		"captcha",
		"g-recaptcha",
		"unusual traffic",
		"automated queries",
		"bot detection",
		"please verify you are human",
	}

	for _, indicator := range captchaIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}

	return false
}

// ========== DEEP: Recursive Subdomain Discovery ==========

// recursivelyDiscoverSubdomains discovers sub-subdomains up to max depth
func (c *Config) recursivelyDiscoverSubdomains(ctx context.Context, subdomain string, currentDepth, maxDepth int) []string {
	if !c.DeepMode || currentDepth >= maxDepth {
		return nil
	}

	console.Logv(c.Verbose, "[DEEP] Level %d: Searching sub-subdomains of %s", currentDepth+1, subdomain)

	// Generate dork for this subdomain level
	dork := fmt.Sprintf("site:*.%s -www", subdomain)

	// Execute search
	originalDork := c.Dork
	c.Dork = dork
	results := c.dorkRun(ctx, "")
	c.Dork = originalDork

	if len(results) == 0 {
		console.Logv(c.Verbose, "[DEEP] Level %d: No results for %s", currentDepth+1, subdomain)
		return nil
	}

	// Extract discovered subdomains
	var discovered []string
	hostSet := make(map[string]bool)

	for _, url := range results {
		host := hostOf(url)
		if host != "" && !hostSet[host] && host != subdomain {
			hostSet[host] = true
			discovered = append(discovered, host)

			// Recursively search this subdomain
			deeperResults := c.recursivelyDiscoverSubdomains(ctx, host, currentDepth+1, maxDepth)
			discovered = append(discovered, deeperResults...)
		}
	}

	console.Logv(c.Verbose, "[DEEP] Level %d: Found %d subdomains under %s", currentDepth+1, len(discovered), subdomain)

	return discovered
}

// ========== SAVE MODE: Page Tracking ==========

// PageStats tracks statistics per page for save mode
type PageStats struct {
	PageNum      int
	TotalResults int
	UniqueNew    int
	SeenBefore   int
}

// trackPageStats analyzes if pagination should continue
func trackPageStats(stats []PageStats) bool {
	if len(stats) < 3 {
		return true // Need at least 3 pages
	}

	// Get last two pages
	last := stats[len(stats)-1]
	secondLast := stats[len(stats)-2]

	// Stop if last two pages had < 5 unique results combined
	if last.UniqueNew+secondLast.UniqueNew < 5 {
		return false
	}

	// Stop if last two pages had 0 unique
	if last.UniqueNew == 0 && secondLast.UniqueNew == 0 {
		return false
	}

	return true
}

// ========== SCORING: Result Classification & Vulnerability Scoring ==========

// ScoredResult represents a URL with its classification and scoring
type ScoredResult struct {
	URL            string
	Severity       string // CRITICAL, HIGH, MEDIUM, LOW
	VulnType       string // SQLi, XSS, Sensitive File, etc.
	AssetType      string // Admin Panel, API, Config File, etc.
	Justification  string // Why this score was assigned
}

// classifyAndScoreResults uses AI to analyze and score results
func (c *Config) classifyAndScoreResults(ctx context.Context, results []string) ([]ScoredResult, error) {
	if !c.ScoringMode || len(results) == 0 {
		return nil, nil
	}

	console.Logv(c.Verbose, "[SCORING] Analyzing %d results with AI...", len(results))

	// Batch results for efficiency (max 50 per API call to avoid token limits)
	var scoredResults []ScoredResult
	batchSize := 50

	for i := 0; i < len(results); i += batchSize {
		end := i + batchSize
		if end > len(results) {
			end = len(results)
		}
		batch := results[i:end]

		// Create prompt for AI
		urlList := ""
		for idx, url := range batch {
			urlList += fmt.Sprintf("%d. %s\n", idx+1, url)
		}

		systemPrompt := fmt.Sprintf(`You are a security analyst. Classify and score these URLs found during reconnaissance.

For each URL, analyze:
1. Vulnerability Type: SQLi, XSS, Sensitive File, IDOR, Info Disclosure, etc.
2. Severity: CRITICAL, HIGH, MEDIUM, LOW
3. Asset Type: Admin Panel, API Endpoint, Config File, Login Page, etc.

URLs to analyze:
%s

Output format (one line per URL):
[NUMBER]|[SEVERITY]|[VULN_TYPE]|[ASSET_TYPE]|[BRIEF_JUSTIFICATION]

Example:
1|CRITICAL|Sensitive File|Config File|Exposed .env file with credentials
2|HIGH|Admin Panel|Login Page|Admin panel with SQL parameter
3|MEDIUM|Info Disclosure|API Documentation|Swagger docs exposed
4|LOW|Standard Page|Public Page|Normal search functionality

Be concise. Output ONLY the classifications, nothing else.`, urlList)

		userPrompt := "Classify and score these URLs for security testing prioritization."

		// Call gemini-cli
		output, err := c.callGeminiCLI(ctx, systemPrompt, userPrompt)
		if err != nil {
			console.Logv(c.Verbose, "[SCORING] Failed to analyze batch: %v", err)
			continue
		}

		// Parse output
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			parts := strings.Split(line, "|")
			if len(parts) >= 5 {
				// Extract number to match with original URL
				numStr := strings.TrimSpace(parts[0])
				numStr = strings.TrimPrefix(numStr, "[")
				numStr = strings.TrimSuffix(numStr, "]")

				var urlIndex int
				fmt.Sscanf(numStr, "%d", &urlIndex)
				urlIndex-- // Convert to 0-based index

				if urlIndex >= 0 && urlIndex < len(batch) {
					scoredResults = append(scoredResults, ScoredResult{
						URL:           batch[urlIndex],
						Severity:      strings.TrimSpace(parts[1]),
						VulnType:      strings.TrimSpace(parts[2]),
						AssetType:     strings.TrimSpace(parts[3]),
						Justification: strings.TrimSpace(parts[4]),
					})
				}
			}
		}
	}

	console.Logv(c.Verbose, "[SCORING] Classified %d/%d results", len(scoredResults), len(results))
	return scoredResults, nil
}

// displayScoredResults shows results grouped by severity
func (c *Config) displayScoredResults(scored []ScoredResult) {
	if len(scored) == 0 {
		return
	}

	// Group by severity
	critical := []ScoredResult{}
	high := []ScoredResult{}
	medium := []ScoredResult{}
	low := []ScoredResult{}

	for _, result := range scored {
		switch result.Severity {
		case "CRITICAL":
			critical = append(critical, result)
		case "HIGH":
			high = append(high, result)
		case "MEDIUM":
			medium = append(medium, result)
		case "LOW":
			low = append(low, result)
		}
	}

	// Display results
	fmt.Fprintf(os.Stderr, "\n[SCORING] === Prioritized Results ===\n")

	if len(critical) > 0 {
		fmt.Fprintf(os.Stderr, "\n🔴 CRITICAL (%d results):\n", len(critical))
		for _, r := range critical {
			fmt.Fprintf(os.Stderr, "  [%s] %s - %s\n", r.VulnType, r.URL, r.Justification)
		}
	}

	if len(high) > 0 {
		fmt.Fprintf(os.Stderr, "\n🟠 HIGH (%d results):\n", len(high))
		for _, r := range high {
			fmt.Fprintf(os.Stderr, "  [%s] %s - %s\n", r.VulnType, r.URL, r.Justification)
		}
	}

	if len(medium) > 0 {
		fmt.Fprintf(os.Stderr, "\n🟡 MEDIUM (%d results):\n", len(medium))
		for _, r := range medium {
			fmt.Fprintf(os.Stderr, "  [%s] %s - %s\n", r.VulnType, r.URL, r.Justification)
		}
	}

	if len(low) > 0 {
		fmt.Fprintf(os.Stderr, "\n🟢 LOW (%d results):\n", len(low))
		for _, r := range low {
			fmt.Fprintf(os.Stderr, "  [%s] %s - %s\n", r.VulnType, r.URL, r.Justification)
		}
	}
}

// ========== BUDGET: Smart Query Budget Optimization ==========

// DorkPrediction represents success prediction for a dork
type DorkPrediction struct {
	Dork        string
	Probability float64 // 0-100
	Reasoning   string
	ShouldSkip  bool
}

// predictDorkSuccess analyzes dorks and predicts which will yield results
// Uses historical pattern statistics for improved accuracy
func (c *Config) predictDorkSuccess(ctx context.Context, dorks []string) ([]DorkPrediction, error) {
	if !c.BudgetMode || len(dorks) == 0 {
		return nil, nil
	}

	console.Logv(c.Verbose, "[BUDGET] Analyzing %d dorks for success probability...", len(dorks))

	// Build historical context from learning data with pattern statistics
	historicalContext := ""
	patternStats := make(map[string]*core.PatternStats)

	if c.LearnMode && c.Intelligence != nil {
		// Initialize pattern statistics if not exists
		if c.Intelligence.PatternStatistics == nil {
			c.Intelligence.PatternStatistics = make(map[string]*core.PatternStats)
		}
		patternStats = c.Intelligence.PatternStatistics

		// Get top 5 most successful dorks
		topDorks := []string{}
		for i, dork := range c.Intelligence.SuccessfulDorks {
			if i >= 5 {
				break
			}
			topDorks = append(topDorks, fmt.Sprintf("%s (%d results)", dork.Dork, dork.ResultCount))
		}

		// Get high-success patterns
		highSuccessPatterns := []string{}
		for pattern, stats := range patternStats {
			if stats.SuccessRate >= 70 && stats.TimesUsed >= 3 {
				highSuccessPatterns = append(highSuccessPatterns, fmt.Sprintf("%s (%.0f%% success, %d/%d)", pattern, stats.SuccessRate, stats.SuccessCount, stats.TimesUsed))
				if len(highSuccessPatterns) >= 5 {
					break
				}
			}
		}

		// Get low-success patterns
		lowSuccessPatterns := []string{}
		for pattern, stats := range patternStats {
			if stats.SuccessRate < 15 && stats.TimesUsed >= 3 {
				lowSuccessPatterns = append(lowSuccessPatterns, fmt.Sprintf("%s (%.0f%% success, %d/%d)", pattern, stats.SuccessRate, stats.SuccessCount, stats.TimesUsed))
				if len(lowSuccessPatterns) >= 3 {
					break
				}
			}
		}

		historicalContext = fmt.Sprintf(`
Historical intelligence for %s:
- Total scans: %d
- Successful dork patterns: %d
- Top successful dorks: %v
- HIGH SUCCESS PATTERNS (70%%+): %v
- LOW SUCCESS PATTERNS (<15%%): %v

IMPORTANT: Use pattern success rates to inform predictions.
If a dork matches a high-success pattern, increase probability.
If a dork matches a low-success pattern, decrease probability.
`, c.Target, c.Intelligence.TotalScans, len(c.Intelligence.SuccessfulDorks), topDorks, highSuccessPatterns, lowSuccessPatterns)
	}

	// Create dork list
	dorkList := ""
	for idx, dork := range dorks {
		dorkList += fmt.Sprintf("%d. %s\n", idx+1, dork)
	}

	systemPrompt := fmt.Sprintf(`You are a Google dorking expert. Predict the success probability of these dorks for Target: %s

%s

Dorks to analyze:
%s

For each dork, estimate:
1. Success probability (0-100%%)
2. Brief reasoning
3. Whether to skip (SKIP if probability < 15%%)

Consider:
- Dork specificity (too broad = noise, too narrow = no results)
- Redundancy with other dorks
- Target relevance
- Historical patterns if provided

Output format (one line per dork):
[NUMBER]|[PROBABILITY]|[SKIP/EXECUTE]|[REASONING]

Example:
1|85|EXECUTE|Specific admin panel dork with SQL params
2|12|SKIP|Too generic, likely no results for this target size
3|45|EXECUTE|Moderate probability, worth trying
4|8|SKIP|Redundant with dork #1, would waste API call

Be realistic and conservative. Output ONLY the predictions, nothing else.`, c.Target, historicalContext, dorkList)

	userPrompt := "Predict which dorks will yield results and which should be skipped to save API quota."

	// Call gemini-cli
	output, err := c.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to predict dork success: %v", err)
	}

	// Parse predictions
	var predictions []DorkPrediction
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) >= 4 {
			numStr := strings.TrimSpace(parts[0])
			numStr = strings.TrimPrefix(numStr, "[")
			numStr = strings.TrimSuffix(numStr, "]")

			var dorkIndex int
			fmt.Sscanf(numStr, "%d", &dorkIndex)
			dorkIndex-- // Convert to 0-based

			if dorkIndex >= 0 && dorkIndex < len(dorks) {
				var probability float64
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%f", &probability)

				shouldSkip := strings.Contains(strings.ToUpper(parts[2]), "SKIP")

				predictions = append(predictions, DorkPrediction{
					Dork:        dorks[dorkIndex],
					Probability: probability,
					Reasoning:   strings.TrimSpace(parts[3]),
					ShouldSkip:  shouldSkip,
				})
			}
		}
	}

	console.Logv(c.Verbose, "[BUDGET] Analyzed %d/%d dorks", len(predictions), len(dorks))
	return predictions, nil
}

// displayBudgetAnalysis shows budget optimization results
func (c *Config) displayBudgetAnalysis(predictions []DorkPrediction) {
	if len(predictions) == 0 {
		return
	}

	skipCount := 0
	execCount := 0
	totalProbability := 0.0

	for _, p := range predictions {
		if p.ShouldSkip {
			skipCount++
		} else {
			execCount++
			totalProbability += p.Probability
		}
	}

	avgProbability := 0.0
	if execCount > 0 {
		avgProbability = totalProbability / float64(execCount)
	}

	fmt.Fprintf(os.Stderr, "\n[BUDGET] === Query Budget Analysis ===\n")
	fmt.Fprintf(os.Stderr, "[BUDGET] Total dorks: %d\n", len(predictions))
	fmt.Fprintf(os.Stderr, "[BUDGET] Will execute: %d (avg success probability: %.1f%%)\n", execCount, avgProbability)
	fmt.Fprintf(os.Stderr, "[BUDGET] Will skip: %d (low probability, saves API quota)\n\n", skipCount)

	// Show what will be skipped
	if skipCount > 0 && c.Verbose {
		fmt.Fprintf(os.Stderr, "[BUDGET] Skipping:\n")
		for _, p := range predictions {
			if p.ShouldSkip {
				fmt.Fprintf(os.Stderr, "  [%.0f%%] %s - %s\n", p.Probability, p.Dork, p.Reasoning)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Show what will be executed
	fmt.Fprintf(os.Stderr, "[BUDGET] Executing:\n")
	for _, p := range predictions {
		if !p.ShouldSkip {
			fmt.Fprintf(os.Stderr, "  [%.0f%%] %s - %s\n", p.Probability, p.Dork, p.Reasoning)
		}
	}
}

// ========== OPTIMIZE: Dork Evolution & Auto-Optimization ==========

// OptimizedDorks represents analysis and improved dorks
type OptimizedDorks struct {
	OriginalCount  int
	OptimizedCount int
	Improvements   []DorkImprovement
}

// DorkImprovement represents a suggested dork improvement
type DorkImprovement struct {
	Original     string
	Optimized    string
	ChangeType   string // "merge", "mutate", "specialize", "remove_redundant"
	Reasoning    string
	ExpectedGain string // "more specific", "less noise", "broader coverage"
}

// optimizeDorks analyzes successful/failed dorks and generates improvements
func (c *Config) optimizeDorks(ctx context.Context, dorkResults map[string][]string) (*OptimizedDorks, error) {
	if !c.SmartMode || len(dorkResults) == 0 {
		return nil, nil
	}

	console.Logv(c.Verbose, "[SMART] Analyzing %d dorks for optimization...", len(dorkResults))

	// Separate successful and failed dorks
	successful := []string{}
	failed := []string{}

	for dork, results := range dorkResults {
		if len(results) > 0 {
			successful = append(successful, fmt.Sprintf("%s (%d results)", dork, len(results)))
		} else {
			failed = append(failed, dork)
		}
	}

	if len(successful) == 0 {
		console.Logv(c.Verbose, "[SMART] No successful dorks to optimize")
		return nil, nil
	}

	successList := strings.Join(successful, "\n")
	failedList := strings.Join(failed, "\n")

	systemPrompt := fmt.Sprintf(`You are a Google dorking optimization expert. Analyze these dorks and suggest improvements.

TARGET DOMAIN: %s

SUCCESSFUL DORKS (found results):
%s

FAILED DORKS (no results):
%s

Your task:
1. Identify patterns in successful dorks
2. Mutate successful dorks to create better variants
3. Merge similar/redundant dorks
4. Remove or fix failed dorks
5. Suggest new optimized dorks based on what worked

Output format (one improvement per line):
[CHANGE_TYPE]|[ORIGINAL_OR_NEW]|[OPTIMIZED]|[REASONING]|[EXPECTED_GAIN]

Change types: MUTATE, MERGE, SPECIALIZE, REMOVE_REDUNDANT, NEW

Example:
MUTATE|site:*.%s inurl:admin|site:*.%s (inurl:admin OR inurl:dashboard) inurl:?|Added parameter mining to successful admin dork|More SQLi targets
MERGE|site:%s inurl:api + site:%s inurl:v1|site:%s (inurl:api OR inurl:v1)|Merged redundant API dorks|Efficiency
SPECIALIZE|site:%s filetype:pdf|site:%s (filetype:pdf OR filetype:doc) intext:confidential|Made document dork more targeted|Higher value files
NEW||site:*.%s (inurl:swagger OR inurl:openapi) filetype:json|API docs pattern from successful dorks|New API discovery

Generate 5-10 improvements. Output ONLY the improvements, nothing else.`, c.Target, successList, failedList, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target)

	userPrompt := "Optimize these dorks to find more results with less noise."

	// Call gemini-cli
	output, err := c.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to optimize dorks: %v", err)
	}

	// Parse improvements
	var improvements []DorkImprovement
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) >= 5 {
			improvements = append(improvements, DorkImprovement{
				ChangeType:   strings.TrimSpace(parts[0]),
				Original:     strings.TrimSpace(parts[1]),
				Optimized:    strings.TrimSpace(parts[2]),
				Reasoning:    strings.TrimSpace(parts[3]),
				ExpectedGain: strings.TrimSpace(parts[4]),
			})
		}
	}

	result := &OptimizedDorks{
		OriginalCount:  len(dorkResults),
		OptimizedCount: len(improvements),
		Improvements:   improvements,
	}

	console.Logv(c.Verbose, "[SMART] Generated %d optimizations", len(improvements))
	return result, nil
}

// displayOptimizedDorks shows optimization suggestions (only if --suggestions flag is set)
func (c *Config) displayOptimizedDorks(optimized *OptimizedDorks) {
	if optimized == nil || len(optimized.Improvements) == 0 {
		return
	}

	// Only show if --suggestions flag is set
	if !c.ShowSuggestions {
		return
	}

	console.Logv(true, "\n[SMART] === Dork Optimization Suggestions ===")
	console.Logv(true, "[SMART] Analyzed %d original dorks, generated %d improvements\n",
		optimized.OriginalCount, optimized.OptimizedCount)

	// Group by change type
	byType := make(map[string][]DorkImprovement)
	for _, imp := range optimized.Improvements {
		byType[imp.ChangeType] = append(byType[imp.ChangeType], imp)
	}

	// Display each type
	types := []string{"MUTATE", "MERGE", "SPECIALIZE", "NEW", "REMOVE_REDUNDANT"}
	for _, changeType := range types {
		improvements := byType[changeType]
		if len(improvements) == 0 {
			continue
		}

		console.Logv(true, "[%s] (%d suggestions):", changeType, len(improvements))
		for _, imp := range improvements {
			if imp.Original != "" {
				console.Logv(true, "  FROM: %s", imp.Original)
			}
			console.Logv(true, "    TO: %s", imp.Optimized)
			console.Logv(true, "   WHY: %s (%s)\n", imp.Reasoning, imp.ExpectedGain)
		}
	}

	console.Logv(true, "[SMART] Tip: Save these optimized dorks for your next scan!")
}

// generateDorksFromSuccessfulURLs reads ~/.config/banshee/successful.txt and generates
// focused dorks based on patterns found in successful/vulnerable URLs from past scans
func (c *Config) generateDorksFromSuccessfulURLs(ctx context.Context) ([]string, error) {
	// Check if feature is disabled
	if c.SuccessfulURLPatterns == 0 {
		console.Logv(c.Verbose, "[SMART] Successful URL pattern learning disabled (--successful-url-patterns=0)")
		return []string{}, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	successfulPath := filepath.Join(home, ".config", "banshee", "successful.txt")

	// Check if file exists
	if _, err := os.Stat(successfulPath); os.IsNotExist(err) {
		// File doesn't exist, return empty slice (not an error)
		return []string{}, nil
	}

	// Read successful URLs
	content, err := os.ReadFile(successfulPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read successful.txt: %v", err)
	}

	urls := strings.Split(string(content), "\n")
	var validURLs []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !strings.HasPrefix(url, "#") && strings.HasPrefix(url, "http") {
			validURLs = append(validURLs, url)
		}
	}

	if len(validURLs) == 0 {
		console.Logv(c.Verbose, "[SMART] No successful URLs found in successful.txt")
		return []string{}, nil
	}

	console.Logv(c.Verbose, "[SMART] Analyzing %d successful URLs from past scans...", len(validURLs))

	// Step 1: Detect tech stack for current target (if not already done)
	currentTargetTech := c.detectTechnologies(ctx)
	if len(currentTargetTech) == 0 {
		console.Logv(c.Verbose, "[SMART] No tech stack detected for current target, using all successful URLs")
		// Use all URLs without tech matching
		urlList := strings.Join(validURLs, "\n")
		return c.generateDorksFromURLList(ctx, urlList)
	}

	// Step 2: Filter URLs by tech stack similarity
	var matchingURLs []string
	for _, successURL := range validURLs {
		// Check if we've already detected tech for this URL
		cached, exists := c.SuccessfulURLCache[successURL]
		if !exists {
			// Run tech detection for this URL (once only)
			console.Logv(c.Verbose, "[SMART] Running tech detection for: %s", successURL)
			urlTech := c.detectTechnologiesForURL(ctx, successURL)
			if urlTech != nil {
				c.SuccessfulURLCache[successURL] = urlTech
				cached = urlTech
			} else {
				// Skip this URL if tech detection failed
				console.Logv(c.Verbose, "[SMART] Tech detection failed for: %s", successURL)
				continue
			}
		}

		// Compare tech stacks and business focus
		if c.compareTechStacks(currentTargetTech, cached) {
			console.Logv(c.Verbose, "[SMART] ✓ Tech stack match: %s", successURL)
			matchingURLs = append(matchingURLs, successURL)
		} else {
			console.Logv(c.Verbose, "[SMART] ✗ Tech stack mismatch: %s", successURL)
		}
	}

	if len(matchingURLs) == 0 {
		console.Logv(c.Verbose, "[SMART] No matching tech stacks found in successful URLs")
		return []string{}, nil
	}

	console.Logv(c.Verbose, "[SMART] Found %d URLs with matching tech stacks", len(matchingURLs))

	// Prepare AI prompt to analyze URL patterns (only from matching URLs)
	urlList := strings.Join(matchingURLs, "\n")

	systemPrompt := fmt.Sprintf(`You are a Google dorking expert analyzing successful/vulnerable URLs from past security scans.

TARGET: %s

SUCCESSFUL URLs FROM PAST SCANS (with finding context):
%s

Each URL may include context about WHAT was found in format: URL (Finding type: description)
For example:
- https://site.com:8443/login.php (AWS keys: Found AWS_ACCESS_KEY_ID)
- https://site.com/admin/config.php (Sensitive document: Database credentials)
- https://site.com/api/v1/users (Exposed data: User information leaked)

Your task:
1. Identify common URL patterns (paths, filenames, parameters, extensions, ports)
2. Understand WHAT TYPE of sensitive data was found (AWS keys, credentials, API keys, etc.)
3. Learn which patterns expose which types of data
4. Detect technology stack indicators (frameworks, CMSs, APIs)
5. Generate focused Google dorks that would find SIMILAR vulnerabilities on the target domain

CRITICAL RULES:
- Pay attention to WHAT was found, not just WHERE
- If AWS keys were found in /login.php, generate dorks for login/auth pages
- If credentials in config files, target config file patterns
- If API keys in .env files, search for environment files
- Learn from PORTS that worked (8443, 8080, etc.) - use inurl:":8443"
- Learn from FILE PATTERNS that worked (login_up.php, admin.php, config.xml)
- Target the SAME TYPES of findings for new domains
- Use operators: site:, inurl:, filetype:, intitle:, intext:, ext:
- Be CREATIVE - if :8443/login.php had AWS keys, try variations like:
  * inurl:":8443" inurl:"login"
  * inurl:":8443" inurl:"admin"
  * inurl:":8443" filetype:php
  * inurl:"/admin" filetype:php site:%s
  * inurl:"/config" filetype:xml OR filetype:php

PATTERN LEARNING EXAMPLES:
If you see: https://example.com:8443/login_up.php (AWS keys)
Generate dorks like:
- site:%s inurl:":8443" inurl:"login"
- site:%s inurl:":8443" filetype:php
- site:%s inurl:"admin" inurl:":8443"
- site:%s (inurl:"login" OR inurl:"admin") filetype:php

Output format (one dork per line):
site:%s [your focused dork operators here]

Generate %d dorks maximum. Output ONLY the dorks, one per line, nothing else.`, c.Target, urlList, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.SuccessfulURLPatterns)

	userPrompt := fmt.Sprintf("Generate focused dorks for %s based on successful URL patterns", c.Target)

	// Call gemini-cli
	output, err := c.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dorks from successful URLs: %v", err)
	}

	// Parse dorks
	var dorks []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, "site:") {
			dorks = append(dorks, line)
			// Limit to successfulURLPatterns count
			if len(dorks) >= c.SuccessfulURLPatterns {
				break
			}
		}
	}

	if len(dorks) > 0 {
		console.Logv(c.Verbose, "[SMART] Generated %d focused dorks from successful URL patterns (limited to %d)", len(dorks), c.SuccessfulURLPatterns)
	}

	return dorks, nil
}

// callGeminiCLI is a helper to call gemini-cli with system prompt and user prompt
func (c *Config) callGeminiCLI(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	// Use configured timeout (default 150s, configurable via ~/.config/banshee/.config)
	timeout := time.Duration(c.SmartTimeout) * time.Second
	if timeout == 0 {
		timeout = 150 * time.Second // Fallback default
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command arguments - only add --model flag if aiModel is specified
	var args []string
	if c.AiModel != "" {
		args = []string{"--model", c.AiModel, "-p", userPrompt}
	} else {
		args = []string{"-p", userPrompt}
	}

	cmd := exec.CommandContext(ctx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(systemPrompt)

	// Set environment variables - suppress Node.js warnings
	env := os.Environ()
	env = append(env, "NODE_NO_WARNINGS=1")
	cmd.Env = env

	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}

	// Capture stdout only, discard stderr to suppress punycode warnings
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil // Discard stderr

	err := cmd.Run()
	if err != nil {
		// Check if timeout
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("AI optimization timeout after %ds (configurable via ~/.config/banshee/.config: smart-timeout=%d)", c.SmartTimeout, c.SmartTimeout)
		}
		return "", fmt.Errorf("AI error: %v", err)
	}

	return stdout.String(), nil
}

// callGeminiCLIWithLargeData handles large data by passing it via stdin instead of command-line arguments
// This avoids "argument list too long" errors when dealing with large response data
// Includes retry logic with exponential backoff for transient failures
func (c *Config) callGeminiCLIWithLargeData(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	const maxRetries = 3
	const baseDelay = 2 * time.Second

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if c.Verbose {
				fmt.Fprintf(os.Stderr, "[RETRY] Attempt %d/%d after %v delay...\n", attempt+1, maxRetries, delay)
			}
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		result, err := c.callGeminiCLIWithLargeDataOnce(ctx, systemPrompt, userPrompt)
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Don't retry on timeout errors or context cancellation
		if ctx.Err() != nil {
			return "", err
		}

		// Don't retry if it's a clear API key issue
		if strings.Contains(err.Error(), "API key") || strings.Contains(err.Error(), "authentication") {
			return "", err
		}

		if c.Verbose {
			fmt.Fprintf(os.Stderr, "[RETRY] Attempt %d failed: %v\n", attempt+1, err)
		}
	}

	return "", fmt.Errorf("AI call failed after %d attempts: %w", maxRetries, lastErr)
}

// callGeminiCLIWithLargeDataOnce performs a single AI call attempt
func (c *Config) callGeminiCLIWithLargeDataOnce(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	// Use configured timeout (default 150s, configurable via ~/.config/banshee/.config)
	timeout := time.Duration(c.SmartTimeout) * time.Second
	if timeout == 0 {
		timeout = 150 * time.Second // Fallback default
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Combine prompts and pass via stdin to avoid argument length limits
	combinedPrompt := systemPrompt + "\n\n" + userPrompt

	// Build command arguments - only add --model flag if aiModel is specified
	var args []string
	if c.AiModel != "" {
		args = []string{"--model", c.AiModel}
	} else {
		args = []string{}
	}

	cmd := exec.CommandContext(ctx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(combinedPrompt)

	// Set environment variables - suppress Node.js warnings
	env := os.Environ()
	env = append(env, "NODE_NO_WARNINGS=1")
	cmd.Env = env

	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}

	// Capture both stdout and stderr for better debugging
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check if timeout
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("AI optimization timeout after %ds (configurable via ~/.config/banshee/.config: smart-timeout=%d)", c.SmartTimeout, c.SmartTimeout)
		}
		// Include stderr in error message for debugging
		stderrStr := stderr.String()
		if stderrStr != "" {
			return "", fmt.Errorf("AI error: %v | stderr: %s", err, stderrStr)
		}
		return "", fmt.Errorf("AI error: %v", err)
	}

	// Get the result
	result := stdout.String()
	stderrStr := stderr.String()

	// Log stderr warnings for debugging (but don't fail on them unless result is empty)
	if stderrStr != "" {
		// Filter out common harmless Node.js warnings
		isHarmlessWarning := strings.Contains(stderrStr, "punycode") ||
			strings.Contains(stderrStr, "DeprecationWarning") ||
			strings.Contains(stderrStr, "ExperimentalWarning")

		if !isHarmlessWarning {
			// Only fail if result is actually empty
			if result == "" {
				return "", fmt.Errorf("AI returned empty response | stderr: %s", stderrStr)
			}
			// If we have a result, just log the warning and continue
			if c.Verbose {
				// Filter out common non-important messages
			if !strings.Contains(stderrStr, "Loaded cached credentials") {
				fmt.Fprintf(os.Stderr, "[DEBUG] AI stderr (non-fatal): %s\n", strings.TrimSpace(stderrStr))
			}
			}
		}
	}

	return result, nil
}

// ========== WAF-BYPASS: Adversarial Dork Generation ==========

// generateAdversarialDorks creates WAF bypass variations of a dork
func (c *Config) generateAdversarialDorks(originalDork string) []string {
	if !c.WafBypass {
		return nil
	}

	console.Logv(c.Verbose, "[WAF-BYPASS] Generating adversarial variations for: %s", originalDork)

	var adversarialDorks []string

	// Extract the base components
	target := c.Target

	// Parse dork to extract key components
	var inurlPart string

	// Extract inurl component
	if strings.Contains(originalDork, "inurl:") {
		re := regexp.MustCompile(`inurl:([^\s]+)`)
		matches := re.FindStringSubmatch(originalDork)
		if len(matches) > 1 {
			inurlPart = matches[1]
		}
	}

	// VARIATION 1: URL Encoding Obfuscation
	if inurlPart != "" {
		// Encode characters with %XX notation
		encoded := urlEncodeSelective(inurlPart)
		adversarialDorks = append(adversarialDorks,
			fmt.Sprintf("site:%s inurl:%s", target, encoded),
		)
	}

	// VARIATION 2: Case Sensitivity Games
	if inurlPart != "" {
		adversarialDorks = append(adversarialDorks,
			// Mixed case variations
			fmt.Sprintf("site:%s (inurl:%s OR inurl:%s OR inurl:%s)",
				target, strings.ToLower(inurlPart), strings.ToUpper(inurlPart), mixCase(inurlPart)),
		)
	}

	// VARIATION 3: Trailing Slash Variations
	if inurlPart != "" {
		adversarialDorks = append(adversarialDorks,
			fmt.Sprintf("site:%s (inurl:%s OR inurl:%s/ OR inurl:%s//)",
				target, inurlPart, inurlPart, inurlPart),
		)
	}

	// VARIATION 4: Path Traversal Obfuscation
	if inurlPart != "" {
		adversarialDorks = append(adversarialDorks,
			// Add /./ and /../ patterns
			fmt.Sprintf("site:%s inurl:/./%s", target, inurlPart),
			fmt.Sprintf("site:%s inurl:%s/.", target, inurlPart),
		)
	}

	// VARIATION 5: Extension Confusion (for files)
	if inurlPart != "" && (strings.Contains(inurlPart, "config") || strings.Contains(inurlPart, ".php") ||
	   strings.Contains(inurlPart, ".asp") || strings.Contains(inurlPart, ".env")) {
		baseFile := strings.TrimSuffix(inurlPart, filepath.Ext(inurlPart))
		ext := filepath.Ext(inurlPart)
		if ext != "" {
			adversarialDorks = append(adversarialDorks,
				fmt.Sprintf("site:%s (inurl:%s OR inurl:%s.bak OR inurl:%s~ OR inurl:%s.old OR inurl:%s.save)",
					target, inurlPart, inurlPart, inurlPart, inurlPart, inurlPart),
			)
			// Add extension bypass attempts
			adversarialDorks = append(adversarialDorks,
				fmt.Sprintf("site:%s inurl:%s%%00", target, inurlPart), // Null byte
				fmt.Sprintf("site:%s inurl:%s.", target, inurlPart),    // Trailing dot
			)
		}
		if baseFile != "" && ext != "" {
			// Extension variations (.phps, .php.bak, etc.)
			adversarialDorks = append(adversarialDorks,
				fmt.Sprintf("site:%s (inurl:%s%s OR inurl:%ss OR inurl:%s.txt)",
					target, baseFile, ext, baseFile+ext, baseFile+ext),
			)
		}
	}

	// VARIATION 6: Unicode/HTML Entity Obfuscation
	if inurlPart != "" {
		// Replace common characters with unicode equivalents
		unicodeVariant := unicodeObfuscate(inurlPart)
		if unicodeVariant != inurlPart {
			adversarialDorks = append(adversarialDorks,
				fmt.Sprintf("site:%s inurl:%s", target, unicodeVariant),
			)
		}
	}

	// VARIATION 7: Double Encoding
	if inurlPart != "" {
		doubleEncoded := urlEncodeDouble(inurlPart)
		adversarialDorks = append(adversarialDorks,
			fmt.Sprintf("site:%s inurl:%s", target, doubleEncoded),
		)
	}

	// VARIATION 8: Wildcard and Fuzzing
	if inurlPart != "" {
		// Remove last character and use partial match
		if len(inurlPart) > 2 {
			partial := inurlPart[:len(inurlPart)-1]
			adversarialDorks = append(adversarialDorks,
				fmt.Sprintf("site:%s inurl:%s*", target, partial),
			)
		}
	}

	// VARIATION 9: Parameter Pollution (for URLs with params)
	if strings.Contains(originalDork, "inurl:?") || strings.Contains(originalDork, "inurl:&") {
		adversarialDorks = append(adversarialDorks,
			// Add multiple parameter variations
			fmt.Sprintf("site:%s inurl:? inurl:&", target),
			fmt.Sprintf("site:%s inurl:?? inurl:&&", target),
		)
	}

	// VARIATION 10: Comment Injection Patterns
	if inurlPart != "" && (strings.Contains(inurlPart, "admin") || strings.Contains(inurlPart, "login")) {
		adversarialDorks = append(adversarialDorks,
			fmt.Sprintf("site:%s inurl:%s/*", target, inurlPart),
			fmt.Sprintf("site:%s inurl:%s/*/", target, inurlPart),
		)
	}

	console.Logv(c.Verbose, "[WAF-BYPASS] Generated %d adversarial variations", len(adversarialDorks))
	return adversarialDorks
}

// urlEncodeSelective selectively encodes characters in a string
func urlEncodeSelective(s string) string {
	// Encode key characters that might trigger WAFs
	s = strings.ReplaceAll(s, "admin", "adm%69n")
	s = strings.ReplaceAll(s, "config", "conf%69g")
	s = strings.ReplaceAll(s, "login", "log%69n")
	s = strings.ReplaceAll(s, ".", "%2E")
	return s
}

// urlEncodeDouble performs double URL encoding
func urlEncodeDouble(s string) string {
	// First encoding
	encoded := url.QueryEscape(s)
	// Second encoding
	doubleEncoded := url.QueryEscape(encoded)
	return doubleEncoded
}

// mixCase creates a mixed case version of a string
func mixCase(s string) string {
	if len(s) == 0 {
		return s
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i += 2 {
		if unicode.IsLetter(runes[i]) {
			if unicode.IsLower(runes[i]) {
				runes[i] = unicode.ToUpper(runes[i])
			} else {
				runes[i] = unicode.ToLower(runes[i])
			}
		}
	}
	return string(runes)
}

// unicodeObfuscate replaces certain ASCII characters with unicode equivalents
func unicodeObfuscate(s string) string {
	// Replace 'i' with unicode equivalent (Latin Small Letter I)
	s = strings.ReplaceAll(s, "i", "\u0069")
	// Replace 'a' with unicode equivalent
	s = strings.ReplaceAll(s, "a", "\u0061")
	return s
}

// generateWAFBypassDorksForPath generates bypass dorks for a specific path
func (c *Config) generateWAFBypassDorksForPath(path string) []string {
	if !c.WafBypass {
		return nil
	}

	var bypassDorks []string
	target := c.Target

	// Path-specific bypass techniques
	bypassDorks = append(bypassDorks,
		// Case variations
		fmt.Sprintf("site:%s (inurl:%s OR inurl:%s OR inurl:%s)",
			target, path, strings.ToUpper(path), mixCase(path)),

		// Trailing slash variations
		fmt.Sprintf("site:%s (inurl:%s OR inurl:%s/ OR inurl:%s//)",
			target, path, path, path),

		// Path traversal
		fmt.Sprintf("site:%s (inurl:/./%s OR inurl:%s/.)",
			target, path, path),

		// URL encoding
		fmt.Sprintf("site:%s inurl:%s", target, urlEncodeSelective(path)),
	)

	return bypassDorks
}

// generateDorksFromURLList generates dorks from a list of URLs (fallback method without tech matching)
func (c *Config) generateDorksFromURLList(ctx context.Context, urlList string) ([]string, error) {
	systemPrompt := fmt.Sprintf(`You are a Google dorking expert analyzing successful/vulnerable URLs from past security scans.

TARGET: %s

SUCCESSFUL URLs FROM PAST SCANS:
%s

Your task:
1. Identify common patterns in these URLs (paths, filenames, parameters, extensions)
2. Determine the business focus (e-commerce, SaaS, healthcare, finance, etc.)
3. Detect technology stack indicators (frameworks, CMSs, APIs)
4. Generate focused Google dorks that would find similar vulnerabilities/exposures on the target domain

Rules:
- ONLY generate dorks relevant to the target's business/tech stack
- Focus on patterns that appear in multiple successful URLs
- Prioritize high-value targets (admin panels, APIs, configs, sensitive files)
- Use operators: site:, inurl:, filetype:, intitle:, intext:, ext:

Output format (one dork per line):
site:%s [your focused dork operators here]

Generate %d dorks maximum. Output ONLY the dorks, one per line, nothing else.`, c.Target, urlList, c.Target, c.SuccessfulURLPatterns)

	userPrompt := fmt.Sprintf("Generate focused dorks for %s based on successful URL patterns", c.Target)

	// Call gemini-cli
	output, err := c.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dorks from successful URLs: %v", err)
	}

	// Parse dorks
	var dorks []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, "site:") {
			dorks = append(dorks, line)
			// Limit to successfulURLPatterns count
			if len(dorks) >= c.SuccessfulURLPatterns {
				break
			}
		}
	}

	return dorks, nil
}

// detectTechnologiesForURL runs tech detection on a specific URL
func (c *Config) detectTechnologiesForURL(ctx context.Context, targetURL string) *SuccessfulURLInfo {
	// Initialize Wappalyzer
	wappalyzer, err := wappalyzergo.New()
	if err != nil {
		console.Logv(c.Verbose, "[TECH-DETECT] Failed to initialize Wappalyzer: %v", err)
		return nil
	}

	// Fetch the URL
	resp, body, err := c.fetchURLForFingerprinting(targetURL)
	if err != nil {
		console.Logv(c.Verbose, "[TECH-DETECT] Failed to fetch %s: %v", targetURL, err)
		return nil
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// Fingerprint the response
	fingerprints := wappalyzer.Fingerprint(resp.Header, []byte(body))
	fingerprintsWithInfo := wappalyzer.FingerprintWithInfo(resp.Header, []byte(body))

	// Build tech stack map
	techStack := make(map[string]interface{})
	var techList []string
	for technology := range fingerprints {
		info, hasInfo := fingerprintsWithInfo[technology]
		
		// Get category
		category := "Other"
		if hasInfo && len(info.Categories) > 0 {
			category = getCategoryName(info.Categories[0])
		}
		
		techStack[technology] = category
		techList = append(techList, fmt.Sprintf("%s (%s)", technology, category))
	}

	if len(techStack) == 0 {
		return nil
	}

	// Use AI to determine business focus
	businessFocus := c.determineBusinessFocus(ctx, targetURL, techList)

	return &SuccessfulURLInfo{
		URL:          targetURL,
		TechStack:    techStack,
		BusinessFocus: businessFocus,
		ScannedAt:    time.Now(),
	}
}

// determineBusinessFocus uses AI to determine the business focus of a URL
func (c *Config) determineBusinessFocus(ctx context.Context, targetURL string, techList []string) string {
	if len(techList) == 0 {
		return "Unknown"
	}

	techStackStr := strings.Join(techList, ", ")
	
	systemPrompt := fmt.Sprintf(`Analyze this URL and its detected technologies to determine the business focus.

URL: %s
Detected Technologies: %s

Determine the primary business focus in ONE WORD from this list:
- ecommerce (online shopping, retail)
- saas (software as a service, web apps)
- healthcare (medical, health services)
- finance (banking, fintech, payments)
- education (learning, schools, courses)
- media (news, content, entertainment)
- enterprise (business software, B2B)
- government (public sector, gov services)
- social (social media, community)
- other

Output ONLY ONE WORD from the list above, nothing else.`, targetURL, techStackStr)

	output, err := c.callGeminiCLI(ctx, systemPrompt, "Determine business focus")
	if err != nil {
		return "Unknown"
	}

	focus := strings.TrimSpace(strings.ToLower(output))
	// Validate it's one of our expected values
	validFocus := map[string]bool{
		"ecommerce": true, "saas": true, "healthcare": true, "finance": true,
		"education": true, "media": true, "enterprise": true, "government": true,
		"social": true, "other": true,
	}

	if validFocus[focus] {
		return focus
	}

	return "other"
}

// compareTechStacks compares two tech stacks and returns true if they're similar
func (c *Config) compareTechStacks(currentTech []TechDetectionResult, successfulURL *SuccessfulURLInfo) bool {
	if successfulURL == nil || len(currentTech) == 0 {
		return false
	}

	// Build a map of current tech stack for easier comparison
	currentTechMap := make(map[string]string)
	currentCategories := make(map[string]int)
	for _, tech := range currentTech {
		currentTechMap[strings.ToLower(tech.Technology)] = tech.Category
		currentCategories[tech.Category]++
	}

	// Count matching technologies
	matches := 0
	for tech, category := range successfulURL.TechStack {
		techLower := strings.ToLower(tech)
		if _, exists := currentTechMap[techLower]; exists {
			matches++
		} else {
			// Check if the category matches (similar tech stacks)
			if catStr, ok := category.(string); ok {
				if currentCategories[catStr] > 0 {
					matches++
				}
			}
		}
	}

	// Calculate similarity percentage
	totalTech := len(successfulURL.TechStack)
	if totalTech == 0 {
		return false
	}

	similarity := float64(matches) / float64(totalTech)
	
	// Consider it a match if at least 30% of technologies/categories match
	threshold := 0.3
	isMatch := similarity >= threshold

	if isMatch {
		console.Logv(c.Verbose, "[SMART] Tech similarity: %.1f%% (threshold: %.1f%%)", similarity*100, threshold*100)
	}

	return isMatch
}
