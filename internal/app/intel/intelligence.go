package intel

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

// extractSensitiveTypesFromSummary pulls token types from "Sensitive:" sections of a summary
func extractSensitiveTypesFromSummary(summary string) []string {
	var types []string
	seen := make(map[string]struct{})

	lower := strings.ToLower(summary)
	if idx := strings.Index(lower, "sensitive:"); idx != -1 {
		rest := summary[idx+len("sensitive:"):]
		tokens := strings.Split(rest, ";")
		for _, tok := range tokens {
			tok = strings.TrimSpace(tok)
			tok = strings.Trim(tok, `"'`)
			if tok == "" {
				continue
			}
			if parts := strings.SplitN(tok, ":", 2); len(parts) == 2 {
				tok = strings.TrimSpace(parts[0])
			}
			tok = strings.ToUpper(tok)
			if tok == "" {
				continue
			}
			if _, ok := seen[tok]; ok {
				continue
			}
			seen[tok] = struct{}{}
			types = append(types, tok)
		}
	}

	// Fallback keyword detection if no explicit Sensitive: section
	if len(types) == 0 {
		keywords := []string{"api_key", "client_id", "token", "password", "secret", "aws", "dsn", "jwt", "session", "private key"}
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				upper := strings.ToUpper(strings.ReplaceAll(kw, " ", "_"))
				if _, ok := seen[upper]; !ok {
					seen[upper] = struct{}{}
					types = append(types, upper)
				}
			}
		}
	}

	return types
}

// classifyResponseFinding derives a priority from the summary content
func classifyResponseFinding(summary string) string {
	lower := strings.ToLower(summary)
	types := extractSensitiveTypesFromSummary(summary)

	criticalKeywords := []string{"secret", "password", "token", "key", "aws", "credential", "private key", "dsn", "client_id", "api_key", "session", "jwt"}
	for _, t := range types {
		tLower := strings.ToLower(t)
		for _, kw := range criticalKeywords {
			if strings.Contains(tLower, strings.ReplaceAll(kw, "_", "")) {
				return "critical"
			}
		}
	}

	// If we saw "Sensitive" wording without explicit keywords, treat as high
	if strings.Contains(lower, "sensitive") {
		return "high"
	}

	if strings.Contains(lower, "admin") || strings.Contains(lower, "dashboard") {
		return "high"
	}

	return ""
}

// getIntelDir returns the intelligence storage directory
func getIntelDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "banshee", ".intel")
}

// getIntelPath returns the intelligence file path for a target
func getIntelPath(target string) string {
	dir := getIntelDir()
	if dir == "" {
		return ""
	}

	// Create hash of target for filename
	hash := md5.Sum([]byte(target))
	filename := fmt.Sprintf("%x.json", hash)
	return filepath.Join(dir, filename)
}

// loadTargetIntelligence loads intelligence for a target
func loadTargetIntelligence(target string) *core.TargetIntelligence {
	path := getIntelPath(target)
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist, create new intelligence
		return &core.TargetIntelligence{
			Target:          target,
			FirstSeen:       time.Now(),
			LastUpdated:     time.Now(),
			DorkPatterns:    make(map[string]int),
			CommonPaths:     make(map[string]int),
		}
	}

	var intel core.TargetIntelligence
	if err := json.Unmarshal(data, &intel); err != nil {
		// Invalid file, create new
		return &core.TargetIntelligence{
			Target:          target,
			FirstSeen:       time.Now(),
			LastUpdated:     time.Now(),
			DorkPatterns:    make(map[string]int),
			CommonPaths:     make(map[string]int),
			SubdomainFirstSeen: make(map[string]time.Time),
		}
	}

	// Initialize maps if they're nil (from old JSON format)
	if intel.DorkPatterns == nil {
		intel.DorkPatterns = make(map[string]int)
	}
	if intel.CommonPaths == nil {
		intel.CommonPaths = make(map[string]int)
	}
	if intel.SubdomainFirstSeen == nil {
		intel.SubdomainFirstSeen = make(map[string]time.Time)
	}
	// Backfill legacy entries with the earliest known scan time to avoid falsely marking them as "new"
	backfillTime := intel.FirstSeen
	for _, s := range intel.DiscoveredSubdomains {
		if _, ok := intel.SubdomainFirstSeen[s]; !ok {
			intel.SubdomainFirstSeen[s] = backfillTime
		}
	}

	// Initialize freshness tracking if not present
	if intel.DataFreshness == nil {
		intel.DataFreshness = initializeIntelligenceFreshness()
	}

	// Initialize validation metrics if not present
	if intel.ValidationMetrics == nil {
		intel.ValidationMetrics = initializeValidationMetrics()
	}

	// Initialize pattern statistics map if nil
	if intel.PatternStatistics == nil {
		intel.PatternStatistics = make(map[string]*core.PatternStats)
	}

	// Run cleanup for expired intelligence
	cleaned := core.CleanupExpiredIntelligence(&intel)
	if cleaned > 0 {
		console.Logv(false, "[Intelligence] Cleaned up %d expired entries for %s", cleaned, target)
	}

	return &intel
}

// saveTargetIntelligence saves intelligence to disk
func saveTargetIntelligence(intel *core.TargetIntelligence) error {
	dir := getIntelDir()
	if dir == "" {
		return fmt.Errorf("could not determine intelligence directory")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create intelligence directory: %w", err)
	}

	path := getIntelPath(intel.Target)
	if path == "" {
		return fmt.Errorf("could not determine intelligence path")
	}

	intel.LastUpdated = time.Now()
	intel.TotalScans++

	data, err := json.MarshalIndent(intel, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Intelligence: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write intelligence file: %w", err)
	}

	return nil
}

// updateIntelligenceWithResults updates intelligence after a scan
func updateIntelligenceWithResults(intel *core.TargetIntelligence, dorks []string, results map[string][]string) {
	if intel == nil {
		return
	}

	now := time.Now()
	intel.Statistics.TotalResults = 0

	for _, dork := range dorks {
		urls := results[dork]
		resultCount := len(urls)

		intel.Statistics.TotalResults += resultCount

		// Update dork intelligence
		found := false
		for i := range intel.SuccessfulDorks {
			if intel.SuccessfulDorks[i].Dork == dork {
				intel.SuccessfulDorks[i].TimesUsed++
				intel.SuccessfulDorks[i].ResultCount += resultCount
				intel.SuccessfulDorks[i].LastUsed = now
				intel.SuccessfulDorks[i].SuccessRate = float64(intel.SuccessfulDorks[i].ResultCount) / float64(intel.SuccessfulDorks[i].TimesUsed)
				found = true
				break
			}
		}

		if !found {
			category := categorizeDork(dork)
			pattern := extractDorkPattern(dork)

			if resultCount > 0 {
				intel.SuccessfulDorks = append(intel.SuccessfulDorks, core.DorkIntelligence{
					Dork:        dork,
					ResultCount: resultCount,
					TimesUsed:   1,
					LastUsed:    now,
					Category:    category,
					Pattern:     pattern,
					SuccessRate: float64(resultCount),
				})

				// Track pattern
				intel.DorkPatterns[pattern]++
			} else {
				intel.FailedDorks = append(intel.FailedDorks, dork)
			}
		}

		// Extract intelligence from URLs
		for _, url := range urls {
			extractIntelligenceFromURL(intel, url)
		}
	}

	// Calculate statistics
	if len(intel.SuccessfulDorks) > 0 {
		intel.Statistics.AverageResultsPerDork = float64(intel.Statistics.TotalResults) / float64(len(intel.SuccessfulDorks))

		// Find best category
		categoryCount := make(map[string]int)
		for _, d := range intel.SuccessfulDorks {
			categoryCount[d.Category] += d.ResultCount
		}

		maxCount := 0
		for cat, count := range categoryCount {
			if count > maxCount {
				maxCount = count
				intel.Statistics.BestDorkCategory = cat
			}
		}
	}

	intel.Statistics.TotalSubdomains = len(intel.DiscoveredSubdomains)
	intel.Statistics.TotalEndpoints = len(intel.APIEndpoints)
	intel.Statistics.MostProductiveHour = now.Hour()
}

// extractIntelligenceFromURL extracts intelligence from a URL
func extractIntelligenceFromURL(intel *core.TargetIntelligence, url string) {
	// Extract subdomain
	subdomain := extractSubdomain(url, intel.Target)
	if subdomain != "" && !contains(intel.DiscoveredSubdomains, subdomain) {
		intel.DiscoveredSubdomains = append(intel.DiscoveredSubdomains, subdomain)
		if intel.SubdomainFirstSeen == nil {
			intel.SubdomainFirstSeen = make(map[string]time.Time)
		}
		if _, ok := intel.SubdomainFirstSeen[subdomain]; !ok {
			intel.SubdomainFirstSeen[subdomain] = time.Now()
		}
	}

	// Extract path
	path := extractPath(url)
	if path != "" {
		intel.CommonPaths[path]++
		if !contains(intel.DiscoveredPaths, path) {
			intel.DiscoveredPaths = append(intel.DiscoveredPaths, path)
		}
	}

	// Extract file extension
	ext := extractExtension(url)
	if ext != "" && !contains(intel.DiscoveredFileTypes, ext) {
		intel.DiscoveredFileTypes = append(intel.DiscoveredFileTypes, ext)
	}

	// Detect API endpoints
	if isAPIEndpoint(url) && !contains(intel.APIEndpoints, url) {
		intel.APIEndpoints = append(intel.APIEndpoints, url)
	}

	// Detect cloud assets
	if isCloudAsset(url) && !contains(intel.CloudAssets, url) {
		intel.CloudAssets = append(intel.CloudAssets, url)
	}
}

// categorizeDork categorizes a dork by type
func categorizeDork(dork string) string {
	dorkLower := strings.ToLower(dork)

	if strings.Contains(dorkLower, "admin") || strings.Contains(dorkLower, "login") {
		return "admin"
	}
	if strings.Contains(dorkLower, "api") || strings.Contains(dorkLower, "endpoint") {
		return "api"
	}
	if strings.Contains(dorkLower, "config") || strings.Contains(dorkLower, ".env") {
		return "config"
	}
	if strings.Contains(dorkLower, "backup") || strings.Contains(dorkLower, ".bak") {
		return "backup"
	}
	if strings.Contains(dorkLower, "sql") || strings.Contains(dorkLower, "injection") {
		return "vuln"
	}
	if strings.Contains(dorkLower, "s3") || strings.Contains(dorkLower, "bucket") || strings.Contains(dorkLower, "storage") {
		return "cloud"
	}
	if strings.Contains(dorkLower, "secret") || strings.Contains(dorkLower, "key") || strings.Contains(dorkLower, "token") {
		return "secrets"
	}

	return "general"
}

// extractDorkPattern extracts the primary pattern from a dork
func extractDorkPattern(dork string) string {
	dorkLower := strings.ToLower(dork)

	patterns := []string{"inurl:", "filetype:", "intitle:", "intext:", "ext:", "site:"}
	foundPatterns := []string{}

	for _, pattern := range patterns {
		if strings.Contains(dorkLower, pattern) {
			foundPatterns = append(foundPatterns, strings.TrimSuffix(pattern, ":"))
		}
	}

	if len(foundPatterns) == 0 {
		return "general"
	}
	if len(foundPatterns) == 1 {
		return foundPatterns[0]
	}
	return "mixed"
}

// extractSubdomain extracts subdomain from URL
func extractSubdomain(url, target string) string {
	re := regexp.MustCompile(`https?://([^/]+)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) < 2 {
		return ""
	}

	host := matches[1]
	if !strings.Contains(host, target) {
		return ""
	}

	// Remove port if present
	host = strings.Split(host, ":")[0]

	// If it's not the main domain, it's a subdomain
	if host != target && strings.HasSuffix(host, "."+target) {
		return host
	}

	return ""
}

// extractPath extracts path from URL
func extractPath(url string) string {
	re := regexp.MustCompile(`https?://[^/]+(/[^?#]*)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) < 2 {
		return ""
	}

	path := matches[1]

	// Remove file name, keep directory
	parts := strings.Split(path, "/")
	if len(parts) > 1 {
		// Keep first 3 path segments
		if len(parts) > 4 {
			parts = parts[:4]
		}
		return strings.Join(parts, "/")
	}

	return path
}

// extractExtension extracts file extension from URL
func extractExtension(url string) string {
	re := regexp.MustCompile(`\.([a-zA-Z0-9]{2,5})(?:[?#]|$)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// isAPIEndpoint checks if URL is likely an API endpoint
func isAPIEndpoint(url string) bool {
	urlLower := strings.ToLower(url)
	return strings.Contains(urlLower, "/api/") ||
		strings.Contains(urlLower, "/v1/") ||
		strings.Contains(urlLower, "/v2/") ||
		strings.Contains(urlLower, "/rest/") ||
		strings.Contains(urlLower, "/graphql") ||
		strings.Contains(urlLower, ".json") ||
		strings.Contains(urlLower, ".xml")
}

// isCloudAsset checks if URL is a cloud asset
func isCloudAsset(url string) bool {
	urlLower := strings.ToLower(url)
	return strings.Contains(urlLower, "s3.amazonaws.com") ||
		strings.Contains(urlLower, "storage.googleapis.com") ||
		strings.Contains(urlLower, "blob.core.windows.net") ||
		strings.Contains(urlLower, "digitaloceanspaces.com") ||
		strings.Contains(urlLower, "cloudfront.net")
}

// generateLearnedPrompt generates an AI prompt based on learned intelligence
func generateLearnedPrompt(intel *core.TargetIntelligence, basePrompt string, category string) string {
	if intel == nil || intel.TotalScans == 0 {
		return basePrompt
	}

	var context strings.Builder
	context.WriteString(fmt.Sprintf("TARGET INTELLIGENCE (from %d previous scans):\n\n", intel.TotalScans))

	// Top performing dorks
	if len(intel.SuccessfulDorks) > 0 {
		context.WriteString("TOP PERFORMING DORKS:\n")

		// Sort by result count
		sorted := make([]core.DorkIntelligence, len(intel.SuccessfulDorks))
		copy(sorted, intel.SuccessfulDorks)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].ResultCount > sorted[j].ResultCount
		})

		// Show top 10
		limit := 10
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for i := 0; i < limit; i++ {
			d := sorted[i]
			context.WriteString(fmt.Sprintf("  • %s (%d results, %.1f%% success rate, category: %s)\n",
				d.Dork, d.ResultCount, d.SuccessRate, d.Category))
		}
		context.WriteString("\n")
	}

	// Discovered assets
	if len(intel.DiscoveredSubdomains) > 0 {
		context.WriteString(fmt.Sprintf("DISCOVERED SUBDOMAINS (%d total):\n", len(intel.DiscoveredSubdomains)))
		limit := 15
		if len(intel.DiscoveredSubdomains) < limit {
			limit = len(intel.DiscoveredSubdomains)
		}
		for i := 0; i < limit; i++ {
			context.WriteString(fmt.Sprintf("  • %s\n", intel.DiscoveredSubdomains[i]))
		}
		if len(intel.DiscoveredSubdomains) > limit {
			context.WriteString(fmt.Sprintf("  ... and %d more\n", len(intel.DiscoveredSubdomains)-limit))
		}
		context.WriteString("\n")
	}

	// Common paths
	if len(intel.CommonPaths) > 0 {
		context.WriteString("COMMON PATHS (by frequency):\n")

		// Sort by frequency
		type pathFreq struct {
			path string
			freq int
		}
		var paths []pathFreq
		for path, freq := range intel.CommonPaths {
			paths = append(paths, pathFreq{path, freq})
		}
		sort.Slice(paths, func(i, j int) bool {
			return paths[i].freq > paths[j].freq
		})

		limit := 10
		if len(paths) < limit {
			limit = len(paths)
		}
		for i := 0; i < limit; i++ {
			context.WriteString(fmt.Sprintf("  • %s (found %d times)\n", paths[i].path, paths[i].freq))
		}
		context.WriteString("\n")
	}

	// File types
	if len(intel.DiscoveredFileTypes) > 0 {
		context.WriteString(fmt.Sprintf("DISCOVERED FILE TYPES: %s\n\n", strings.Join(intel.DiscoveredFileTypes, ", ")))
	}

	// Tech stack
	if len(intel.TechStack) > 0 {
		context.WriteString(fmt.Sprintf("KNOWN TECH STACK: %s\n\n", strings.Join(intel.TechStack, ", ")))
	}

	// Best patterns
	if len(intel.DorkPatterns) > 0 {
		context.WriteString("MOST SUCCESSFUL DORK PATTERNS:\n")

		// Sort by success count
		type patternCount struct {
			pattern string
			count   int
		}
		var patterns []patternCount
		for pattern, count := range intel.DorkPatterns {
			patterns = append(patterns, patternCount{pattern, count})
		}
		sort.Slice(patterns, func(i, j int) bool {
			return patterns[i].count > patterns[j].count
		})

		for i := 0; i < len(patterns) && i < 5; i++ {
			context.WriteString(fmt.Sprintf("  • %s (%d successful dorks)\n", patterns[i].pattern, patterns[i].count))
		}
		context.WriteString("\n")
	}

	// Statistics
	if intel.Statistics.BestDorkCategory != "" {
		context.WriteString(fmt.Sprintf("STATISTICS:\n"))
		context.WriteString(fmt.Sprintf("  • Total results: %d\n", intel.Statistics.TotalResults))
		context.WriteString(fmt.Sprintf("  • Average results per Dork: %.1f\n", intel.Statistics.AverageResultsPerDork))
		context.WriteString(fmt.Sprintf("  • Best category: %s\n", intel.Statistics.BestDorkCategory))
		context.WriteString("\n")
	}

	context.WriteString("TASK:\n")
	context.WriteString(fmt.Sprintf("Based on this intelligence, %s\n", basePrompt))
	context.WriteString("\nIMPORTANT - CONTINUOUS LEARNING RULES:\n")
	context.WriteString("- DO NOT reuse the exact same dorks shown above\n")
	context.WriteString("- Generate COMPLETELY NEW dorks inspired by successful patterns\n")
	context.WriteString("- Use successful patterns (inurl, filetype, etc.) to create better variations\n")
	context.WriteString("- Target discovered subdomains and paths with new dork combinations\n")
	context.WriteString("- Apply learned file types and categories to new searches\n")
	context.WriteString("- Avoid patterns that failed in the past\n")
	context.WriteString("- Goal: Each scan generates BETTER dorks, not duplicate ones\n")

	return context.String()
}

// contains checks if string slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// getLinguisticIntelPath returns the linguistic intelligence file path for a target
func getLinguisticIntelPath(target string) string {
	dir := getIntelDir()
	if dir == "" {
		return ""
	}

	// Create hash of target for filename
	hash := md5.Sum([]byte(target))
	filename := fmt.Sprintf("ling_%x.json", hash)
	return filepath.Join(dir, filename)
}

// saveLinguisticIntelligence saves linguistic intelligence to disk
func saveLinguisticIntelligence(target string, intel *core.LinguisticIntelligence) error {
	dir := getIntelDir()
	if dir == "" {
		return fmt.Errorf("could not determine intelligence directory")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create intelligence directory: %w", err)
	}

	path := getLinguisticIntelPath(target)
	if path == "" {
		return fmt.Errorf("could not determine linguistic intelligence path")
	}

	data, err := json.MarshalIndent(intel, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal linguistic Intelligence: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write linguistic intelligence file: %w", err)
	}

	return nil
}

// loadLinguisticIntelligence loads linguistic intelligence for a target
func loadLinguisticIntelligence(target string) *core.LinguisticIntelligence {
	path := getLinguisticIntelPath(target)
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist
		return nil
	}

	var intel core.LinguisticIntelligence
	if err := json.Unmarshal(data, &intel); err != nil {
		// Invalid file
		return nil
	}

	// Initialize maps if they're nil
	if intel.InternalTerms == nil {
		intel.InternalTerms = make(map[string]string)
	}

	return &intel
}

// updatePatternStatistics updates pattern success statistics
func updatePatternStatistics(intel *core.TargetIntelligence, dork string, success bool, resultCount int) {
	if intel == nil {
		return
	}

	// Initialize if needed
	if intel.PatternStatistics == nil {
		intel.PatternStatistics = make(map[string]*core.PatternStats)
	}

	// Extract pattern from dork
	pattern := extractDorkPattern(dork)
	if pattern == "" {
		return
	}

	// Update or create pattern statistics
	stats, exists := intel.PatternStatistics[pattern]
	if !exists {
		stats = &core.PatternStats{
			Pattern:      pattern,
			TimesUsed:    0,
			SuccessCount: 0,
			SuccessRate:  0,
			TotalResults: 0,
			AvgResults:   0,
			FirstUsed:    time.Now(),
		}
		intel.PatternStatistics[pattern] = stats
	}

	stats.TimesUsed++

	if success {
		stats.SuccessCount++
		stats.TotalResults += resultCount
		stats.LastSuccess = time.Now()
	}

	// Recalculate success rate and average results
	stats.SuccessRate = (float64(stats.SuccessCount) / float64(stats.TimesUsed)) * 100
	if stats.SuccessCount > 0 {
		stats.AvgResults = float64(stats.TotalResults) / float64(stats.SuccessCount)
	}
}

// initializeIntelligenceFreshness creates default freshness tracking
func initializeIntelligenceFreshness() *core.IntelligenceFreshness {
	now := time.Now()
	return &core.IntelligenceFreshness{
		SubdomainsUpdated: now,
		TechStackUpdated:  now,
		DorksUpdated:      now,
		PatternsUpdated:   now,
		SubdomainsTTL:     30,  // 30 days
		TechStackTTL:      90,  // 90 days
		DorksTTL:          60,  // 60 days
		PatternsTTL:       180, // 180 days
	}
}

// initializeValidationMetrics creates default validation metrics
func initializeValidationMetrics() *core.ValidationMetrics {
	return &core.ValidationMetrics{
		TotalPatterns:     0,
		ValidatedPatterns: 0,
		HighConfidence:    0,
		LowConfidence:     0,
		PrunedPatterns:    0,
		LastValidation:    time.Now(),
		PatternConfidence: make(map[string]float64),
	}
}

// validateDorkSyntax checks if a dork has valid Google/Brave search syntax
func validateDorkSyntax(dork string) (bool, string) {
	// Valid operators for Google/Brave
	validOperators := []string{
		"site:", "inurl:", "intext:", "intitle:", "filetype:", "ext:",
		"cache:", "link:", "related:", "info:", "define:", "stocks:",
		"map:", "movie:", "weather:", "OR", "AND", "-", "*", "..", "\"",
	}
	
	// Check for basic syntax errors
	if strings.TrimSpace(dork) == "" {
		return false, "empty dork"
	}
	
	// Check for unmatched quotes
	quoteCount := strings.Count(dork, "\"")
	if quoteCount%2 != 0 {
		return false, "unmatched quotes"
	}
	
	// Check for unmatched parentheses
	openParen := strings.Count(dork, "(")
	closeParen := strings.Count(dork, ")")
	if openParen != closeParen {
		return false, "unmatched parentheses"
	}
	
	// Check if dork uses at least one valid operator or is a simple search
	hasValidOperator := false
	for _, op := range validOperators {
		if strings.Contains(dork, op) {
			hasValidOperator = true
			break
		}
	}
	
	// If no operators, it's a simple search query (also valid)
	if !hasValidOperator {
		// Simple queries are valid, but should have some content
		if len(strings.TrimSpace(dork)) < 3 {
			return false, "dork too short"
		}
	}
	
	return true, "valid"
}

// calculateDorkQualityScore rates a dork's expected effectiveness 0-100
func calculateDorkQualityScore(dork string) float64 {
	score := 50.0 // Start at 50
	
	// Bonus for using multiple operators (more specific)
	operators := []string{"site:", "inurl:", "intext:", "intitle:", "filetype:", "ext:"}
	operatorCount := 0
	for _, op := range operators {
		if strings.Contains(dork, op) {
			operatorCount++
		}
	}
	score += float64(operatorCount) * 10.0
	if operatorCount > 3 {
		score += 10.0 // Bonus for very specific dorks
	}
	
	// Bonus for using quotes (exact match)
	if strings.Contains(dork, "\"") {
		score += 5.0
	}
	
	// Bonus for using OR (broader coverage)
	if strings.Contains(dork, " OR ") {
		score += 5.0
	}
	
	// Penalty for very long dorks (may be too specific)
	if len(dork) > 200 {
		score -= 10.0
	}
	
	// Penalty for very short dorks (too broad)
	if len(dork) < 10 {
		score -= 15.0
	}
	
	// Penalty for having too many nested parentheses
	parenDepth := 0
	maxDepth := 0
	for _, ch := range dork {
		if ch == '(' {
			parenDepth++
			if parenDepth > maxDepth {
				maxDepth = parenDepth
			}
		} else if ch == ')' {
			parenDepth--
		}
	}
	if maxDepth > 3 {
		score -= 10.0
	}
	
	// Clamp score between 0 and 100
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	
	return score
}
