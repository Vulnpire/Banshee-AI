package intel

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// getIndustryIntelPath returns the path for industry intelligence file
func getIndustryIntelPath(industry string) string {
	dir := getIntelDir()
	if dir == "" {
		return ""
	}

	// Create hash of industry for filename
	hash := md5.Sum([]byte(industry))
	filename := fmt.Sprintf("industry_%x.json", hash)
	return filepath.Join(dir, filename)
}

// loadIndustryIntelligence loads industry-wide intelligence
func loadIndustryIntelligence(industry string) *core.IndustryIntelligence {
	path := getIndustryIntelPath(industry)
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist, create new
		return &core.IndustryIntelligence{
			Industry:        industry,
			TargetCount:     0,
			CommonPaths:     make(map[string]int),
			CommonTech:      make(map[string]int),
			SuccessPatterns: []core.IndustryPattern{},
			LastUpdated:     time.Now(),
		}
	}

	var intel core.IndustryIntelligence
	if err := json.Unmarshal(data, &intel); err != nil {
		return &core.IndustryIntelligence{
			Industry:        industry,
			TargetCount:     0,
			CommonPaths:     make(map[string]int),
			CommonTech:      make(map[string]int),
			SuccessPatterns: []core.IndustryPattern{},
			LastUpdated:     time.Now(),
		}
	}

	return &intel
}

// saveIndustryIntelligence saves industry intelligence
func saveIndustryIntelligence(intel *core.IndustryIntelligence) error {
	dir := getIntelDir()
	if dir == "" {
		return fmt.Errorf("could not determine intelligence directory")
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create intelligence directory: %w", err)
	}

	path := getIndustryIntelPath(intel.Industry)
	if path == "" {
		return fmt.Errorf("could not determine industry intelligence path")
	}

	intel.LastUpdated = time.Now()

	data, err := json.MarshalIndent(intel, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal industry Intelligence: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write industry intelligence file: %w", err)
	}

	return nil
}

// detectIndustry attempts to detect the industry based on tech stack and patterns
func detectIndustry(intel *core.TargetIntelligence) string {
	if intel == nil {
		return "unknown"
	}

	techStack := make(map[string]bool)
	for _, tech := range intel.TechStack {
		techStack[strings.ToLower(tech)] = true
	}

	paths := make(map[string]bool)
	for _, path := range intel.DiscoveredPaths {
		paths[strings.ToLower(path)] = true
	}

	// SaaS detection
	saasIndicators := []string{"kubernetes", "docker", "healthz", "metrics", "prometheus", "grafana", "api"}
	saasCount := 0
	for _, indicator := range saasIndicators {
		if techStack[indicator] {
			saasCount++
		}
		for path := range paths {
			if strings.Contains(path, indicator) {
				saasCount++
				break
			}
		}
	}
	if saasCount >= 3 {
		return "saas"
	}

	// E-commerce detection
	ecommerceIndicators := []string{"shopify", "magento", "woocommerce", "prestashop", "cart", "checkout", "payment", "products"}
	ecommerceCount := 0
	for _, indicator := range ecommerceIndicators {
		if techStack[indicator] {
			ecommerceCount++
		}
		for path := range paths {
			if strings.Contains(path, indicator) {
				ecommerceCount++
				break
			}
		}
	}
	if ecommerceCount >= 2 {
		return "ecommerce"
	}

	// Finance detection
	financeIndicators := []string{"banking", "finance", "payment", "transaction", "account", "balance"}
	financeCount := 0
	for _, indicator := range financeIndicators {
		for path := range paths {
			if strings.Contains(path, indicator) {
				financeCount++
				break
			}
		}
	}
	if financeCount >= 2 {
		return "finance"
	}

	return "general"
}

// applyIndustryIntelligence generates dorks based on industry patterns
func (c *Config) applyIndustryIntelligence(intel *core.TargetIntelligence) []string {
	if !c.LearnMode || intel == nil {
		return nil
	}

	industry := detectIndustry(intel)
	if industry == "unknown" || industry == "general" {
		return nil
	}

	// Load industry intelligence
	industryIntel := loadIndustryIntelligence(industry)
	if industryIntel == nil || len(industryIntel.SuccessPatterns) == 0 {
		return nil
	}

	var dorks []string

	console.Logv(c.Verbose, "[LEARN-INDUSTRY] Applying %s industry intelligence (%d patterns)", industry, len(industryIntel.SuccessPatterns))

	// Apply industry patterns with high success rates
	for _, pattern := range industryIntel.SuccessPatterns {
		if pattern.SuccessRate >= 50 { // Only apply patterns with >50% success rate
			dorks = append(dorks, fmt.Sprintf("site:%s %s", c.Target, pattern.Pattern))
		}
	}

	// Limit to prevent overwhelming
	if len(dorks) > 10 {
		dorks = dorks[:10]
	}

	if len(dorks) > 0 {
		console.Logv(c.Verbose, "[LEARN-INDUSTRY] Auto-adding %d industry-specific dorks", len(dorks))
	}

	return dorks
}

// updateIndustryIntelligence updates industry patterns based on successful scans
func updateIndustryIntelligence(intel *core.TargetIntelligence, successPatterns []core.SuccessPattern) error {
	if intel == nil || len(successPatterns) == 0 {
		return nil
	}

	industry := detectIndustry(intel)
	if industry == "unknown" || industry == "general" {
		return nil
	}

	// Load industry intelligence
	industryIntel := loadIndustryIntelligence(industry)
	if industryIntel == nil {
		return nil
	}

	// Update target count
	industryIntel.TargetCount++

	// Update common paths
	for _, path := range intel.DiscoveredPaths {
		industryIntel.CommonPaths[path]++
	}

	// Update common tech
	for _, tech := range intel.TechStack {
		industryIntel.CommonTech[tech]++
	}

	// Update success patterns
	for _, pattern := range successPatterns {
		if pattern.SuccessCount > 0 {
			// Find existing pattern
			found := false
			for i, existing := range industryIntel.SuccessPatterns {
				if existing.Pattern == pattern.Pattern {
					industryIntel.SuccessPatterns[i].Frequency++
					// Recalculate success rate
					industryIntel.SuccessPatterns[i].SuccessRate = float64(industryIntel.SuccessPatterns[i].Frequency) / float64(industryIntel.TargetCount) * 100
					found = true
					break
				}
			}

			if !found {
				industryIntel.SuccessPatterns = append(industryIntel.SuccessPatterns, core.IndustryPattern{
					Pattern:     pattern.Pattern,
					Frequency:   1,
					SuccessRate: float64(1) / float64(industryIntel.TargetCount) * 100,
					Description: fmt.Sprintf("Pattern from %s context", pattern.Context),
				})
			}
		}
	}

	// Save updated intelligence
	return saveIndustryIntelligence(industryIntel)
}

// detectCVEs detects known CVEs for discovered technologies using comprehensive database
func detectCVEs(ctx context.Context, c *Config, techStack []string) []core.CVEIntelligence {
	if len(techStack) == 0 {
		return nil
	}

	console.Logv(c.Verbose, "[CVE-DETECT] Scanning %d technologies against comprehensive CVE database...", len(techStack))

	// Use the enhanced CVE detection from cve_database.go
	cveEntries := c.enhancedCVEDetection(ctx)

	// Convert CVEEntry to core.CVEIntelligence format
	var cves []core.CVEIntelligence
	techCVEMap := make(map[string]*core.CVEIntelligence)

	for _, entry := range cveEntries {
		// Group CVEs by technology
		key := entry.Technology
		if existing, ok := techCVEMap[key]; ok {
			existing.CVEList = append(existing.CVEList, entry.CVEID)
			// Update severity to highest
			if entry.Severity == "critical" {
				existing.Severity = "critical"
			}
		} else {
			techCVEMap[key] = &core.CVEIntelligence{
				Technology:  entry.Technology,
				Version:     "", // Will be filled by AI detection
				CVEList:     []string{entry.CVEID},
				Severity:    entry.Severity,
				LastChecked: time.Now(),
			}
		}
	}

	// Convert map to slice
	for _, cve := range techCVEMap {
		cves = append(cves, *cve)
		console.Logv(c.Verbose, "[CVE-DETECT] %s - %d CVEs found (%s severity)", cve.Technology, len(cve.CVEList), cve.Severity)
	}

	return cves
}

// generateCVETargetedDorks generates comprehensive dorks for detected CVEs using the CVE database
func (c *Config) generateCVETargetedDorks(cves []core.CVEIntelligence) []string {
	if len(cves) == 0 {
		return nil
	}

	console.Logv(c.Verbose, "[CVE-DORK] Generating comprehensive CVE-targeted dorks...")

	// Get full CVE entries for these CVEs
	var cveEntries []CVEEntry
	for _, cveIntel := range cves {
		for _, cveID := range cveIntel.CVEList {
			// Find the CVE entry in the database
			for _, entry := range CVEDatabase {
				if entry.CVEID == cveID {
					cveEntries = append(cveEntries, entry)
					break
				}
			}
		}
	}

	// Generate dorks using the comprehensive database
	dorks := c.generateCVEDorks(cveEntries)

	if len(dorks) > 0 {
		console.Logv(c.Verbose, "[CVE-DORK] Generated %d GHDB-based CVE dorks from %d vulnerabilities", len(dorks), len(cveEntries))
	}

	return dorks
}

// applyIndustryVulnerabilityPatterns generates dorks based on industry-specific vulnerability patterns
func (c *Config) applyIndustryVulnerabilityPatterns(intel *core.TargetIntelligence) []string {
	if !c.LearnMode || intel == nil {
		return nil
	}

	// Detect industry
	industry := detectIndustry(intel)
	if industry == "unknown" {
		// Try to detect from domain TLD or other indicators
		if strings.HasSuffix(c.Target, ".gov") {
			industry = "government"
		} else if strings.HasSuffix(c.Target, ".edu") {
			industry = "education"
		}
	}

	if industry == "unknown" {
		console.Logv(c.Verbose, "[INDUSTRY-VULN] Could not determine industry, skipping industry-specific patterns")
		return nil
	}

	console.Logv(c.Verbose, "[INDUSTRY-VULN] Detected industry: %s", industry)

	// Get industry-specific vulnerability patterns
	patterns := getIndustryVulnPatterns(industry)
	if len(patterns) == 0 {
		console.Logv(c.Verbose, "[INDUSTRY-VULN] No patterns found for industry: %s", industry)
		return nil
	}

	console.Logv(c.Verbose, "[INDUSTRY-VULN] Applying %d vulnerability patterns for %s industry", len(patterns), industry)

	// Generate dorks, filtering by false positive rate
	dorks := c.generateIndustryVulnDorks(patterns)

	// Filter out patterns with high false positive rates if not in verbose mode
	if !c.Verbose {
		var filteredDorks []string
		for i, dork := range dorks {
			if i < len(patterns) && patterns[i].FalsePositiveRate < 0.30 {
				filteredDorks = append(filteredDorks, dork)
			}
		}
		dorks = filteredDorks
	}

	if len(dorks) > 0 {
		console.Logv(c.Verbose, "[INDUSTRY-VULN] Generated %d industry-specific vulnerability dorks", len(dorks))
	}

	return dorks
}
