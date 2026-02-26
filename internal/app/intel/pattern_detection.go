package intel

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// detectNamingConventions analyzes subdomains and emails to detect naming patterns
func detectNamingConventions(subdomains []string, emails []string) *core.NamingConventions {
	nc := &core.NamingConventions{
		Environments: []string{},
		Services:     []string{},
		Regions:      []string{},
		Confidence:   0,
	}

	if len(subdomains) < 3 {
		// Not enough data to detect patterns
		return nc
	}

	// Analyze subdomains for patterns
	envs := make(map[string]bool)
	services := make(map[string]bool)
	regions := make(map[string]bool)

	// Common environment names
	envPatterns := []string{"prod", "production", "dev", "develop", "development", "stage", "staging", "test", "testing", "qa", "uat", "demo"}
	// Common service names
	servicePatterns := []string{"api", "admin", "app", "web", "www", "mail", "smtp", "db", "database", "cache", "cdn", "auth", "login", "dashboard", "portal"}
	// Common region patterns
	regionPatterns := []string{"us-east", "us-west", "eu-west", "eu-central", "ap-south", "ap-northeast", "ca-central"}

	// Check for dash-separated patterns: {env}-{service}-{region}
	dashPattern := 0
	for _, sub := range subdomains {
		parts := strings.Split(sub, ".")
		if len(parts) > 0 {
			subdomain := parts[0]
			segments := strings.Split(subdomain, "-")

			if len(segments) >= 2 {
				dashPattern++
				// Check for environment
				for _, env := range envPatterns {
					if strings.Contains(strings.ToLower(subdomain), env) {
						envs[env] = true
					}
				}
				// Check for service
				for _, svc := range servicePatterns {
					if strings.Contains(strings.ToLower(subdomain), svc) {
						services[svc] = true
					}
				}
				// Check for region
				for _, reg := range regionPatterns {
					if strings.Contains(strings.ToLower(subdomain), reg) {
						regions[reg] = true
					}
				}
			}
		}
	}

	// Build detected lists
	for env := range envs {
		nc.Environments = append(nc.Environments, env)
	}
	for svc := range services {
		nc.Services = append(nc.Services, svc)
	}
	for reg := range regions {
		nc.Regions = append(nc.Regions, reg)
	}

	// Calculate confidence
	if dashPattern >= len(subdomains)/2 {
		nc.SubdomainPattern = "{component}-{component}-{component}.{domain}"
		nc.SubdomainExample = subdomains[:min(5, len(subdomains))]
		nc.Confidence = float64(dashPattern) / float64(len(subdomains)) * 100
	}

	// Analyze emails for patterns
	if len(emails) >= 2 {
		// Check for first.last@domain pattern
		firstLastCount := 0
		for _, email := range emails {
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				local := parts[0]
				if strings.Contains(local, ".") {
					firstLastCount++
				}
			}
		}

		if firstLastCount >= len(emails)/2 {
			nc.EmailPattern = "{first}.{last}@{domain}"
			nc.EmailExample = emails[:min(3, len(emails))]
		}
	}

	return nc
}

// generatePatternBasedDorks generates dorks based on detected naming patterns
func (c *Config) generatePatternBasedDorks(nc *core.NamingConventions) []string {
	if nc == nil || nc.Confidence < 30 {
		return nil
	}

	var dorks []string

	// Generate environment-based dorks
	if len(nc.Environments) > 0 {
		// Try other common environments not yet seen
		targetEnvs := []string{"dev", "development", "test", "testing", "qa", "uat", "demo", "sandbox", "stage", "staging"}
		for _, env := range targetEnvs {
			found := false
			for _, known := range nc.Environments {
				if env == known {
					found = true
					break
				}
			}
			if !found {
				// Generate dorks for unseen environments
				dorks = append(dorks,
					fmt.Sprintf("site:%s-*.%s", env, c.Target),
					fmt.Sprintf("site:*-%s-*.%s", env, c.Target),
				)
			}
		}
	}

	// Generate service-based dorks
	if len(nc.Services) > 0 {
		// Try other common services
		targetSvcs := []string{"admin", "db", "database", "cache", "internal", "private", "backup", "jenkins", "gitlab", "jira"}
		for _, svc := range targetSvcs {
			found := false
			for _, known := range nc.Services {
				if svc == known {
					found = true
					break
				}
			}
			if !found {
				// Generate dorks for unseen services
				dorks = append(dorks,
					fmt.Sprintf("site:*-%s-*.%s", svc, c.Target),
					fmt.Sprintf("site:%s-*.%s", svc, c.Target),
				)
			}
		}
	}

	// Generate region-based dorks if pattern detected
	if len(nc.Regions) > 0 {
		// Try other common regions
		targetRegions := []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-central-1", "ap-northeast-1", "ap-southeast-1"}
		for _, reg := range targetRegions {
			dorks = append(dorks,
				fmt.Sprintf("site:*-%s*.%s", reg, c.Target),
			)
		}
	}

	// Email-based dorks
	if nc.EmailPattern != "" {
		dorks = append(dorks,
			fmt.Sprintf("site:%s intext:\"@%s\" (intext:password OR intext:token OR intext:api_key)", c.Target, c.Target),
			fmt.Sprintf("site:%s filetype:xls OR filetype:xlsx OR filetype:csv intext:\"@%s\"", c.Target, c.Target),
		)
	}

	// Wildcard pattern matching based on detected structure
	if nc.SubdomainPattern != "" {
		dorks = append(dorks,
			fmt.Sprintf("site:*-*-*.%s", c.Target),
			fmt.Sprintf("site:*-*.%s inurl:admin", c.Target),
			fmt.Sprintf("site:*-*.%s inurl:api", c.Target),
		)
	}

	if len(dorks) > 0 {
		console.Logv(c.Verbose, "[PATTERN-DETECTION] Generated %d dorks based on naming conventions (confidence: %.1f%%)", len(dorks), nc.Confidence)
	}

	return dorks
}

// extractPatternsFromResults analyzes successful results to extract patterns
func extractPatternsFromResults(results []string) []core.SuccessPattern {
	patterns := make(map[string]*core.SuccessPattern)

	for _, url := range results {
		// Extract path
		pathPattern := extractPathPattern(url)
		if pathPattern != "" {
			key := "path:" + pathPattern
			if p, exists := patterns[key]; exists {
				p.SuccessCount++
				p.LastSeen = time.Now()
			} else {
				patterns[key] = &core.SuccessPattern{
					Pattern:      "inurl:" + pathPattern,
					Path:         pathPattern,
					Context:      detectContext(url),
					SuccessCount: 1,
					LastSeen:     time.Now(),
				}
			}
		}

		// Extract parameters
		params := extractParameters(url)
		for _, param := range params {
			key := "param:" + param
			if p, exists := patterns[key]; exists {
				p.SuccessCount++
				p.LastSeen = time.Now()
			} else {
				patterns[key] = &core.SuccessPattern{
					Pattern:      "inurl:?" + param + "=",
					Parameter:    param,
					Context:      detectContext(url),
					SuccessCount: 1,
					LastSeen:     time.Now(),
				}
			}
		}

		// Extract file types
		fileType := extractFileType(url)
		if fileType != "" {
			key := "filetype:" + fileType
			if p, exists := patterns[key]; exists {
				p.SuccessCount++
				p.LastSeen = time.Now()
			} else {
				patterns[key] = &core.SuccessPattern{
					Pattern:      "filetype:" + fileType,
					FileType:     fileType,
					Context:      detectContext(url),
					SuccessCount: 1,
					LastSeen:     time.Now(),
				}
			}
		}
	}

	// Convert map to slice
	var result []core.SuccessPattern
	for _, p := range patterns {
		result = append(result, *p)
	}

	return result
}

// extractPathPattern extracts meaningful path patterns from URL
func extractPathPattern(url string) string {
	// Extract path from URL
	re := regexp.MustCompile(`https?://[^/]+(/[^?#]*)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		path := matches[1]
		// Remove trailing slashes
		path = strings.TrimRight(path, "/")
		// Only return paths that are meaningful (not just "/")
		if path != "" && path != "/" {
			return path
		}
	}
	return ""
}

// extractParameters extracts parameter names from URL
func extractParameters(url string) []string {
	var params []string
	// Match ?param= or &param=
	re := regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)=`)
	matches := re.FindAllStringSubmatch(url, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	return params
}

// extractFileType extracts file extension from URL
func extractFileType(url string) string {
	// Common file extensions
	extensions := []string{".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".csv", ".xls", ".xlsx", ".pdf", ".sql", ".env", ".ini", ".conf", ".yaml", ".yml"}
	urlLower := strings.ToLower(url)
	for _, ext := range extensions {
		if strings.Contains(urlLower, ext) {
			return strings.TrimPrefix(ext, ".")
		}
	}
	return ""
}

// detectContext detects the context/category of a URL
func detectContext(url string) string {
	urlLower := strings.ToLower(url)

	// Admin context
	if strings.Contains(urlLower, "admin") || strings.Contains(urlLower, "dashboard") || strings.Contains(urlLower, "panel") {
		return "admin"
	}
	// API context
	if strings.Contains(urlLower, "api") || strings.Contains(urlLower, "/v1/") || strings.Contains(urlLower, "/v2/") {
		return "api"
	}
	// Config context
	if strings.Contains(urlLower, "config") || strings.Contains(urlLower, "settings") {
		return "config"
	}
	// Auth context
	if strings.Contains(urlLower, "login") || strings.Contains(urlLower, "auth") || strings.Contains(urlLower, "signin") {
		return "auth"
	}
	// Upload context
	if strings.Contains(urlLower, "upload") || strings.Contains(urlLower, "file") {
		return "upload"
	}

	return "general"
}
