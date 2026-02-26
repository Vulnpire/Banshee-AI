package tech

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/cve"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"
)

// TechDetectionResult contains detected technology information
type TechDetectionResult struct {
	Technology string
	Version    string
	Category   string
	Confidence int // 0-100
}

// detectTechnologies performs comprehensive technology fingerprinting using Wappalyzer
func (c *Config) detectTechnologies(ctx context.Context) []TechDetectionResult {
	console.Logv(c.Verbose, "[TECH-DETECT] Starting comprehensive technology fingerprinting...")

	// Initialize Wappalyzer
	wappalyzer, err := wappalyzergo.New()
	if err != nil {
		console.Logv(c.Verbose, "[TECH-DETECT] Failed to initialize Wappalyzer: %v", err)
		return nil
	}

	// Fetch the target homepage
	targetURL := fmt.Sprintf("https://%s", c.Target)

	// Try HTTPS first, fallback to HTTP
	resp, body, err := c.fetchURLForFingerprinting(targetURL)
	if err != nil {
		// Try HTTP if HTTPS fails
		targetURL = fmt.Sprintf("http://%s", c.Target)
		resp, body, err = c.fetchURLForFingerprinting(targetURL)
		if err != nil {
			console.Logv(c.Verbose, "[TECH-DETECT] Failed to fetch target for fingerprinting: %v", err)
			return nil
		}
	}

	// Safely close response body
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// Add debug logging if verbose
	if c.Verbose {
		console.Logv(c.Verbose, "[TECH-DETECT] Fetched %d bytes from %s", len(body), targetURL)
		console.Logv(c.Verbose, "[TECH-DETECT] Analyzing %d response headers", len(resp.Header))
	}

	// Fingerprint the response
	fingerprints := wappalyzer.Fingerprint(resp.Header, []byte(body))

	// Also get detailed info for categories
	fingerprintsWithInfo := wappalyzer.FingerprintWithInfo(resp.Header, []byte(body))

	var results []TechDetectionResult
	techCount := 0

	// Process fingerprints
	for technology := range fingerprints {
		// Get additional info if available
		info, hasInfo := fingerprintsWithInfo[technology]

		// Try to extract version from headers or HTML
		version := c.extractVersionFromResponse(technology, resp.Header, body)

		// Get category
		category := "Detected"
		if hasInfo && len(info.Categories) > 0 {
			category = getCategoryName(info.Categories[0])
		}

		result := TechDetectionResult{
			Technology: technology,
			Version:    version,
			Category:   category,
			Confidence: 100, // Wappalyzer matches are high confidence
		}

		results = append(results, result)
		techCount++

		// Log each detection with version
		if version != "" {
			console.Logv(c.Verbose, "[TECH-DETECT] ✓ %s %s (%s)", result.Technology, version, category)
		} else {
			console.Logv(c.Verbose, "[TECH-DETECT] ✓ %s (%s)", result.Technology, category)
		}
	}

	// If we detected very few technologies, try analyzing additional common paths
	if techCount < 3 {
		console.Logv(c.Verbose, "[TECH-DETECT] Limited results (%d techs), analyzing additional endpoints...", techCount)
		additionalResults := c.analyzeAdditionalPaths(ctx, wappalyzer)
		results = append(results, additionalResults...)
		techCount = len(results)
	}

	if techCount > 0 {
		console.Logv(c.Verbose, "[TECH-DETECT] Detected %d technologies using Wappalyzer fingerprinting", techCount)
	} else {
		console.Logv(c.Verbose, "[TECH-DETECT] No technologies detected (target may be blocking requests)")
	}

	return results
}

// fetchURLForFingerprinting fetches a URL for technology fingerprinting
func (c *Config) fetchURLForFingerprinting(url string) (*http.Response, string, error) {
	// Create HTTP client with timeout and proper headers
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.Insecure,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow up to 5 redirects
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	// Set realistic browser headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}

	// Read body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, "", err
	}

	return resp, string(bodyBytes), nil
}

// getCategoryName returns a human-readable category name
func getCategoryName(category string) string {
	// Map common categories
	categoryMap := map[string]string{
		"cms":                  "CMS",
		"web-frameworks":       "Framework",
		"programming-language": "Language",
		"web-servers":          "Web Server",
		"databases":            "Database",
		"analytics":            "Analytics",
		"javascript-libraries": "JS Library",
		"cdn":                  "CDN",
		"ecommerce":            "E-commerce",
		"marketing":            "Marketing",
		"payment":              "Payment",
	}

	if mapped, ok := categoryMap[strings.ToLower(category)]; ok {
		return mapped
	}

	return "Other"
}

// updateIntelligenceWithTechStack updates intelligence with detected technologies
func (c *Config) updateIntelligenceWithTechStack(results []TechDetectionResult) {
	if c.Intelligence == nil || len(results) == 0 {
		return
	}

	// Clear existing tech stack
	c.Intelligence.TechStack = []string{}

	// Add detected technologies
	for _, result := range results {
		techString := result.Technology
		if result.Version != "" {
			techString = fmt.Sprintf("%s %s", result.Technology, result.Version)
		}

		// Add to tech stack
		c.Intelligence.TechStack = append(c.Intelligence.TechStack, techString)
	}

	console.Logv(c.Verbose, "[TECH-DETECT] Updated intelligence with %d detected technologies", len(c.Intelligence.TechStack))
}

// generateTechBasedDorks generates initial dorks based on detected technologies
func (c *Config) generateTechBasedDorks(results []TechDetectionResult) []string {
	if len(results) == 0 {
		return nil
	}

	var dorks []string

	console.Logv(c.Verbose, "[TECH-DORK] Generating technology-specific dorks...")

	for _, tech := range results {
		techLower := strings.ToLower(tech.Technology)
		version := tech.Version

		// Generate tech-specific dorks based on detected technology
		switch {
		// Web Servers
		case strings.Contains(techLower, "apache"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s intitle:\"Apache\" \"It works!\"", c.Target),
				fmt.Sprintf("site:%s intext:\"Apache\" intitle:\"Test Page\"", c.Target),
			)
			if version != "" {
				dorks = append(dorks,
					fmt.Sprintf("site:%s intext:\"Apache/%s\"", c.Target, version),
				)
			}

		case strings.Contains(techLower, "nginx"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s intitle:\"Welcome to nginx\"", c.Target),
				fmt.Sprintf("site:%s intext:\"nginx\"", c.Target),
			)

		case strings.Contains(techLower, "tomcat"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:8080", c.Target),
				fmt.Sprintf("site:%s intitle:\"Apache Tomcat\"", c.Target),
				fmt.Sprintf("site:%s inurl:manager/html", c.Target),
			)

		// CMS
		case strings.Contains(techLower, "wordpress"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:wp-content", c.Target),
				fmt.Sprintf("site:%s inurl:wp-json/wp/v2/users", c.Target),
				fmt.Sprintf("site:%s inurl:wp-admin", c.Target),
				fmt.Sprintf("site:%s inurl:wp-config.php.bak", c.Target),
			)

		case strings.Contains(techLower, "drupal"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:user/register", c.Target),
				fmt.Sprintf("site:%s inurl:CHANGELOG.txt", c.Target),
				fmt.Sprintf("site:%s inurl:sites/default/files", c.Target),
			)

		case strings.Contains(techLower, "joomla"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:administrator", c.Target),
				fmt.Sprintf("site:%s inurl:configuration.php", c.Target),
			)

		// Frameworks
		case strings.Contains(techLower, "laravel"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:_ignition", c.Target),
				fmt.Sprintf("site:%s filetype:env intext:APP_KEY", c.Target),
				fmt.Sprintf("site:%s inurl:telescope", c.Target),
			)

		case strings.Contains(techLower, "django"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:admin intext:django", c.Target),
				fmt.Sprintf("site:%s inurl:__debug__", c.Target),
			)

		case strings.Contains(techLower, "spring"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:/actuator", c.Target),
				fmt.Sprintf("site:%s inurl:/actuator/health", c.Target),
				fmt.Sprintf("site:%s inurl:/actuator/env", c.Target),
			)

		case strings.Contains(techLower, "struts"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:.action", c.Target),
				fmt.Sprintf("site:%s filetype:action", c.Target),
			)

		// E-commerce
		case strings.Contains(techLower, "shopify"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:/admin", c.Target),
				fmt.Sprintf("site:%s inurl:/collections/", c.Target),
			)

		case strings.Contains(techLower, "magento"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:/admin", c.Target),
				fmt.Sprintf("site:%s inurl:/downloader/", c.Target),
			)

		case strings.Contains(techLower, "woocommerce"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:wc-api", c.Target),
				fmt.Sprintf("site:%s inurl:wp-admin", c.Target),
			)

		// Databases & Data Stores
		case strings.Contains(techLower, "mongodb"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:27017", c.Target),
			)

		case strings.Contains(techLower, "elasticsearch"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:9200", c.Target),
				fmt.Sprintf("site:%s inurl:9200/_cluster/health", c.Target),
			)

		case strings.Contains(techLower, "redis"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:6379", c.Target),
			)

		// DevOps & Infrastructure
		case strings.Contains(techLower, "kubernetes"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:/api/v1", c.Target),
				fmt.Sprintf("site:%s intitle:\"Kubernetes Dashboard\"", c.Target),
			)

		case strings.Contains(techLower, "docker"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:2375", c.Target),
				fmt.Sprintf("site:%s inurl:2376", c.Target),
			)

		case strings.Contains(techLower, "jenkins"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:/jenkins", c.Target),
				fmt.Sprintf("site:%s intitle:\"Dashboard [Jenkins]\"", c.Target),
			)

		case strings.Contains(techLower, "gitlab"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:/users/sign_in", c.Target),
				fmt.Sprintf("site:%s inurl:/api/v4/version", c.Target),
			)

		case strings.Contains(techLower, "grafana"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:/grafana", c.Target),
				fmt.Sprintf("site:%s intitle:\"Grafana\"", c.Target),
			)

		// Cloud Providers (detected from headers/signatures)
		case strings.Contains(techLower, "aws"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s inurl:s3.amazonaws.com", c.Target),
			)

		case strings.Contains(techLower, "cloudflare"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s intext:\"cloudflare\"", c.Target),
			)
		}
	}

	// Remove duplicates
	dorks = removeDuplicates(dorks)

	if len(dorks) > 0 {
		console.Logv(c.Verbose, "[TECH-DORK] Generated %d technology-specific dorks", len(dorks))
	}

	return dorks
}

// extractVersionFromResponse attempts to extract version information from headers and body
func (c *Config) extractVersionFromResponse(technology string, headers http.Header, body string) string {
	techLower := strings.ToLower(technology)

	// Check common server headers
	if server := headers.Get("Server"); server != "" {
		serverLower := strings.ToLower(server)
		// Extract version from Server header (e.g., "Apache/2.4.41", "nginx/1.18.0")
		if strings.Contains(serverLower, techLower) {
			parts := strings.Split(server, "/")
			if len(parts) == 2 {
				return parts[1]
			}
		}
	}

	// Check X-Powered-By header
	if powered := headers.Get("X-Powered-By"); powered != "" {
		poweredLower := strings.ToLower(powered)
		if strings.Contains(poweredLower, techLower) {
			// Extract version (e.g., "PHP/7.4.3", "ASP.NET/4.0.30319")
			parts := strings.Split(powered, "/")
			if len(parts) == 2 {
				return parts[1]
			}
		}
	}

	// Check X-Generator header
	if gen := headers.Get("X-Generator"); gen != "" {
		genLower := strings.ToLower(gen)
		if strings.Contains(genLower, techLower) {
			parts := strings.Split(gen, " ")
			for _, part := range parts {
				if strings.Contains(strings.ToLower(part), techLower) {
					versionParts := strings.Split(part, "/")
					if len(versionParts) == 2 {
						return versionParts[1]
					}
				}
			}
		}
	}

	// Check HTML meta tags for common CMS versions
	bodyLower := strings.ToLower(body)

	// WordPress version
	if strings.Contains(techLower, "wordpress") {
		re := regexp.MustCompile(`(?i)wordpress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
		// Check generator meta tag
		re = regexp.MustCompile(`(?i)<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress\s+([0-9.]+)`)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	// Joomla version
	if strings.Contains(techLower, "joomla") {
		re := regexp.MustCompile(`(?i)joomla!\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	// Drupal version
	if strings.Contains(techLower, "drupal") {
		re := regexp.MustCompile(`(?i)drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	// jQuery version (very common)
	if strings.Contains(techLower, "jquery") {
		re := regexp.MustCompile(`jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)`)
		if matches := re.FindStringSubmatch(bodyLower); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// analyzeAdditionalPaths tries analyzing additional common paths for better tech detection
func (c *Config) analyzeAdditionalPaths(ctx context.Context, wappalyzer *wappalyzergo.Wappalyze) []TechDetectionResult {
	// Common paths that often reveal technology info
	commonPaths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/",
		"/api/",
		"/swagger.json",
		"/openapi.json",
	}

	var additionalResults []TechDetectionResult
	detectedTechs := make(map[string]bool)

	for _, path := range commonPaths {
		// Build URL
		targetURL := fmt.Sprintf("https://%s%s", c.Target, path)

		// Fetch the path
		resp, body, err := c.fetchURLForFingerprinting(targetURL)
		if err != nil {
			// Try HTTP if HTTPS fails
			targetURL = fmt.Sprintf("http://%s%s", c.Target, path)
			resp, body, err = c.fetchURLForFingerprinting(targetURL)
			if err != nil {
				continue // Skip this path if both fail
			}
		}

		// Safely close response body
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}

		// Fingerprint this response
		fingerprints := wappalyzer.Fingerprint(resp.Header, []byte(body))
		fingerprintsWithInfo := wappalyzer.FingerprintWithInfo(resp.Header, []byte(body))

		for technology := range fingerprints {
			// Skip if already detected
			if detectedTechs[technology] {
				continue
			}
			detectedTechs[technology] = true

			// Get info
			info, hasInfo := fingerprintsWithInfo[technology]

			// Extract version
			version := c.extractVersionFromResponse(technology, resp.Header, body)

			// Get category
			category := "Detected"
			if hasInfo && len(info.Categories) > 0 {
				category = getCategoryName(info.Categories[0])
			}

			result := TechDetectionResult{
				Technology: technology,
				Version:    version,
				Category:   category,
				Confidence: 90, // Slightly lower confidence for non-homepage detections
			}

			additionalResults = append(additionalResults, result)

			// Log
			if version != "" {
				console.Logv(c.Verbose, "[TECH-DETECT] ✓ %s %s (%s) [from %s]", technology, version, category, path)
			} else {
				console.Logv(c.Verbose, "[TECH-DETECT] ✓ %s (%s) [from %s]", technology, category, path)
			}
		}
	}

	return additionalResults
}

// performComprehensiveTechDetection performs full tech detection workflow
// This function is only called when --tech-detect flag is set
func (c *Config) performComprehensiveTechDetection(ctx context.Context) ([]string, []CVEEntry) {
	// Sanity check - should only be called when tech detection is enabled
	if !c.TechDetect {
		return nil, nil
	}

	// Step 1: Detect technologies using Wappalyzer
	techResults := c.detectTechnologies(ctx)
	if len(techResults) == 0 {
		console.Logv(c.Verbose, "[TECH-DETECT] No technologies detected, skipping CVE matching")
		return nil, nil
	}

	// Step 2: Update intelligence with detected tech stack
	if c.LearnMode {
		c.updateIntelligenceWithTechStack(techResults)
	}

	// Step 3: Generate technology-specific dorks
	techDorks := c.generateTechBasedDorks(techResults)

	// Step 4: Perform CVE detection based on detected technologies
	// Only do CVE matching if user explicitly requests it
	var detectedCVEs []CVEEntry
	isCVEHuntingRequested := false
	if c.LearnMode && c.AiPrompt != "" {
		promptLower := strings.ToLower(c.AiPrompt)
		isCVEHuntingRequested = strings.Contains(promptLower, "cve") ||
			strings.Contains(promptLower, "vulnerab") ||
			strings.Contains(promptLower, "exploit")
	}

	if isCVEHuntingRequested {
		console.Logv(c.Verbose, "[CVE-DETECT] Matching detected technologies against CVE database...")

		for _, tech := range techResults {
			// Match CVEs for this technology and version
			cves := cve.MatchCVEsByTechnology(tech.Technology, tech.Version)

			// Filter by year if specified
			if c.CveYear > 0 {
				var filteredCVEs []CVEEntry
				for _, cve := range cves {
					// Extract year from CVE ID (format: CVE-YYYY-XXXXX)
					if len(cve.CVEID) >= 8 {
						yearStr := cve.CVEID[4:8]
						if year, err := strconv.Atoi(yearStr); err == nil {
							if year == c.CveYear {
								filteredCVEs = append(filteredCVEs, cve)
							}
						}
					}
				}
				cves = filteredCVEs

				if len(cves) > 0 {
					console.Logv(c.Verbose, "[CVE-FILTER] Filtered to %d CVEs from year %d", len(cves), c.CveYear)
				}
			}

			if len(cves) > 0 {
				detectedCVEs = append(detectedCVEs, cves...)

				for _, cve := range cves {
					console.Logv(c.Verbose, "[CVE-MATCH] %s %s → %s (%s, CVSS: %.1f)",
						tech.Technology, tech.Version, cve.CVEID, cve.Severity, cve.CVSS)
				}
			}
		}

		// Step 5: Generate CVE-specific dorks
		if len(detectedCVEs) > 0 {
			cveDorks := c.generateCVEDorks(detectedCVEs)
			techDorks = append(techDorks, cveDorks...)

			console.Logv(c.Verbose, "[CVE-DORK] Added %d CVE-targeted dorks", len(cveDorks))
		}
	}

	return techDorks, detectedCVEs
}
