package cve

import (
	"context"
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
	"strconv"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// NVDCVEItem represents a CVE from the NVD API
type NVDCVEItem struct {
	ID       string `json:"id"`
	Published string `json:"published"` // Publication date: YYYY-MM-DDTHH:MM:SS.sss
	Descriptions []struct {
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CVSSV31 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CVSSV2 []struct {
			CVSSData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria              string `json:"criteria"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
				VersionStartIncluding string `json:"versionStartIncluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type NVDResponse struct {
	Vulnerabilities []struct {
		CVE NVDCVEItem `json:"cve"`
	} `json:"vulnerabilities"`
	TotalResults int `json:"totalResults"`
}

// updateCVEDatabase fetches latest CVEs from NVD API and updates local database
func (c *Config) updateCVEDatabase(ctx context.Context) error {
	fmt.Println()
	fmt.Printf("%s[CVE-UPDATE]%s Starting CVE database update...\n", console.ColorCyan, console.ColorReset)
	fmt.Printf("%s[CVE-UPDATE]%s This will take 2-3 minutes due to NVD API rate limiting (6s/request)\n", console.ColorCyan, console.ColorReset)
	if c.NvdAPIKey == "" {
		fmt.Printf("%s[CVE-UPDATE]%s No NVD API key provided - may encounter rate limiting (403 errors)\n", console.ColorYellow, console.ColorReset)
		fmt.Printf("%s[CVE-UPDATE]%s Get free API key: https://nvd.nist.gov/developers/request-an-api-key\n", console.ColorYellow, console.ColorReset)
	}

	// Show AI dork generation status
	if c.AiDorkGeneration {
		fmt.Printf("%s[AI-DORK]%s AI-powered dork generation enabled (using gemini-cli)\n", console.ColorGreen, console.ColorReset)
		fmt.Printf("%s[AI-DORK]%s This will generate specialized, attack-focused dorks for each CVE\n", console.ColorGreen, console.ColorReset)
		fmt.Printf("%s[AI-DORK]%s Process will take longer but produce higher quality results\n", console.ColorGreen, console.ColorReset)
		// Check if gemini-cli is available
		if _, err := exec.LookPath("gemini-cli"); err != nil {
			fmt.Printf("%s[WARNING]%s gemini-cli not found in PATH - falling back to traditional dorks\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("%s[WARNING]%s Install from: https://github.com/reugn/gemini-cli\n", console.ColorYellow, console.ColorReset)
			c.AiDorkGeneration = false // Disable if not available
		}
	}

	fmt.Println()

	// Get config directory
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	cveDBPath := filepath.Join(home, ".config", "banshee", "cve_database_custom.json")

	// Check if custom database already exists
	var existingCVEs []CVEEntry
	if data, err := os.ReadFile(cveDBPath); err == nil {
		if err := json.Unmarshal(data, &existingCVEs); err == nil {
			fmt.Printf("%s[CVE-UPDATE]%s Found %d existing CVEs in custom database\n", console.ColorYellow, console.ColorReset, len(existingCVEs))
		}
	}

	// Fetch CVEs from NVD
	fmt.Printf("%s[CVE-UPDATE]%s Fetching CVEs from NVD API...\n", console.ColorCyan, console.ColorReset)
	newCVEs, err := c.fetchCVEsFromNVD(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch CVEs: %v", err)
	}

	fmt.Printf("%s[CVE-UPDATE]%s Fetched %d new CVEs from NVD\n", console.ColorGreen, console.ColorReset, len(newCVEs))

	// If no new CVEs and no existing, use built-in database as base
	if len(newCVEs) == 0 && len(existingCVEs) == 0 {
		fmt.Printf("%s[CVE-UPDATE]%s No CVEs fetched from NVD, using built-in database as base\n", console.ColorYellow, console.ColorReset)
		newCVEs = CVEDatabase
	}

	// Merge with existing CVEs (deduplicate by CVE ID)
	cveMap := make(map[string]CVEEntry)
	for _, cve := range existingCVEs {
		cveMap[cve.CVEID] = cve
	}
	for _, cve := range newCVEs {
		cveMap[cve.CVEID] = cve // New CVEs take precedence
	}

	// Convert map to slice
	var allCVEs []CVEEntry
	for _, cve := range cveMap {
		allCVEs = append(allCVEs, cve)
	}

	// Sort by CVSS score (descending)
	sort.Slice(allCVEs, func(i, j int) bool {
		return allCVEs[i].CVSS > allCVEs[j].CVSS
	})

	// Save to custom database
	data, err := json.MarshalIndent(allCVEs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CVEs: %v", err)
	}

	// Ensure directory exists
	os.MkdirAll(filepath.Dir(cveDBPath), 0755)

	if err := os.WriteFile(cveDBPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write CVE database: %v", err)
	}

	// Show summary statistics
	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, cve := range allCVEs {
		switch strings.ToLower(cve.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}

	fmt.Println()
	fmt.Printf("%s╔════════════════════════════════════════════════════════════════╗%s\n", console.ColorCyan, console.ColorReset)
	fmt.Printf("%s║           CVE DATABASE UPDATE SUMMARY                         ║%s\n", console.ColorCyan, console.ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════════╝%s\n", console.ColorCyan, console.ColorReset)
	fmt.Println()

	// Show applied filters
	if c.CveYear > 0 || c.CveSeverity != "" {
		fmt.Printf("%s  Filters Applied:%s\n", console.ColorCyan, console.ColorReset)
		if c.CveYear > 0 {
			fmt.Printf("    • Year: %s%d%s\n", console.ColorGreen, c.CveYear, console.ColorReset)
		}
		if c.CveSeverity != "" {
			fmt.Printf("    • Severity: %s%s%s\n", console.ColorGreen, strings.ToUpper(c.CveSeverity), console.ColorReset)
		}
		fmt.Printf("    • Only exploitable CVEs (RCE, SQLi, Path Traversal, etc.)\n")
		fmt.Println()
	}

	fmt.Printf("  Total CVEs:     %s%d%s (exploitable only)\n", console.ColorBoldWhite, len(allCVEs), console.ColorReset)
	fmt.Printf("  Critical:       %s%d%s\n", console.ColorRed, critical, console.ColorReset)
	fmt.Printf("  High:           %s%d%s\n", console.ColorOrange, high, console.ColorReset)
	fmt.Printf("  Medium:         %s%d%s\n", console.ColorYellow, medium, console.ColorReset)
	fmt.Printf("  Low:            %s%d%s\n", console.ColorGray, low, console.ColorReset)
	fmt.Println()
	fmt.Printf("  Database:       %s\n", cveDBPath)
	fmt.Printf("  Last Updated:   %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	return nil
}

// fetchCVEsFromNVD fetches CVEs from NVD API
func (c *Config) fetchCVEsFromNVD(ctx context.Context) ([]CVEEntry, error) {
	var allCVEs []CVEEntry
	has403Errors := false

	// Technologies to search for
	technologies := []string{
		"Apache", "Nginx", "WordPress", "Drupal", "Joomla",
		"Laravel", "Django", "Spring", "Struts",
		"GitLab", "Jenkins", "Tomcat",
	}

	totalTechs := len(technologies)
	for i, tech := range technologies {
		fmt.Printf("%s[%d/%d]%s Fetching CVEs for %s...", console.ColorCyan, i+1, totalTechs, console.ColorReset, tech)

		// Build NVD API URL (NO DATE FILTERS - NVD doesn't support them)
		// We filter by year after downloading by parsing the "published" field
		baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
		params := url.Values{}
		params.Add("keywordSearch", tech)
		params.Add("resultsPerPage", fmt.Sprintf("%d", c.CveResultsPerPage))

		// Add severity filter if specified (NVD API supports: LOW, MEDIUM, HIGH, CRITICAL)
		if c.CveSeverity != "" {
			severities := strings.Split(strings.ToUpper(c.CveSeverity), ",")
			for _, sev := range severities {
				sev = strings.TrimSpace(sev)
				if sev == "CRITICAL" || sev == "HIGH" || sev == "MEDIUM" || sev == "LOW" {
					params.Add("cvssV3Severity", sev)
				}
			}
		}

		apiURL := baseURL + "?" + params.Encode()

		if c.Verbose {
			fmt.Printf("\n%s[DEBUG]%s API URL: %s\n", console.ColorGray, console.ColorReset, apiURL)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			fmt.Printf(" %s✗ Request error%s\n", console.ColorRed, console.ColorReset)
			continue
		}

		req.Header.Set("User-Agent", core.DefaultUserAgent)
		if c.NvdAPIKey != "" {
			req.Header.Set("apiKey", c.NvdAPIKey)
			if c.Verbose {
				fmt.Printf("\n%s[DEBUG]%s Using API key: %s...%s\n",
					console.ColorGray, console.ColorReset, c.NvdAPIKey[:8], console.ColorReset)
			}
		}

		resp, err := c.Client.Do(req)
		if err != nil {
			fmt.Printf(" %s✗ Network error: %v%s\n", console.ColorRed, err, console.ColorReset)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			fmt.Printf(" %s✗ Read error%s\n", console.ColorRed, console.ColorReset)
			continue
		}

		// Check for API errors
		if resp.StatusCode != 200 {
			fmt.Printf(" %s✗ HTTP %d%s\n", console.ColorRed, resp.StatusCode, console.ColorReset)
			if c.Verbose && len(body) > 0 {
				bodyPreview := string(body)
				if len(bodyPreview) > 200 {
					bodyPreview = bodyPreview[:200]
				}
				fmt.Printf("%s[DEBUG]%s Response body: %s\n", console.ColorGray, console.ColorReset, bodyPreview)
			}
			if resp.StatusCode == 403 {
				has403Errors = true
			}
			continue
		}

		var nvdResp NVDResponse
		if err := json.Unmarshal(body, &nvdResp); err != nil {
			fmt.Printf(" %s✗ Parse error: %v%s\n", console.ColorRed, err, console.ColorReset)
			continue
		}

		// Debug: Show what NVD returned
		if c.Verbose {
			fmt.Printf("\n%s[DEBUG]%s NVD returned %d total results, %d vulnerabilities in response\n",
				console.ColorGray, console.ColorReset, nvdResp.TotalResults, len(nvdResp.Vulnerabilities))
		}

		// Parse CVEs
		techCVEs := 0
		skipped := 0
		for idx, vuln := range nvdResp.Vulnerabilities {
			// Debug: Print first CVE structure to understand format
			if c.Verbose && idx == 0 && i == 0 {
				sample, _ := json.MarshalIndent(vuln.CVE, "", "  ")
				fmt.Printf("\n%s[DEBUG]%s Sample CVE structure:\n%s\n", console.ColorGray, console.ColorReset, string(sample[:min(len(sample), 1000)]))
			}

			// Filter by year if specified (parse published date from CVE)
			if c.CveYear > 0 && vuln.CVE.Published != "" {
				// Parse year from published date: YYYY-MM-DDTHH:MM:SS.sss
				pubYear := 0
				if len(vuln.CVE.Published) >= 4 {
					if year, err := strconv.Atoi(vuln.CVE.Published[:4]); err == nil {
						pubYear = year
					}
				}

				// Skip if not from the specified year
				if pubYear != c.CveYear {
					skipped++
					continue
				}
			}

			cve := c.parseNVDCVE(vuln.CVE, tech)
			if cve != nil {
				allCVEs = append(allCVEs, *cve)
				techCVEs++
			} else {
				skipped++
				// Debug: Show why first CVE was skipped
				if c.Verbose && idx == 0 {
					fmt.Printf("%s[DEBUG]%s First CVE %s was skipped - checking metrics...\n",
						console.ColorGray, console.ColorReset, vuln.CVE.ID)
					fmt.Printf("%s[DEBUG]%s   CVSSV31 metrics count: %d\n", console.ColorGray, console.ColorReset, len(vuln.CVE.Metrics.CVSSV31))
					fmt.Printf("%s[DEBUG]%s   CVSSV2 metrics count: %d\n", console.ColorGray, console.ColorReset, len(vuln.CVE.Metrics.CVSSV2))
				}
			}
		}

		if c.Verbose && skipped > 0 {
			fmt.Printf("%s[DEBUG]%s Skipped %d CVEs (missing severity or incomplete data)\n",
				console.ColorGray, console.ColorReset, skipped)
		}

		fmt.Printf(" %s✓ %d CVEs%s (NVD returned %d)\n", console.ColorGreen, techCVEs, console.ColorReset, len(nvdResp.Vulnerabilities))

		// Rate limiting - NVD requires 6 seconds between requests without API key
		if i < totalTechs-1 {
			fmt.Printf("%s[WAIT]%s Rate limiting... (6 seconds)\n", console.ColorGray, console.ColorReset)
			time.Sleep(6 * time.Second)
		}
	}

	// Provide helpful guidance if all requests failed with 403
	if has403Errors && len(allCVEs) == 0 {
		fmt.Println()
		fmt.Printf("%s[HINT]%s All NVD API requests failed with 403 errors.\n", console.ColorYellow, console.ColorReset)

		if c.NvdAPIKey == "" {
			fmt.Printf("%s[HINT]%s NVD now requires an API key for most requests.\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("%s[HINT]%s Get a free API key: %shttps://nvd.nist.gov/developers/request-an-api-key%s\n", console.ColorYellow, console.ColorReset, console.ColorCyan, console.ColorReset)
			fmt.Printf("%s[HINT]%s Save to: %s~/.config/banshee/nvd-api-key.txt%s\n", console.ColorYellow, console.ColorReset, console.ColorGreen, console.ColorReset)
		} else {
			fmt.Printf("%s[HINT]%s API key was provided but NVD still returned 403.\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("%s[HINT]%s Possible causes:\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("%s        1.%s API key needs activation (check email from NVD)\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("%s        2.%s Network/firewall blocking NVD API access\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("%s        3.%s Invalid or expired API key\n", console.ColorYellow, console.ColorReset)
			fmt.Printf("%s[HINT]%s Using built-in CVE database as fallback.\n", console.ColorYellow, console.ColorReset)
		}
		fmt.Println()
	}

	return allCVEs, nil
}

// parseNVDCVE converts NVD CVE format to our CVEEntry format
func (c *Config) parseNVDCVE(nvdCVE NVDCVEItem, technology string) *CVEEntry {
	cve := &CVEEntry{
		CVEID:      nvdCVE.ID,
		Technology: technology,
	}

	// Get description (keep full description for AI dork generation and database storage)
	var fullDescription string
	if len(nvdCVE.Descriptions) > 0 {
		fullDescription = nvdCVE.Descriptions[0].Value
		// Store FULL description in database (no truncation)
		cve.Description = fullDescription
	}

	// Get CVSS score and severity
	if len(nvdCVE.Metrics.CVSSV31) > 0 {
		cve.CVSS = nvdCVE.Metrics.CVSSV31[0].CVSSData.BaseScore
		cve.Severity = strings.ToLower(nvdCVE.Metrics.CVSSV31[0].CVSSData.BaseSeverity)
	} else if len(nvdCVE.Metrics.CVSSV2) > 0 {
		cve.CVSS = nvdCVE.Metrics.CVSSV2[0].CVSSData.BaseScore
		// Convert CVSS v2 score to severity
		if cve.CVSS >= 9.0 {
			cve.Severity = "critical"
		} else if cve.CVSS >= 7.0 {
			cve.Severity = "high"
		} else if cve.CVSS >= 4.0 {
			cve.Severity = "medium"
		} else {
			cve.Severity = "low"
		}
	}

	// Skip CVEs without severity (likely incomplete data)
	if cve.Severity == "" {
		return nil
	}

	// Determine exploit type from description (BEFORE generating dorks)
	descLower := strings.ToLower(cve.Description)
	isExploitable := false

	if strings.Contains(descLower, "remote code execution") || strings.Contains(descLower, "rce") || strings.Contains(descLower, "execute arbitrary code") {
		cve.ExploitType = "RCE"
		isExploitable = true
	} else if strings.Contains(descLower, "sql injection") {
		cve.ExploitType = "SQLi"
		isExploitable = true
	} else if strings.Contains(descLower, "cross-site scripting") || strings.Contains(descLower, "xss") {
		cve.ExploitType = "XSS"
		isExploitable = true
	} else if strings.Contains(descLower, "path traversal") || strings.Contains(descLower, "directory traversal") {
		cve.ExploitType = "Path Traversal"
		isExploitable = true
	} else if strings.Contains(descLower, "bypass") || strings.Contains(descLower, "authentication bypass") || strings.Contains(descLower, "auth bypass") {
		cve.ExploitType = "Auth Bypass"
		isExploitable = true
	} else if strings.Contains(descLower, "file upload") || strings.Contains(descLower, "arbitrary file") {
		cve.ExploitType = "File Upload"
		isExploitable = true
	} else if strings.Contains(descLower, "ssrf") || strings.Contains(descLower, "server-side request forgery") {
		cve.ExploitType = "SSRF"
		isExploitable = true
	} else if strings.Contains(descLower, "command injection") || strings.Contains(descLower, "os command") {
		cve.ExploitType = "Command Injection"
		isExploitable = true
	} else if strings.Contains(descLower, "privilege escalation") || strings.Contains(descLower, "escalation of privilege") {
		cve.ExploitType = "Privilege Escalation"
		isExploitable = true
	} else if strings.Contains(descLower, "information disclosure") || strings.Contains(descLower, "sensitive information") {
		cve.ExploitType = "Info Disclosure"
		isExploitable = true
	} else if strings.Contains(descLower, "deserialization") || strings.Contains(descLower, "unsafe deserialization") {
		cve.ExploitType = "Deserialization"
		isExploitable = true
	} else if strings.Contains(descLower, "allows") && (strings.Contains(descLower, "attackers") || strings.Contains(descLower, "remote attackers") || strings.Contains(descLower, "unauthorized")) {
		// Catch-all for exploitable CVEs: "allows attackers to...", "allows remote attackers to...", "allows unauthorized..."
		cve.ExploitType = "Security Bypass"
		isExploitable = true
	} else if strings.Contains(descLower, "unauthorized access") || strings.Contains(descLower, "access control") {
		cve.ExploitType = "Access Control"
		isExploitable = true
	}

	// Skip CVEs that are ONLY DoS (not useful for dorking)
	// But keep if DoS is mentioned alongside other exploit types
	if strings.Contains(descLower, "denial of service") || strings.Contains(descLower, "dos") {
		if !isExploitable {
			cve.ExploitType = "DoS"
			return nil // Skip DoS-only CVEs
		}
		// Otherwise, keep the more serious exploit type we already identified
	}

	// For critical/high severity CVEs, be more lenient - include them even without specific exploit keywords
	if !isExploitable && (cve.Severity == "critical" || cve.Severity == "high") {
		cve.ExploitType = "High Severity"
		isExploitable = true
	}

	// Skip if no exploitable characteristics found
	if !isExploitable {
		return nil
	}

	// Determine if CVE has public exploit (critical/high severity CVEs)
	cve.HasPublicExploit = cve.Severity == "critical" || cve.Severity == "high"

	// If --has-exploit flag is set, skip CVEs without public exploits
	if c.HasExploit && !cve.HasPublicExploit {
		return nil
	}

	// Try to extract version pattern from CPE data
	if len(nvdCVE.Configurations) > 0 {
		for _, config := range nvdCVE.Configurations {
			for _, node := range config.Nodes {
				for _, cpe := range node.CPEMatch {
					// CPE format: cpe:2.3:a:vendor:product:version:...
					parts := strings.Split(cpe.Criteria, ":")
					if len(parts) >= 5 {
						version := parts[4]
						if version != "*" && version != "-" {
							// Create version pattern
							cve.VersionPattern = regexp.QuoteMeta(version)
							break
						}
					}
				}
			}
		}
	}

	// Generate dorks: AI-powered or traditional
	if c.AiDorkGeneration && fullDescription != "" {
		// Use AI to generate specialized dorks
		if c.Verbose {
			fmt.Printf("%s[AI-DORK]%s Generating specialized dorks for %s...", console.ColorCyan, console.ColorReset, cve.CVEID)
		}

		aiDorks, err := c.generateAIDorks(cve.CVEID, technology, fullDescription, cve.ExploitType, cve.Severity)
		if err != nil {
			// Fallback to traditional dorks if AI fails
			if c.Verbose {
				fmt.Printf(" %s✗ AI failed: %v%s\n", console.ColorYellow, err, console.ColorReset)
				fmt.Printf("%s[AI-DORK]%s Falling back to traditional dorks\n", console.ColorYellow, console.ColorReset)
			}
			cve.Dorks = generateExploitDorks(technology, cve.CVEID, cve.ExploitType)
		} else {
			cve.Dorks = aiDorks
			if c.Verbose {
				fmt.Printf(" %s✓ Generated %d AI dorks%s\n", console.ColorGreen, len(aiDorks), console.ColorReset)
			}
		}
	} else {
		// Use traditional dork generation
		cve.Dorks = generateExploitDorks(technology, cve.CVEID, cve.ExploitType)
	}

	return cve
}

// generateExploitDorks creates relevant dorks based on technology and exploit type
func generateExploitDorks(technology, cveID, exploitType string) []string {
	dorks := []string{
		fmt.Sprintf("intext:\"%s\" \"%s\"", technology, cveID),
		fmt.Sprintf("intext:\"%s\"", cveID),
	}

	// Add exploit-type specific dorks
	techLower := strings.ToLower(technology)
	switch exploitType {
	case "RCE":
		dorks = append(dorks,
			fmt.Sprintf("inurl:\"admin\" intext:\"%s\"", techLower),
			fmt.Sprintf("inurl:\"upload\" intext:\"%s\"", techLower),
		)
	case "SQLi":
		dorks = append(dorks,
			fmt.Sprintf("inurl:\"?id=\" intext:\"%s\"", techLower),
			fmt.Sprintf("inurl:\"login\" intext:\"%s\"", techLower),
		)
	case "Path Traversal":
		dorks = append(dorks,
			fmt.Sprintf("inurl:\"download\" intext:\"%s\"", techLower),
			fmt.Sprintf("inurl:\"file\" intext:\"%s\"", techLower),
		)
	case "Auth Bypass":
		dorks = append(dorks,
			fmt.Sprintf("inurl:\"admin\" intext:\"%s\"", techLower),
			fmt.Sprintf("inurl:\"login\" intext:\"%s\"", techLower),
		)
	case "File Upload":
		dorks = append(dorks,
			fmt.Sprintf("inurl:\"upload\" intext:\"%s\"", techLower),
		)
	}

	return dorks
}

// generateAIDorks uses gemini-cli to generate specialized, attack-focused dorks for a CVE
func (c *Config) generateAIDorks(cveID, technology, fullDescription, exploitType, severity string) ([]string, error) {
	// Check if gemini-cli is installed
	if _, err := exec.LookPath("gemini-cli"); err != nil {
		return nil, fmt.Errorf("gemini-cli not found in PATH - install from: https://github.com/reugn/gemini-cli")
	}

	// Load Gemini API key from config file (for rotation support)
	geminiAPIKey := ""
	if home, err := os.UserHomeDir(); err == nil {
		keyPath := filepath.Join(home, ".config", "banshee", "gemini-api-key.txt")
		if keyData, err := os.ReadFile(keyPath); err == nil {
			// Support multiple keys (one per line) - use first available
			lines := strings.Split(string(keyData), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					geminiAPIKey = line
					break
				}
			}
		}
	}

	// Determine max dorks to request from AI (default 10, configurable via --max-cve-dork)
	maxDorks := c.MaxCVEDork
	if maxDorks == 0 {
		maxDorks = 10 // Default
	}

	// Build the prompt for gemini-cli
	prompt := fmt.Sprintf(`You are a penetration testing expert analyzing CVEs to generate Google dorks for finding vulnerable systems.

Analyze this CVE and generate %d specialized Google dorks to find vulnerable systems (NOT advisories or documentation):

CVE ID: %s
Technology: %s
Severity: %s
Exploit Type: %s
Full Description:
%s

Generate dorks that Target:
1. Technology fingerprints (error pages, version strings, specific headers)
2. Version detection patterns in HTML/responses
3. Vulnerable endpoints or paths mentioned in the CVE
4. Configuration files or admin panels for this technology
5. Default installation paths and directories
6. Common deployment patterns
7. Technology-specific file extensions or patterns
8. Login pages or authentication endpoints

Requirements:
- Focus on finding VULNERABLE SYSTEMS, not security advisories
- Use advanced Google operators: inurl:, intitle:, intext:, filetype:, ext:
- Be SPECIFIC to this CVE's attack vector
- Target real deployments, not documentation
- Include version-specific patterns if possible
- Avoid generic dorks like 'intext:"CVE-ID"'

Format: Return ONLY the dorks, one per line, no numbering, no explanations, no extra text.`,
		maxDorks, cveID, technology, strings.ToUpper(severity), exploitType, fullDescription)

	// Call gemini-cli with stdin and API key environment variable
	// Increased timeout to 120s to handle longer AI responses
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Build command arguments - only add --model flag if aiModel is specified
	var args []string
	if c.AiModel != "" {
		args = []string{"--model", c.AiModel}
	} else {
		args = []string{}
	}

	cmd := exec.CommandContext(ctx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(prompt)

	// Set Gemini API key via environment variable if available
	if geminiAPIKey != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("GOOGLE_AI_API_KEY=%s", geminiAPIKey))
	}

	// Capture stdout and stderr separately to filter Node.js warnings
	output, err := cmd.Output()
	if err != nil {
		// Check if it's a timeout
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("gemini-cli timeout after 120s")
		}
		return nil, fmt.Errorf("gemini-cli failed: %v", err)
	}

	// Parse output - one dork per line
	lines := strings.Split(string(output), "\n")
	var dorks []string
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, comments, warnings, and non-dork lines
		if line == "" ||
		   strings.HasPrefix(line, "#") ||
		   strings.HasPrefix(line, "//") ||
		   strings.Contains(line, "DeprecationWarning") ||
		   strings.Contains(line, "node:") ||
		   strings.Contains(line, "(Use ") ||
		   strings.Contains(line, "Loaded cached credentials") ||
		   strings.Contains(line, "punycode") {
			continue
		}

		// Remove numbering if present (e.g., "1. dork" -> "dork")
		line = regexp.MustCompile(`^\d+\.\s*`).ReplaceAllString(line, "")
		// Remove markdown formatting if present
		line = strings.Trim(line, "`*-")
		line = strings.TrimSpace(line)

		// Only add if it looks like a valid dork (contains Google operators or quotes)
		if line != "" && (strings.Contains(line, "inurl:") ||
		                  strings.Contains(line, "intitle:") ||
		                  strings.Contains(line, "intext:") ||
		                  strings.Contains(line, "filetype:") ||
		                  strings.Contains(line, "ext:") ||
		                  strings.Contains(line, "site:") ||
		                  strings.Contains(line, "\"")) {
			dorks = append(dorks, line)
		}
	}

	// Validate we got some dorks
	if len(dorks) == 0 {
		return nil, fmt.Errorf("gemini-cli returned no valid dorks")
	}

	return dorks, nil
}

// loadCustomCVEDatabase loads custom CVE database if exists
func loadCustomCVEDatabase() ([]CVEEntry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cveDBPath := filepath.Join(home, ".config", "banshee", "cve_database_custom.json")

	data, err := os.ReadFile(cveDBPath)
	if err != nil {
		return nil, err // File doesn't exist, use built-in database
	}

	var cves []CVEEntry
	if err := json.Unmarshal(data, &cves); err != nil {
		return nil, err
	}

	return cves, nil
}

// getCVEDatabase returns merged built-in + custom CVE database
func getCVEDatabase() []CVEEntry {
	// Start with built-in database
	allCVEs := make([]CVEEntry, len(CVEDatabase))
	copy(allCVEs, CVEDatabase)

	// Try to load custom database
	customCVEs, err := loadCustomCVEDatabase()
	if err == nil && len(customCVEs) > 0 {
		// Merge with built-in (deduplicate by CVE ID)
		cveMap := make(map[string]CVEEntry)
		for _, cve := range allCVEs {
			cveMap[cve.CVEID] = cve
		}
		for _, cve := range customCVEs {
			cveMap[cve.CVEID] = cve // Custom DB takes precedence
		}

		// Convert back to slice
		allCVEs = make([]CVEEntry, 0, len(cveMap))
		for _, cve := range cveMap {
			allCVEs = append(allCVEs, cve)
		}
	}

	return allCVEs
}

// improveVersionDetection handles Ubuntu/Debian package versions
func improveVersionDetection(version string) string {
	// Handle Ubuntu/Debian package versions (e.g., "2.4.49-1ubuntu1")
	// Extract base version

	// Remove Debian/Ubuntu specific parts
	version = regexp.MustCompile(`[-+~](debian|ubuntu|deb|dfsg).*`).ReplaceAllString(version, "")

	// Remove build numbers after the version
	version = regexp.MustCompile(`-\d+$`).ReplaceAllString(version, "")

	return version
}
