package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

// researchCacheEntry represents cached OSINT research
type researchCacheEntry struct {
	Target    string    `json:"target"`
	Depth     int       `json:"depth"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// loadResearchCache loads cached research for a target/depth
func loadResearchCache(target string, depth int) (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	cachePath := filepath.Join(home, ".config", "banshee", "research-cache.json")
	b, err := os.ReadFile(cachePath)
	if err != nil {
		return "", false
	}

	var cache map[string]researchCacheEntry
	if err := json.Unmarshal(b, &cache); err != nil {
		return "", false
	}

	key := fmt.Sprintf("%s|%d", strings.ToLower(strings.TrimSpace(target)), depth)
	entry, ok := cache[key]
	if !ok || entry.Data == "" {
		return "", false
	}
	return entry.Data, true
}

// saveResearchCache stores research for a target/depth
func saveResearchCache(target string, depth int, data string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	cachePath := filepath.Join(home, ".config", "banshee", "research-cache.json")

	_ = os.MkdirAll(filepath.Dir(cachePath), 0755)

	cache := make(map[string]researchCacheEntry)
	if b, err := os.ReadFile(cachePath); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &cache)
	}

	key := fmt.Sprintf("%s|%d", strings.ToLower(strings.TrimSpace(target)), depth)
	cache[key] = researchCacheEntry{
		Target:    target,
		Depth:     depth,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	encoded, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(cachePath, encoded, 0644)
}

// performOSINTResearch conducts OSINT research on the target company using gemini-cli
func (c *Config) performOSINTResearch(ctx context.Context, target string) (string, error) {
	// Check if gemini-cli is installed
	if err := checkGeminiCLI(); err != nil {
		return "", err
	}

	// Check cache unless flush mode is explicitly requested
	if !c.FlushMode {
		if cached, ok := loadResearchCache(target, c.ResearchDepth); ok {
			console.Logv(c.Verbose, "[OSINT] Using cached research for %s (depth %d), skipping new run", target, c.ResearchDepth)
			if c.Verbose {
				osintTag := console.ColorizeVerboseOutput("[OSINT]")
				fmt.Fprintf(os.Stderr, "%s %sResearch summary (cached):%s\n", osintTag, console.ColorTeal, console.ColorReset)
				formattedOutput := formatMarkdownToText(cached)
				preview := formattedOutput
				if len(preview) > 1000 {
					preview = preview[:1000] + "..."
				}
				fmt.Fprintf(os.Stderr, "%s\n\n", preview)
			}
			return cached, nil
		}
	}

	console.Logv(c.Verbose, "[OSINT] Performing research on Target: %s (depth: %d)", target, c.ResearchDepth)

	// Build research prompt based on depth level
	var systemInstructions string
	var userPrompt string

	depthDescription := ""
	switch c.ResearchDepth {
	case 1:
		depthDescription = "basic"
		systemInstructions = fmt.Sprintf(`You are a security researcher conducting OSINT on a target company/domain. Provide a dense, actionable security-focused profile that can immediately drive targeted Google dorking.

RESEARCH AREAS (BASIC BUT COMPREHENSIVE):
1. Company/Organization Snapshot
   - What is this company/organization? Industry/sector and business model
   - Main products/services and any brand or project names
   - Primary languages/regions visible on the public web presence

2. Security Posture & History
   - Publicly disclosed vulnerabilities (CVEs, advisories, bug bounty reports)
   - Past security incidents, breaches, or data leaks
   - Mentioned authentication models or trust boundaries

3. Technology Stack & Infrastructure Signals
   - Core technologies, frameworks, and cloud/CDN providers seen or implied
   - Common file types or document patterns (policies, playbooks, exports)
   - Any environment hints (staging/dev hosts, VPN/SSO references)

4. Public Assets & Exposure Vectors
   - Typical public endpoints (admin panels, APIs, dashboards, portals)
   - Known subdomain or path naming conventions
   - Third-party integrations that expose additional surfaces

5. High-Signal Search Pivots
   - Unique names/terms to anchor dorks (products, subsidiaries, internal tools)
   - Email/address formats and regional cues

OUTPUT FORMAT:
Provide a structured report with clear sections. Keep it concise but rich with target-specific nouns, technologies, and patterns that can seed dorks. Avoid generic statements.`)

	case 2:
		depthDescription = "moderate"
		systemInstructions = fmt.Sprintf(`You are a security researcher conducting OSINT on a target company/domain. Provide a detailed security-focused profile.

RESEARCH AREAS (MODERATE):
1. Company/Organization Information
   - Company name, industry, sector
   - Main products, services, and business model
   - Geographic presence and scale

2. Security Posture & History
   - Publicly disclosed vulnerabilities (CVEs, bug bounty reports)
   - Past security incidents, breaches, or data leaks
   - Security certifications or compliance (if known)
   - Bug bounty program participation

3. Technology Stack & Infrastructure
   - Known technologies, platforms, frameworks
   - Cloud providers (AWS, Azure, GCP)
   - CDN usage (Cloudflare, Akamai, etc.)
   - Programming languages and databases commonly used

4. Public-Facing Assets
   - Common exposed endpoints (admin panels, APIs, portals)
   - Known subdomain patterns
   - Common file types and document exposure
   - Authentication mechanisms

5. Potential Weaknesses
   - Common vulnerability patterns for their tech stack
   - Known misconfigurations in similar organizations
   - Typical attack surfaces for their industry

OUTPUT FORMAT:
Provide a structured report with clear sections.
Focus on actionable intelligence for security testing and Google dorking.`)

	case 3:
		depthDescription = "comprehensive"
		systemInstructions = fmt.Sprintf(`You are a senior security researcher conducting comprehensive OSINT on a target company/domain. Provide an in-depth security-focused profile.

RESEARCH AREAS (COMPREHENSIVE):
1. Company/Organization Deep Dive
   - Full company profile: name, industry, sector, business model
   - Geographic presence, subsidiaries, acquisitions
   - Key products, services, and technologies
   - Market position and competitors

2. Security Posture & Historical Analysis
   - Comprehensive vulnerability history (CVEs, bug bounty reports, HackerOne, Bugcrowd)
   - Detailed breach history and incident timeline
   - Data leak analysis (Have I Been Pwned, breach databases)
   - Security certifications (ISO 27001, SOC 2, PCI-DSS, etc.)
   - Bug bounty program scope and rewards
   - Responsible disclosure policy

3. Technology Stack & Infrastructure Analysis
   - Complete technology stack (frontend, backend, database, cache)
   - Cloud infrastructure (AWS, Azure, GCP) and services used
   - CDN and security services (Cloudflare, Akamai, Fastly)
   - Programming languages, frameworks, and libraries
   - API technologies (REST, GraphQL, SOAP)
   - Known third-party integrations and dependencies

4. Public-Facing Assets & Attack Surface
   - Web applications and their purposes
   - API endpoints and documentation exposure
   - Admin panels, dashboards, and management interfaces
   - Authentication mechanisms (OAuth, SAML, custom)
   - Common subdomain patterns and naming conventions
   - Exposed file types and sensitive documents
   - Development/staging environment exposure
   - Version control exposure (.git, .svn)

5. Vulnerability Patterns & Weaknesses
   - Common vulnerability types for their tech stack
   - Known misconfigurations in their industry
   - OWASP Top 10 relevance to their stack
   - Typical attack vectors (SQLi, XSS, IDOR, etc.)
   - Legacy system exposure
   - Third-party component vulnerabilities

6. Intelligence Sources
   - GitHub repositories and code exposure
   - Social media presence and information disclosure
   - Job postings revealing technology details
   - SSL/TLS certificate information
   - DNS records and infrastructure details

OUTPUT FORMAT:
Provide a comprehensive, well-structured report with detailed sections.
Include specific examples where possible.
Focus on actionable intelligence for advanced security testing and targeted Google dorking.`)

	case 4:
		depthDescription = "linguistic"
		systemInstructions = fmt.Sprintf(`You are an expert OSINT researcher specializing in LINGUISTIC and ORGANIZATIONAL intelligence gathering.

RESEARCH AREAS (LINGUISTIC & ORGANIZATIONAL):

1. Company Identity & Naming
   - Full legal company name and common variations
   - Trading names, brand names, product names
   - Acronyms and internal naming conventions
   - Historical names (before mergers/acquisitions)

2. Email Intelligence
   - Primary email domain(s) used by the company
   - Alternative email domains (regional, subsidiary)
   - Email format patterns (firstname.lastname@domain, etc.)
   - Public employee emails from websites, press releases, papers

3. Project & Product Intelligence
   - Active project names and code names
   - Product names and versions
   - Service offerings and platforms
   - Internal tools and systems mentioned publicly
   - GitHub repositories and project names

4. Technology & Tools
   - Specific technologies, frameworks, and tools they use
   - Programming languages mentioned in job postings
   - Cloud providers and services
   - Third-party integrations and vendors
   - Development tools and CI/CD platforms

5. Organizational Intelligence
   - Department names and structures (HR, Finance, IT, Legal, R&D, etc.)
   - Office locations and regional branches
   - Subsidiaries and acquired companies
   - Parent company and corporate structure
   - Partnership and collaboration mentions

6. People Intelligence
   - Key executives (CEO, CTO, CISO, etc.)
   - Notable employees mentioned in press/blogs
   - Conference speakers and paper authors
   - Technical staff from GitHub/LinkedIn
   - Former employees (for historical context)

7. Industry & Compliance
   - Industry sector and specific vertical
   - Regulatory requirements (HIPAA, PCI-DSS, FERPA, SOC2, etc.)
   - Certifications and compliance standards
   - Industry-specific terminology

8. Internal Terminology
   - Common acronyms used internally
   - Project code names
   - Internal system names
   - Jargon specific to their industry/company
   - Legacy system names

9. Temporal Intelligence
   - Fiscal year patterns
   - Major events and timelines
   - Product launch dates
   - Merger/acquisition dates
   - Conference attendance and speaking events

10. Communication Patterns
    - Social media presence and handles
    - Blog and publication platforms
    - Developer community presence
    - Customer support channels

OUTPUT FORMAT:
Provide detailed intelligence in each category above.
Include specific names, emails, terms, and examples wherever possible.
Focus on ACTIONABLE linguistic intelligence that can be used to craft targeted Google dorks.
This data will be used to generate creative email-based and company-specific dork queries.`)
	}

	userPrompt = fmt.Sprintf("Conduct %s OSINT research on: %s\n\nReturn a security-focused profile packed with target-specific details (names, technologies, language/region cues) that directly inform targeted Google dorks for vulnerability discovery and asset enumeration. Avoid generic text.",
		depthDescription, target)

	// Execute research with retry logic
	maxAttempts := 3
	maxRateLimitRetries := 5
	executionMethods := []struct {
		name string
		exec func() (*exec.Cmd, error)
	}{
		{
			name: "pipe-direct",
			exec: func() (*exec.Cmd, error) {
				var args []string

				if c.AiModel != "" {

					args = []string{"--model", c.AiModel, "-p", userPrompt}

				} else {

					args = []string{"-p", userPrompt}

				}

				cmd := exec.Command("gemini-cli", args...)
				cmd.Stdin = strings.NewReader(systemInstructions)
				cmd.Env = os.Environ()
				if home, err := os.UserHomeDir(); err == nil {
					cmd.Dir = home
				}
				return cmd, nil
			},
		},
	}

	// If the combined prompt is large, avoid shell-based fallbacks to prevent ARG_MAX/shell truncation
	payloadLen := len(systemInstructions) + len(userPrompt)
	if payloadLen > 4000 {
		executionMethods = executionMethods[:1] // keep only pipe-direct
		console.Logv(c.Verbose, "[OSINT] Large prompt detected (%d bytes), using direct stdin execution only", payloadLen)
	}

	var lastErr error

	for _, method := range executionMethods {
		rateLimitRetries := 0

		for rateLimitRetries <= maxRateLimitRetries {
			if rateLimitRetries > 0 {
				console.Logv(c.Verbose, "[OSINT] Rate limit retry %d/%d", rateLimitRetries, maxRateLimitRetries)
			}

			for attempt := 1; attempt <= maxAttempts; attempt++ {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}

				cmdCtx, cmdCancel := context.WithTimeout(ctx, 90*time.Second) // Longer timeout for research

				cmd, err := method.exec()
				if err != nil {
					cmdCancel()
					continue
				}

				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr

				done := make(chan error, 1)
				go func() {
					done <- cmd.Run()
				}()

				spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
				spinIdx := 0
				ticker := time.NewTicker(100 * time.Millisecond)

				wasRateLimited := false

			selectLoop:
				for {
					select {
					case err := <-done:
						ticker.Stop()
						cmdCancel()

						if c.Verbose {
							fmt.Fprint(os.Stderr, "\r\033[K")
						}

						if err != nil {
							if cmdCtx.Err() == context.DeadlineExceeded {
								lastErr = fmt.Errorf("timeout (method: %s, attempt: %d/%d)", method.name, attempt, maxAttempts)
								console.Logv(c.Verbose, "[OSINT] %v", lastErr)
								break selectLoop
							}

							stderrStr := stderr.String()

							// Check for rate limit error
							if strings.Contains(stderrStr, "429 Too Many Requests") ||
								strings.Contains(stderrStr, "503 Service Unavailable") ||
								strings.Contains(stderrStr, "quota") ||
								strings.Contains(stderrStr, "Quota exceeded") ||
								strings.Contains(stderrStr, "overloaded") {

								retryDelay := parseRetryDelay(stderrStr)
								if retryDelay > 0 {
									console.Logv(c.Verbose, "[OSINT] Rate limited. Waiting %.1f seconds before retry...", retryDelay.Seconds())
									waitWithCountdown(ctx, retryDelay, c.Verbose)

									if ctx.Err() != nil {
										return "", ctx.Err()
									}

									wasRateLimited = true
									lastErr = fmt.Errorf("rate limited (will retry)")
									break selectLoop
								}
							}

							if !strings.Contains(stderrStr, "DeprecationWarning") && stderrStr != "" {
								lastErr = fmt.Errorf("error (method: %s): %s", method.name, stderrStr)
								console.Logv(c.Verbose, "[OSINT] %v", lastErr)
								break selectLoop
							}
						}

						output := stdout.String()
						if output == "" {
							lastErr = fmt.Errorf("empty response (method: %s)", method.name)
							console.Logv(c.Verbose, "[OSINT] %v", lastErr)
							break selectLoop
						}

						console.Logv(c.Verbose, "[OSINT] Research complete (%d bytes)", len(output))
						if c.Verbose {
							osintTag := console.ColorizeVerboseOutput("[OSINT]")
							fmt.Fprintf(os.Stderr, "%s %sResearch summary:%s\n", osintTag, console.ColorTeal, console.ColorReset)
							// Format and display the markdown output
							formattedOutput := formatMarkdownToText(output)
							// Show first 1000 chars of formatted research
							preview := formattedOutput
							if len(preview) > 1000 {
								preview = preview[:1000] + "..."
							}
							fmt.Fprintf(os.Stderr, "%s\n\n", preview)
						}

						// Save research for future runs
						if !c.FlushMode {
							saveResearchCache(target, c.ResearchDepth, output)
						}

						return output, nil

					case <-ticker.C:
						if c.Verbose {
							spinnerChar := console.ColorizeSpinner(spinner[spinIdx%len(spinner)])
							osintTag := console.ColorizeVerboseOutput("[OSINT]")
							fmt.Fprintf(os.Stderr, "\r%s %s Conducting research on %s...", osintTag, spinnerChar, target)
							spinIdx++
						}
					}
				}

				ticker.Stop()
				cmdCancel()

				if wasRateLimited {
					rateLimitRetries++
					console.Logv(c.Verbose, "[OSINT] Retrying after cooldown...")
					break
				}

				if attempt < maxAttempts {
					time.Sleep(time.Second)
				}
			}

			if rateLimitRetries == 0 || rateLimitRetries > maxRateLimitRetries {
				break
			}
		}

		if rateLimitRetries > maxRateLimitRetries {
			lastErr = fmt.Errorf("exceeded rate limit retries (%d attempts)", maxRateLimitRetries)
		}
	}

	return "", fmt.Errorf("gemini-cli research failed after all attempts. Last error: %v", lastErr)
}

// mergeLinguisticIntelligence merges existing and new linguistic intelligence
func mergeLinguisticIntelligence(existing, new *core.LinguisticIntelligence) *core.LinguisticIntelligence {
	merged := &core.LinguisticIntelligence{
		EmailDomain:   new.EmailDomain,
		InternalTerms: make(map[string]string),
	}

	// Merge project names (unique)
	projectMap := make(map[string]bool)
	for _, p := range existing.ProjectNames {
		projectMap[p] = true
	}
	for _, p := range new.ProjectNames {
		projectMap[p] = true
	}
	for p := range projectMap {
		merged.ProjectNames = append(merged.ProjectNames, p)
	}

	// Merge product names (unique)
	productMap := make(map[string]bool)
	for _, p := range existing.ProductNames {
		productMap[p] = true
	}
	for _, p := range new.ProductNames {
		productMap[p] = true
	}
	for p := range productMap {
		merged.ProductNames = append(merged.ProductNames, p)
	}

	// Merge department terms (unique)
	deptMap := make(map[string]bool)
	for _, d := range existing.DepartmentTerms {
		deptMap[d] = true
	}
	for _, d := range new.DepartmentTerms {
		deptMap[d] = true
	}
	for d := range deptMap {
		merged.DepartmentTerms = append(merged.DepartmentTerms, d)
	}

	// Merge technologies (unique)
	techMap := make(map[string]bool)
	for _, t := range existing.Technologies {
		techMap[t] = true
	}
	for _, t := range new.Technologies {
		techMap[t] = true
	}
	for t := range techMap {
		merged.Technologies = append(merged.Technologies, t)
	}

	// Merge employee names (unique)
	empMap := make(map[string]bool)
	for _, e := range existing.EmployeeNames {
		empMap[e] = true
	}
	for _, e := range new.EmployeeNames {
		empMap[e] = true
	}
	for e := range empMap {
		merged.EmployeeNames = append(merged.EmployeeNames, e)
	}

	// Merge subsidiaries (unique)
	subMap := make(map[string]bool)
	for _, s := range existing.Subsidiaries {
		subMap[s] = true
	}
	for _, s := range new.Subsidiaries {
		subMap[s] = true
	}
	for s := range subMap {
		merged.Subsidiaries = append(merged.Subsidiaries, s)
	}

	// Merge partnerships (unique)
	partMap := make(map[string]bool)
	for _, p := range existing.Partnerships {
		partMap[p] = true
	}
	for _, p := range new.Partnerships {
		partMap[p] = true
	}
	for p := range partMap {
		merged.Partnerships = append(merged.Partnerships, p)
	}

	// Merge acquisitions (unique)
	acqMap := make(map[string]bool)
	for _, a := range existing.Acquisitions {
		acqMap[a] = true
	}
	for _, a := range new.Acquisitions {
		acqMap[a] = true
	}
	for a := range acqMap {
		merged.Acquisitions = append(merged.Acquisitions, a)
	}

	// Merge locations (unique)
	locMap := make(map[string]bool)
	for _, l := range existing.Locations {
		locMap[l] = true
	}
	for _, l := range new.Locations {
		locMap[l] = true
	}
	for l := range locMap {
		merged.Locations = append(merged.Locations, l)
	}

	// Merge jargon (unique)
	jargonMap := make(map[string]bool)
	for _, j := range existing.Jargon {
		jargonMap[j] = true
	}
	for _, j := range new.Jargon {
		jargonMap[j] = true
	}
	for j := range jargonMap {
		merged.Jargon = append(merged.Jargon, j)
	}

	// Merge internal terms (new values override existing)
	for k, v := range existing.InternalTerms {
		merged.InternalTerms[k] = v
	}
	for k, v := range new.InternalTerms {
		merged.InternalTerms[k] = v
	}

	// Use new industry if it exists, otherwise use existing
	if new.Industry != "" {
		merged.Industry = new.Industry
	} else {
		merged.Industry = existing.Industry
	}

	return merged
}

// extractLinguisticIntelligence extracts company-specific terminology from research data
// ENHANCED: Comprehensive pattern extraction for maximum secret discovery
func extractLinguisticIntelligence(target string, researchData string) *core.LinguisticIntelligence {
	intel := &core.LinguisticIntelligence{
		EmailDomain:     fmt.Sprintf("@%s", target),
		ProjectNames:    make([]string, 0),
		DepartmentTerms: []string{"hr", "payroll", "finance", "legal", "admin", "sales", "marketing", "engineering", "it", "security", "compliance"},
		Jargon:          make([]string, 0),
		ProductNames:    make([]string, 0),
		Subsidiaries:    make([]string, 0),
		Technologies:    make([]string, 0),
		EmployeeNames:   make([]string, 0),
		InternalTerms:   make(map[string]string),
		Acquisitions:    make([]string, 0),
		Partnerships:    make([]string, 0),
		Locations:       make([]string, 0),
	}

	researchLower := strings.ToLower(researchData)

	// Extract project names (look for quoted project names or "Project X" patterns)
	projectPatterns := []string{
		`"Project\s+(\w+)"`,
		`"([A-Z][a-z]+\s+Initiative)"`,
		`"([A-Z][a-z]+\s+Program)"`,
		`product:\s*([A-Za-z0-9]+)`,
		`platform:\s*([A-Za-z0-9]+)`,
	}
	for _, pattern := range projectPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(researchData, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				intel.ProjectNames = append(intel.ProjectNames, match[1])
			}
		}
	}

	// Extract product names (common indicators)
	productKeywords := []string{"product", "platform", "service", "application", "system"}
	for _, keyword := range productKeywords {
		idx := strings.Index(researchLower, keyword+":")
		if idx >= 0 {
			// Extract text after keyword
			text := researchData[idx:]
			endIdx := strings.IndexAny(text, "\n.")
			if endIdx > 0 {
				productText := text[len(keyword)+1 : endIdx]
				productText = strings.TrimSpace(productText)
				if len(productText) > 2 && len(productText) < 50 {
					intel.ProductNames = append(intel.ProductNames, productText)
				}
			}
		}
	}

	// Extract subsidiary companies (look for "acquired", "subsidiary", "owns")
	subsidiaryKeywords := []string{"acquired", "subsidiary", "owns", "daughter company"}
	for _, keyword := range subsidiaryKeywords {
		idx := strings.Index(researchLower, keyword)
		if idx >= 0 {
			// Look for capitalized words nearby (likely company names)
			windowStart := max(0, idx-50)
			windowEnd := min(len(researchData), idx+100)
			window := researchData[windowStart:windowEnd]

			// Find capitalized words (potential company names)
			re := regexp.MustCompile(`[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*`)
			matches := re.FindAllString(window, -1)
			for _, match := range matches {
				if len(match) > 3 && !strings.Contains(strings.ToLower(match), keyword) {
					intel.Subsidiaries = append(intel.Subsidiaries, match)
					intel.Acquisitions = append(intel.Acquisitions, match)
				}
			}
		}
	}

	// Extract technologies mentioned in research
	techKeywords := []string{
		"wordpress", "drupal", "joomla", "laravel", "django", "rails", "flask",
		"react", "angular", "vue", "next.js", "nuxt", "asp.net", "spring",
		"aws", "azure", "gcp", "google cloud", "amazon web services",
		"kubernetes", "docker", "jenkins", "gitlab", "github",
		"mysql", "postgresql", "mongodb", "redis", "elasticsearch",
		"apache", "nginx", "iis", "tomcat",
		"salesforce", "sap", "oracle", "workday",
	}
	for _, tech := range techKeywords {
		if strings.Contains(researchLower, tech) {
			intel.Technologies = append(intel.Technologies, tech)
		}
	}

	// Detect industry from research keywords
	industryPatterns := map[string][]string{
		"healthcare": {"healthcare", "hospital", "medical", "patient", "clinic", "hipaa", "phi", "ehr", "emr"},
		"finance":    {"bank", "financial", "fintech", "payment", "credit", "trading", "investment", "pci", "pci-dss"},
		"ecommerce":  {"ecommerce", "e-commerce", "retail", "shop", "store", "merchant", "cart", "checkout"},
		"education":  {"education", "university", "school", "student", "learning", "ferpa", "academic"},
		"government": {"government", "federal", "state", "municipal", "public sector", "gov", ".gov"},
		"technology": {"software", "saas", "cloud", "tech", "startup", "platform", "api"},
		"legal":      {"law firm", "legal", "attorney", "lawyer", "court", "litigation"},
	}
	for industry, keywords := range industryPatterns {
		for _, keyword := range keywords {
			if strings.Contains(researchLower, keyword) {
				intel.Industry = industry
				break
			}
		}
		if intel.Industry != "" {
			break
		}
	}

	// Extract partnership mentions
	partnerKeywords := []string{"partner", "partnership", "collaboration", "integration with"}
	for _, keyword := range partnerKeywords {
		idx := strings.Index(researchLower, keyword)
		if idx >= 0 {
			windowStart := max(0, idx-30)
			windowEnd := min(len(researchData), idx+80)
			window := researchData[windowStart:windowEnd]

			re := regexp.MustCompile(`[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*`)
			matches := re.FindAllString(window, -1)
			for _, match := range matches {
				if len(match) > 3 {
					intel.Partnerships = append(intel.Partnerships, match)
				}
			}
		}
	}

	// Extract location information
	locationKeywords := []string{"headquarters", "office", "data center", "datacenter", "facility", "campus"}
	for _, keyword := range locationKeywords {
		idx := strings.Index(researchLower, keyword)
		if idx >= 0 {
			windowStart := max(0, idx-10)
			windowEnd := min(len(researchData), idx+100)
			window := researchData[windowStart:windowEnd]

			// Look for city/state/country names (capitalized)
			re := regexp.MustCompile(`(?:in|at|located|based in)\s+([A-Z][a-z]+(?:,?\s+[A-Z][a-z]+)*)`)
			matches := re.FindStringSubmatch(window)
			if len(matches) > 1 {
				intel.Locations = append(intel.Locations, matches[1])
			}
		}
	}

	// Extract internal terminology patterns
	// Look for "refers to X as Y" or "calls customers 'members'"
	terminologyPatterns := []string{
		`(?:refers? to|calls?)\s+(\w+)\s+(?:as|'|")([^'"]+)['"]`,
		`(?:known as|also called)\s+["']?([^'"]+)["']?`,
	}
	for _, pattern := range terminologyPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(researchData, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				standard := strings.ToLower(strings.TrimSpace(match[1]))
				custom := strings.ToLower(strings.TrimSpace(match[2]))
				if len(standard) > 2 && len(custom) > 2 {
					intel.InternalTerms[standard] = custom
				}
			}
		}
	}

	// Extract employee name patterns (for directory searches)
	employeePatterns := []string{
		`(?:CEO|CTO|CFO|CISO|VP|Director|Manager):\s+([A-Z][a-z]+\s+[A-Z][a-z]+)`,
		`(?:founded by|led by|headed by)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)`,
	}
	for _, pattern := range employeePatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(researchData, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				intel.EmployeeNames = append(intel.EmployeeNames, match[1])
			}
		}
	}

	return intel
}

// generateLinguisticDorks generates dorks based on linguistic intelligence
// ENHANCED: Maximized for finding secrets with company-specific patterns (quota-friendly - no API calls)
func (c *Config) generateLinguisticDorks(target string, intel *core.LinguisticIntelligence) []string {
	var dorks []string

	console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Generating maximized company-specific dorks...")

	// === EMAIL-BASED DORKS (High-Value Secret Discovery) ===
	dorks = append(dorks,
		// Documents with company emails
		fmt.Sprintf("site:%s (ext:pdf OR ext:doc OR ext:docx) intext:\"%s\" (intext:Confidential OR intext:\"Internal Only\" OR intext:Restricted)",
			target, intel.EmailDomain),
		// Spreadsheets with employee data
		fmt.Sprintf("site:%s (ext:xls OR ext:xlsx OR ext:csv) intext:\"%s\" (intext:salary OR intext:ssn OR intext:password)",
			target, intel.EmailDomain),
		// Staff directories
		fmt.Sprintf("site:%s intext:\"%s\" (intext:\"employee directory\" OR intext:\"staff list\" OR intext:\"contact list\")",
			target, intel.EmailDomain),
		// Email in credentials/configs
		fmt.Sprintf("site:%s (ext:txt OR ext:log OR ext:conf) intext:\"%s\" (intext:password OR intext:credentials)",
			target, intel.EmailDomain),
	)

	// === PROJECT-BASED DORKS ===
	for _, project := range intel.ProjectNames {
		if len(project) > 2 {
			projectLower := strings.ToLower(strings.ReplaceAll(project, " ", "-"))
			dorks = append(dorks,
				// Project documentation
				fmt.Sprintf("site:%s intext:\"%s\" (ext:pdf OR ext:doc OR ext:ppt OR ext:pptx)", target, project),
				// Project in URLs (internal systems)
				fmt.Sprintf("site:%s inurl:%s (intext:admin OR intext:dashboard OR intext:internal)", target, projectLower),
				// Project configurations
				fmt.Sprintf("site:%s (inurl:%s OR intext:\"%s\") (ext:json OR ext:xml OR ext:yml)", target, projectLower, project),
				// Project credentials
				fmt.Sprintf("site:%s intext:\"%s\" (intext:api_key OR intext:token OR intext:secret)", target, project),
			)
		}
	}

	// === PRODUCT/SERVICE-BASED DORKS ===
	for _, product := range intel.ProductNames {
		if len(product) > 2 {
			productLower := strings.ToLower(strings.ReplaceAll(product, " ", "-"))
			dorks = append(dorks,
				// Product API documentation
				fmt.Sprintf("site:%s intext:\"%s\" (inurl:api OR inurl:docs OR inurl:swagger)", target, product),
				// Product configuration files
				fmt.Sprintf("site:%s inurl:%s (ext:json OR ext:xml OR ext:yaml OR ext:conf)", target, productLower),
				// Product manuals/guides
				fmt.Sprintf("site:%s intext:\"%s\" (intext:manual OR intext:guide OR intext:documentation)", target, product),
			)
		}
	}

	// === TECHNOLOGY-SPECIFIC DORKS ===
	for _, tech := range intel.Technologies {
		techLower := strings.ToLower(tech)
		switch {
		case strings.Contains(techLower, "wordpress"):
			dorks = append(dorks, fmt.Sprintf("site:%s inurl:wp-config", target))
		case strings.Contains(techLower, "laravel"):
			dorks = append(dorks, fmt.Sprintf("site:%s (inurl:.env OR inurl:telescope)", target))
		case strings.Contains(techLower, "aws"):
			dorks = append(dorks,
				fmt.Sprintf("site:%s (intext:\"aws_access_key\" OR intext:\"aws_secret\")", target),
				fmt.Sprintf("site:%s intext:\"s3.amazonaws.com\" (ext:txt OR ext:log)", target),
			)
		case strings.Contains(techLower, "azure"):
			dorks = append(dorks, fmt.Sprintf("site:%s (intext:\"azure\" OR intext:\"blob.core.windows\") (intext:key OR intext:token)", target))
		case strings.Contains(techLower, "salesforce"):
			dorks = append(dorks, fmt.Sprintf("site:%s intext:\"salesforce\" (intext:token OR intext:api OR intext:oauth)", target))
		}
	}

	// === INDUSTRY-SPECIFIC DORKS ===
	switch intel.Industry {
	case "healthcare":
		dorks = append(dorks,
			fmt.Sprintf("site:%s (intext:patient OR intext:medical OR intext:phi) (ext:xls OR ext:xlsx OR ext:csv)", target),
			fmt.Sprintf("site:%s (intext:hipaa OR intext:ehr OR intext:emr) (ext:pdf OR ext:doc)", target),
			fmt.Sprintf("site:%s (inurl:patient OR inurl:medical) (intext:ssn OR intext:dob OR intext:diagnosis)", target),
		)
	case "finance":
		dorks = append(dorks,
			fmt.Sprintf("site:%s (intext:\"credit card\" OR intext:\"account number\" OR intext:\"routing number\") (ext:xls OR ext:csv)", target),
			fmt.Sprintf("site:%s (intext:pci OR intext:\"payment card\") (ext:pdf OR ext:doc)", target),
			fmt.Sprintf("site:%s (inurl:transaction OR inurl:payment) (intext:amount OR intext:balance)", target),
		)
	case "education":
		dorks = append(dorks,
			fmt.Sprintf("site:%s (intext:student OR intext:grade OR intext:ferpa) (ext:xls OR ext:xlsx)", target),
			fmt.Sprintf("site:%s (inurl:student OR inurl:enrollment) (intext:ssn OR intext:dob)", target),
		)
	case "government":
		dorks = append(dorks,
			fmt.Sprintf("site:%s (intext:\"classified\" OR intext:\"official use only\" OR intext:\"for official use\") ext:pdf", target),
			fmt.Sprintf("site:%s (intext:clearance OR intext:\"security clearance\") ext:doc", target),
		)
	}

	// === DEPARTMENT DORKS (High-Value Targets) ===
	sensitiveDepts := fmt.Sprintf("site:%s (ext:xls OR ext:xlsx OR ext:csv) (inurl:hr OR inurl:payroll OR inurl:finance OR inurl:legal)", target)
	dorks = append(dorks, sensitiveDepts)

	for _, dept := range intel.DepartmentTerms {
		dorks = append(dorks,
			// Department files with potential PII
			fmt.Sprintf("site:%s (inurl:%s OR intext:\"%s\") (ext:xls OR ext:xlsx) (intext:ssn OR intext:salary OR intext:employee)", target, dept, dept),
			// Department documents
			fmt.Sprintf("site:%s (inurl:%s OR intext:\"%s\") (ext:pdf OR ext:doc) (intext:confidential OR intext:internal)", target, dept, dept),
		)
	}

	// === SUBSIDIARY & ACQUISITION DORKS ===
	for _, subsidiary := range intel.Subsidiaries {
		if len(subsidiary) > 3 {
			dorks = append(dorks,
				// Merger/acquisition documents
				fmt.Sprintf("site:%s intext:\"%s\" (intext:acquisition OR intext:merger OR intext:agreement) ext:pdf", target, subsidiary),
				// Financial documents
				fmt.Sprintf("site:%s intext:\"%s\" (intext:financial OR intext:revenue OR intext:valuation)", target, subsidiary),
			)
		}
	}

	// === PARTNERSHIP DORKS ===
	for _, partner := range intel.Partnerships {
		if len(partner) > 3 {
			dorks = append(dorks,
				fmt.Sprintf("site:%s intext:\"%s\" (intext:partnership OR intext:agreement OR intext:contract)", target, partner),
				fmt.Sprintf("site:%s intext:\"%s\" (intext:integration OR intext:api OR intext:credentials)", target, partner),
			)
		}
	}

	// === LOCATION-BASED DORKS ===
	for _, location := range intel.Locations {
		if len(location) > 3 {
			dorks = append(dorks,
				fmt.Sprintf("site:%s intext:\"%s\" (intext:office OR intext:facility OR intext:address)", target, location),
			)
		}
	}

	// === INTERNAL TERMINOLOGY DORKS ===
	for _, custom := range intel.InternalTerms {
		// Use company's custom terminology to find internal documents
		dorks = append(dorks,
			fmt.Sprintf("site:%s intext:\"%s\" (ext:pdf OR ext:doc OR ext:xls)", target, custom),
		)
	}

	// === EMPLOYEE NAME DORKS (Staff Directories) ===
	for _, employee := range intel.EmployeeNames {
		if len(employee) > 5 {
			// Search for directories containing known executives
			dorks = append(dorks,
				fmt.Sprintf("site:%s intext:\"%s\" (intext:directory OR intext:contact OR intext:email)", target, employee),
			)
		}
	}

	// === GENERIC HIGH-VALUE DORKS ===
	dorks = append(dorks,
		// Credentials & secrets
		fmt.Sprintf("site:%s (ext:txt OR ext:log) (intext:password OR intext:pwd OR intext:passwd)", target),
		fmt.Sprintf("site:%s (ext:env OR ext:ini OR ext:conf) (intext:secret OR intext:api_key OR intext:token)", target),

		// Database files
		fmt.Sprintf("site:%s (ext:sql OR ext:db OR ext:dump) (intext:INSERT OR intext:CREATE TABLE)", target),

		// Backup files
		fmt.Sprintf("site:%s (inurl:backup OR inurl:backups OR inurl:bak) (ext:zip OR ext:tar OR ext:gz OR ext:sql)", target),

		// Private documents
		fmt.Sprintf("site:%s (ext:doc OR ext:docx OR ext:pdf) (intext:\"not for distribution\" OR intext:\"do not share\" OR intext:\"confidential\")", target),

		// Meeting notes & presentations
		fmt.Sprintf("site:%s (ext:ppt OR ext:pptx OR ext:pdf) (intext:\"internal only\" OR intext:\"confidential\" OR intext:\"restricted\")", target),

		// Source code leaks
		fmt.Sprintf("site:%s (ext:py OR ext:java OR ext:php OR ext:rb) (intext:password OR intext:api_key OR intext:secret)", target),

		// Configuration files
		fmt.Sprintf("site:%s (inurl:config OR inurl:configuration OR inurl:settings) (ext:json OR ext:xml OR ext:yml OR ext:ini)", target),
	)

	// Deduplicate dorks
	dorks = removeDuplicates(dorks)

	console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Generated %d maximized company-specific dorks", len(dorks))

	// Show breakdown if verbose
	if c.Verbose {
		console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Intelligence extracted:")
		console.Logv(c.Verbose, "  - Projects: %d", len(intel.ProjectNames))
		console.Logv(c.Verbose, "  - Products: %d", len(intel.ProductNames))
		console.Logv(c.Verbose, "  - Technologies: %d", len(intel.Technologies))
		console.Logv(c.Verbose, "  - Subsidiaries: %d", len(intel.Subsidiaries))
		console.Logv(c.Verbose, "  - Partnerships: %d", len(intel.Partnerships))
		console.Logv(c.Verbose, "  - Locations: %d", len(intel.Locations))
		console.Logv(c.Verbose, "  - Employees: %d", len(intel.EmployeeNames))
		if intel.Industry != "" {
			console.Logv(c.Verbose, "  - Industry: %s", intel.Industry)
		}
	}

	return dorks
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// generateResearchBasedDorks generates specialized dorks based on OSINT research
// ENHANCED: Now includes linguistic and organizational intelligence
func (c *Config) generateResearchBasedDorks(ctx context.Context, target string, researchData string) ([]string, error) {
	// Check if gemini-cli is installed
	if err := checkGeminiCLI(); err != nil {
		return nil, err
	}

	// Validate quantity
	if c.AiQuantity < 1 {
		c.AiQuantity = 1
	}
	if c.AiQuantity > 50 {
		c.AiQuantity = 50
	}

	console.Logv(c.Verbose, "[OSINT] Generating %d research-based dorks...", c.AiQuantity)

	// Build specialized system instructions
	systemInstructions := fmt.Sprintf(`You are a Google dorking expert specializing in targeted security reconnaissance.
You have been provided with OSINT research data about a target. Your task is to generate HIGHLY SPECIALIZED and TARGETED Google dorks based on this research.

OSINT RESEARCH DATA:
%s

CRITICAL OUTPUT RULES:
1. Output ONLY dorks, one per line
2. NO explanations, NO numbering, NO markdown, NO extra text
3. Each dork MUST start with: site:%s
4. Use OR (not |) for alternatives inside parentheses
5. Use ONLY ONE set of parentheses for OR groups
6. Generate dorks that are SPECIFICALLY tailored to the research data above

DORK GENERATION STRATEGY:
Based on the OSINT research above, create dorks that Target:

1. Known Vulnerabilities & CVEs
   - If CVEs mentioned: search for vulnerability-specific patterns
   - If breach history: search for exposed data related to past breaches
   - If bug bounty reports: target similar vulnerability classes
   - CRITICAL: When searching for CVEs, target the VULNERABLE COMPONENT, not the CVE number
   - NEVER generate lazy dorks like intext:"CVE-2025-55182" - that's useless!
   - If user asks for specific CVE/vulnerability names, target the actual vulnerable patterns:
     * react2shell (CVE-2025-55182): inurl:"_next/static" OR inurl:"/_next/" OR intext:"Next.js"
     * log4shell (CVE-2021-44228): intext:"${jndi:" OR inurl:log4j OR intext:"org.apache.logging.log4j"
     * spring4shell (CVE-2022-22965): inurl:"/actuator/" OR inurl:"spring" intext:"error"
     * heartbleed (CVE-2014-0160): intext:"OpenSSL/1.0.1" OR intext:"heartbeat"
     * ProxyShell (CVE-2021-34473): inurl:"/autodiscover/" OR inurl:"/ews/" OR inurl:"/mapi/"
     * ProxyLogon (CVE-2021-26855): inurl:"/owa/auth/" OR inurl:"/ecp/"
     * GraphQL introspection: inurl:"/graphql" OR inurl:"/graphiql" OR intext:"__schema"
     * Path Traversal: inurl:"../" OR inurl:"..../" OR inurl:"..%2f"
     * Kubernetes exposure: inurl:"/api/v1/" OR inurl:"/metrics" intext:"kubernetes"

2. Technology Stack Exploitation
   - Target specific technologies mentioned in research
   - Search for config files specific to their stack
   - Look for version-specific vulnerabilities
   - Target known misconfigurations for their frameworks

3. Company-Specific Assets
   - Use company naming patterns from research
   - Target specific products/services mentioned
   - Search for industry-specific documents
   - Look for subsidiary or acquisition-related assets

4. Historical Weakness Patterns
   - If past incidents mentioned: create dorks to find similar issues
   - Target authentication mechanisms mentioned in research
   - Search for exposed assets specific to their infrastructure
   - Look for third-party integrations mentioned

5. Industry & Sector-Specific
   - Create dorks relevant to their industry/sector
   - Target compliance documents (if regulated industry)
   - Search for industry-specific sensitive files
   - Look for sector-typical misconfigurations

QUALITY REQUIREMENTS:
- Every dork MUST be based on specific information from the OSINT research
- Avoid generic dorks - make them targeted and specific
- Weave in unique names/terms from research (products, project code names, subsidiaries, executives, internal tools)
- When possible, anchor text with industry-specific jargon or document types mentioned in research
- Combine multiple operators creatively
- Focus on the target's known weaknesses and assets
- Prioritize dorks that target disclosed vulnerabilities or known issues

PARENTHESES RULES:
- Group OR expressions: (operator1 OR operator2 OR operator3)
- NO nested parentheses
- Date operators go OUTSIDE parentheses

CORRECT FORMAT EXAMPLES:
site:%s (inurl:admin OR inurl:dashboard OR inurl:panel)
site:%s (filetype:env OR filetype:config) intext:"database"
site:%s inurl:api (filetype:json OR filetype:yaml)
site:%s (inurl:? inurl:id= OR inurl:? inurl:page=) intext:"error"
site:%s inurl:? inurl:& (intext:"sql" OR intext:"mysql")

Generate EXACTLY %d highly targeted dorks based on the OSINT research. Output only the dorks, nothing else.`,
		researchData, target, target, target, target, target, target, c.AiQuantity)

	// Include user's AI prompt if provided (for CVE-specific requests)
	userGoal := "their specific vulnerabilities, technologies, and weaknesses"
	if c.AiPrompt != "" {
		userGoal = fmt.Sprintf("%s (User Goal: %s)", userGoal, c.AiPrompt)
	}
	userPrompt := fmt.Sprintf("Based on the OSINT research provided, generate %d highly specialized Google dorks for site:%s that target %s.",
		c.AiQuantity, target, userGoal)

	// Execute dork generation with retry logic
	maxAttempts := 3
	maxRateLimitRetries := 5
	executionMethods := []struct {
		name string
		exec func() (*exec.Cmd, error)
	}{
		{
			name: "pipe-direct",
			exec: func() (*exec.Cmd, error) {
				var args []string

				if c.AiModel != "" {

					args = []string{"--model", c.AiModel, "-p", userPrompt}

				} else {

					args = []string{"-p", userPrompt}

				}

				cmd := exec.Command("gemini-cli", args...)
				cmd.Stdin = strings.NewReader(systemInstructions)
				cmd.Env = os.Environ()
				if home, err := os.UserHomeDir(); err == nil {
					cmd.Dir = home
				}
				return cmd, nil
			},
		},
		{
			name: "pipe-bash",
			exec: func() (*exec.Cmd, error) {
				var bashCmd string

				if c.AiModel != "" {

					bashCmd = fmt.Sprintf("echo %s | gemini-cli --model %s -p %s",

						shellescape(systemInstructions),

						shellescape(c.AiModel),

						shellescape(userPrompt))

				} else {

					bashCmd = fmt.Sprintf("echo %s | gemini-cli -p %s",

						shellescape(systemInstructions),

						shellescape(userPrompt))

				}
				cmd := exec.Command("bash", "-c", bashCmd)
				cmd.Env = os.Environ()
				if home, err := os.UserHomeDir(); err == nil {
					cmd.Dir = home
				}
				return cmd, nil
			},
		},
		{
			name: "pipe-sh",
			exec: func() (*exec.Cmd, error) {
				var shCmd string

				if c.AiModel != "" {

					shCmd = fmt.Sprintf("echo %s | gemini-cli --model %s -p %s",

						shellescape(systemInstructions),

						shellescape(c.AiModel),

						shellescape(userPrompt))

				} else {

					shCmd = fmt.Sprintf("echo %s | gemini-cli -p %s",

						shellescape(systemInstructions),

						shellescape(userPrompt))

				}
				cmd := exec.Command("sh", "-c", shCmd)
				cmd.Env = os.Environ()
				if home, err := os.UserHomeDir(); err == nil {
					cmd.Dir = home
				}
				return cmd, nil
			},
		},
	}

	var lastErr error

	for _, method := range executionMethods {
		rateLimitRetries := 0

		for rateLimitRetries <= maxRateLimitRetries {
			if rateLimitRetries > 0 {
				console.Logv(c.Verbose, "[OSINT] Rate limit retry %d/%d", rateLimitRetries, maxRateLimitRetries)
			}

			for attempt := 1; attempt <= maxAttempts; attempt++ {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}

				cmdCtx, cmdCancel := context.WithTimeout(ctx, 60*time.Second)

				cmd, err := method.exec()
				if err != nil {
					cmdCancel()
					continue
				}

				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr

				done := make(chan error, 1)
				go func() {
					done <- cmd.Run()
				}()

				spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
				spinIdx := 0
				ticker := time.NewTicker(100 * time.Millisecond)

				wasRateLimited := false

			selectLoop:
				for {
					select {
					case err := <-done:
						ticker.Stop()
						cmdCancel()

						if c.Verbose {
							fmt.Fprint(os.Stderr, "\r\033[K")
						}

						if err != nil {
							if cmdCtx.Err() == context.DeadlineExceeded {
								lastErr = fmt.Errorf("timeout (method: %s, attempt: %d/%d)", method.name, attempt, maxAttempts)
								console.Logv(c.Verbose, "[OSINT] %v", lastErr)
								break selectLoop
							}

							stderrStr := stderr.String()

							// Check for rate limit error
							if strings.Contains(stderrStr, "429 Too Many Requests") ||
								strings.Contains(stderrStr, "503 Service Unavailable") ||
								strings.Contains(stderrStr, "quota") ||
								strings.Contains(stderrStr, "Quota exceeded") ||
								strings.Contains(stderrStr, "overloaded") {

								retryDelay := parseRetryDelay(stderrStr)
								if retryDelay > 0 {
									console.Logv(c.Verbose, "[OSINT] Rate limited. Waiting %.1f seconds before retry...", retryDelay.Seconds())
									waitWithCountdown(ctx, retryDelay, c.Verbose)

									if ctx.Err() != nil {
										return nil, ctx.Err()
									}

									wasRateLimited = true
									lastErr = fmt.Errorf("rate limited (will retry)")
									break selectLoop
								}
							}

							if !strings.Contains(stderrStr, "DeprecationWarning") && stderrStr != "" {
								lastErr = fmt.Errorf("error (method: %s): %s", method.name, stderrStr)
								console.Logv(c.Verbose, "[OSINT] %v", lastErr)
								break selectLoop
							}
						}

						output := stdout.String()
						if output == "" {
							lastErr = fmt.Errorf("empty response (method: %s)", method.name)
							console.Logv(c.Verbose, "[OSINT] %v", lastErr)
							break selectLoop
						}

						console.Logv(c.Verbose, "[OSINT] Received dork response (%d bytes)", len(output))

						lines := strings.Split(output, "\n")
						var dorks []string

						for _, line := range lines {
							line = strings.TrimSpace(line)

							if line == "" ||
								strings.HasPrefix(line, "```") ||
								strings.HasPrefix(line, "#") ||
								strings.Contains(strings.ToLower(line), "here are") ||
								strings.Contains(strings.ToLower(line), "here is") ||
								strings.Contains(strings.ToLower(line), "i've generated") {
								continue
							}

							line = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(line, "")
							line = regexp.MustCompile(`^[-*•]\s*`).ReplaceAllString(line, "")
							line = strings.TrimSpace(line)

							line = fixDorkSyntax(line)
							line = cleanNestedParentheses(line)
							line = improveDorkSyntax(line)

							// Apply subdomain-only filter if -a flag is set
							if c.IncludeSubdomains {
								line = applySubdomainOnlyFilter(line, c.Target)
							}

							if strings.Contains(line, "site:") {
								dorks = append(dorks, line)
							}
						}

						if len(dorks) == 0 {
							lastErr = fmt.Errorf("no valid dorks in output")
							if c.Verbose {
								console.Logv(c.Verbose, "[OSINT] %v. Raw output:\n%s", lastErr, output)
							}
							break selectLoop
						}

						if len(dorks) > c.AiQuantity {
							dorks = dorks[:c.AiQuantity]
						}

						console.Logv(c.Verbose, "[OSINT] Generated %d research-based dorks", len(dorks))

						// Always start with AI dorks; optionally add linguistic intelligence at depth 4
						allDorks := dorks

						if c.ResearchDepth >= 4 {
							// ENHANCED: Extract linguistic and organizational intelligence
							// First, try to load existing linguistic intelligence
							existingIntel := loadLinguisticIntelligence(target)

							linguisticIntel := extractLinguisticIntelligence(target, researchData)

							// Merge with existing intelligence if available
							if existingIntel != nil {
								console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Loaded existing linguistic intelligence, merging...")
								linguisticIntel = mergeLinguisticIntelligence(existingIntel, linguisticIntel)
							}

							// Save linguistic intelligence for future use
							if err := saveLinguisticIntelligence(target, linguisticIntel); err != nil {
								console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Warning: Failed to save linguistic Intelligence: %v", err)
							} else {
								console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Saved linguistic intelligence for future researches")
							}

							// Use AI to generate creative, unique linguistic dorks
							linguisticDorks := c.generateLinguisticDorksAI(target, linguisticIntel)

							// Fallback to template-based if AI generation fails
							if len(linguisticDorks) == 0 {
								console.Logv(c.Verbose, "[LINGUISTIC-INTEL] AI generation unavailable, using template fallback")
								linguisticDorks = c.generateLinguisticDorks(target, linguisticIntel)
							}

							if len(linguisticDorks) > 0 {
								allDorks = append(allDorks, linguisticDorks...)
							}
						} else if c.Verbose {
							console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Skipping linguistic expansion (requires --research-depth 4)")
						}

						console.Logv(c.Verbose, "[OSINT] Total dorks (AI + Linguistic): %d", len(allDorks))
						if c.Verbose {
							for i, dork := range allDorks {
								if i < len(dorks) {
									fmt.Fprintf(os.Stderr, "  [AI] %d. %s\n", i+1, dork)
								} else {
									fmt.Fprintf(os.Stderr, "  [LING] %d. %s\n", i+1, dork)
								}
							}
						}

						return allDorks, nil

					case <-ticker.C:
						if c.Verbose {
							spinnerChar := console.ColorizeSpinner(spinner[spinIdx%len(spinner)])
							osintTag := console.ColorizeVerboseOutput("[OSINT]")
							fmt.Fprintf(os.Stderr, "\r%s %s Generating research-based dorks...", osintTag, spinnerChar)
							spinIdx++
						}
					}
				}

				ticker.Stop()
				cmdCancel()

				if wasRateLimited {
					rateLimitRetries++
					console.Logv(c.Verbose, "[OSINT] Retrying after cooldown...")
					break
				}

				if attempt < maxAttempts {
					time.Sleep(time.Second)
				}
			}

			if rateLimitRetries == 0 || rateLimitRetries > maxRateLimitRetries {
				break
			}
		}

		if rateLimitRetries > maxRateLimitRetries {
			lastErr = fmt.Errorf("exceeded rate limit retries (%d attempts)", maxRateLimitRetries)
		}
	}

	return nil, fmt.Errorf("gemini-cli dork generation failed after all attempts. Last error: %v", lastErr)
}
