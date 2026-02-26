package ai

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// generateLinguisticDorks generates dorks based on linguistic intelligence
// ENHANCED: AI-powered creative dork generation using company-specific intelligence
func (c *Config) generateLinguisticDorksAI(target string, intel *core.LinguisticIntelligence) []string {
	var dorks []string

	console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Using AI to generate creative company-specific dorks...")

	// Build intelligence context for AI
	var intelContext strings.Builder
	intelContext.WriteString("COMPANY INTELLIGENCE EXTRACTED:\n\n")

	if intel.EmailDomain != "" {
		intelContext.WriteString(fmt.Sprintf("Email Domain: %s\n", intel.EmailDomain))
	}

	if len(intel.ProjectNames) > 0 {
		intelContext.WriteString(fmt.Sprintf("Projects: %s\n", strings.Join(intel.ProjectNames, ", ")))
	}

	if len(intel.ProductNames) > 0 {
		intelContext.WriteString(fmt.Sprintf("Products/Services: %s\n", strings.Join(intel.ProductNames, ", ")))
	}

	if len(intel.Technologies) > 0 {
		intelContext.WriteString(fmt.Sprintf("Technologies: %s\n", strings.Join(intel.Technologies, ", ")))
	}

	if intel.Industry != "" {
		intelContext.WriteString(fmt.Sprintf("Industry: %s\n", intel.Industry))
	}

	if len(intel.Subsidiaries) > 0 {
		intelContext.WriteString(fmt.Sprintf("Subsidiaries/Acquisitions: %s\n", strings.Join(intel.Subsidiaries, ", ")))
	}

	if len(intel.Partnerships) > 0 {
		intelContext.WriteString(fmt.Sprintf("Partners: %s\n", strings.Join(intel.Partnerships, ", ")))
	}

	if len(intel.Locations) > 0 {
		intelContext.WriteString(fmt.Sprintf("Locations: %s\n", strings.Join(intel.Locations, ", ")))
	}

	if len(intel.EmployeeNames) > 0 {
		intelContext.WriteString(fmt.Sprintf("Known Executives: %s\n", strings.Join(intel.EmployeeNames, ", ")))
	}

	if len(intel.InternalTerms) > 0 {
		var terms []string
		for _, v := range intel.InternalTerms {
			terms = append(terms, v)
		}
		intelContext.WriteString(fmt.Sprintf("Internal Terminology: %s\n", strings.Join(terms, ", ")))
	}

	intelContext.WriteString(fmt.Sprintf("Departments: %s\n", strings.Join(intel.DepartmentTerms, ", ")))

	// Create AI prompt for creative dork generation
	systemPrompt := fmt.Sprintf(`You are an elite Google dorking expert specializing in company-specific reconnaissance.

%s

TASK: Generate HIGHLY CREATIVE and UNIQUE Google dorks for site:%s based on this intelligence.

CRITICAL RULES:
1. Output ONLY dorks, one per line
2. NO explanations, NO numbering, NO markdown, NO extra text
3. Each dork MUST start with: site:%s
4. Use OR (not |) for alternatives inside parentheses
5. Be CREATIVE and UNIQUE - avoid obvious/generic patterns
6. Combine multiple intelligence points cleverly
7. Think like a real attacker - what secrets would be most damaging?

CREATIVE DORK CATEGORIES (Generate BALANCED mix from ALL categories):

1. PROJECT/PRODUCT-SPECIFIC DORKS (30%% of total):
   - Use actual project names from intelligence
   - Target staging/dev environments: inurl:ProjectName inurl:(staging OR dev OR test)
   - Configuration files: intext:"ProjectName" (ext:env OR ext:conf OR ext:yml)
   - API documentation: intext:"ProductName" (inurl:api OR inurl:docs) (ext:json OR ext:yaml)
   - Source code leaks: "ProductName" (inurl:github OR inurl:gitlab) (ext:java OR ext:py OR ext:js)
   - Version-specific: intext:"ProductName" intext:"version" (intext:vulnerability OR intext:exploit)
   - Internal tools: intext:"ProjectCodename" (intext:admin OR intext:dashboard)
   - Examples:
     * site:acme.com intext:"ProjectX" inurl:staging (ext:config OR ext:yml)
     * site:acme.com "AlphaProduct" inurl:api ext:json (intext:key OR intext:token)

2. TECHNOLOGY STACK EXPLOITATION (25%% of total):
   - Target specific technologies mentioned in intelligence
   - Framework configs: intext:"TechnologyName" (ext:xml OR ext:properties OR ext:ini)
   - Cloud credentials: (intext:aws OR intext:azure OR intext:gcp) (intext:access_key OR intext:secret)
   - Database configs: intext:"mysql" OR intext:"postgresql" (ext:conf OR ext:cnf) intext:password
   - CI/CD exposure: inurl:(jenkins OR gitlab OR circleci) (intext:credential OR intext:token)
   - Container configs: (intext:docker OR intext:kubernetes) (ext:yaml OR ext:yml) intext:secret
   - Examples:
     * site:acme.com intext:"Laravel" (ext:env OR ext:config) (intext:DB_PASSWORD OR intext:APP_KEY)
     * site:acme.com inurl:gitlab ext:yml (intext:aws_access_key OR intext:DOCKER_PASSWORD)

3. DEPARTMENT & ORGANIZATIONAL INTELLIGENCE (20%% of total):
   - Target specific departments: inurl:(hr OR finance OR legal OR it)
   - Subsidiary dorks: intext:"SubsidiaryName" (intext:acquisition OR intext:integration)
   - Partnership leaks: intext:"PartnerName" (intext:agreement OR intext:contract OR intext:API)
   - Location-based: intext:"OfficeName" OR intext:"CityName" (intext:budget OR intext:employee)
   - Executive Intelligence: intext:"ExecutiveName" (intext:email OR intext:phone OR intext:org)
   - Examples:
     * site:acme.com inurl:hr ext:xlsx (intext:salary OR intext:compensation) "Austin"
     * site:acme.com intext:"AcquiredCo" (intext:migration OR intext:credential OR intext:vpn)

4. EMAIL-BASED SECRETS (15%% of total):
   - Use SPARINGLY - not every dork needs email!
   - Credentials: intext:"password" intext:"@company.com" (ext:txt OR ext:log)
   - Employee lists: intext:"@company.com" (intext:directory OR intext:"employee list") ext:csv
   - Code leaks: intext:"@company.com" (ext:env OR ext:config) (intext:key OR intext:token)
   - Database dumps: intext:"@company.com" ext:sql
   - Examples:
     * site:acme.com ext:log intext:"@acme.com" (intext:exception OR intext:error) intext:password
     * site:acme.com ext:env intext:"@acme.com" (intext:DATABASE_URL OR intext:API_KEY)

5. INDUSTRY-SPECIFIC COMPLIANCE (10%% of total):
   - Use industry from intelligence
   - Healthcare: (intext:patient OR intext:PHI OR intext:HIPAA) (ext:pdf OR ext:xlsx)
   - Finance: (intext:PCI OR intext:cardholder OR intext:transaction) (ext:csv OR ext:db)
   - Education: (intext:student OR intext:FERPA OR intext:grade) (ext:xlsx OR ext:pdf)
   - Government: (intext:classified OR intext:clearance) (ext:pdf OR ext:doc)
   - Examples:
     * site:healthcare.com (intext:patient OR intext:PHI) ext:xlsx (intext:ssn OR intext:dob)
     * site:fintech.com intext:PCI (intext:card OR intext:cvv) ext:csv

CRITICAL DIVERSITY RULES:
- NO MORE than 15%% of dorks should contain "@company.com"
- MUST use intelligence from ALL categories above
- Each dork should target DIFFERENT intelligence (projects, tech, departments, etc.)
- Combine 2-3 different intelligence points per dork
- Think: What unique secrets can each category reveal?

QUALITY REQUIREMENTS:
- Target SPECIFIC secrets (credentials, PII, financial, compliance)
- Use ACTUAL data from intelligence (real project names, technologies, locations)
- Avoid generic patterns - be creative and specific!
- Each dork must be UNIQUE and target different aspects

FORBIDDEN (DO NOT GENERATE):
- Generic dorks: site:example.com ext:pdf
- Repetitive patterns: multiple dorks with same structure
- Email overuse: more than 2 email-based dorks out of 10

EXCELLENT EXAMPLES (diverse targeting):
- site:acme.com intext:"ProjectAlpha" inurl:(staging OR dev) (ext:yml OR ext:json) intext:api_key
- site:acme.com inurl:finance "SubsidiaryCo" ext:xlsx (intext:budget OR intext:invoice) 2024
- site:acme.com (intext:aws OR intext:azure) (ext:config OR ext:properties) (intext:access_key OR intext:secret_key)
- site:acme.com inurl:hr ext:pdf "Austin" (intext:compensation OR intext:salary)
- site:acme.com intext:"PartnerCorp" (intext:API OR intext:integration) (ext:json OR ext:xml)
- site:acme.com ext:log (intext:exception OR intext:error) (intext:password OR intext:token) "ProductName"

Generate EXACTLY %d highly creative, unique Google dorks for site:%s.
Each dork must be DIFFERENT and target specific secrets.
Output ONLY the dorks, nothing else. NO numbering, NO explanations.`, intelContext.String(), target, target, c.AiQuantity, target)

	userPrompt := fmt.Sprintf("Generate %d DIVERSE Google dorks for site:%s. Use intelligence from ALL categories: projects (%d), products (%d), technologies (%d), departments, subsidiaries (%d), partnerships (%d), locations (%d). NO MORE than 1-2 dorks should use @%s. Focus on variety!",
		c.AiQuantity, target,
		len(intel.ProjectNames),
		len(intel.ProductNames),
		len(intel.Technologies),
		len(intel.Subsidiaries),
		len(intel.Partnerships),
		len(intel.Locations),
		target)

	// Call AI to generate dorks
	output, err := c.callGeminiCLI(context.Background(), systemPrompt, userPrompt)
	if err != nil {
		console.Logv(c.Verbose, "[LINGUISTIC-INTEL] AI generation failed: %v", err)
		return nil
	}

	// Parse AI output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and metadata
		if line == "" ||
			strings.HasPrefix(line, "```") ||
			strings.HasPrefix(line, "#") ||
			strings.Contains(strings.ToLower(line), "here are") ||
			strings.Contains(strings.ToLower(line), "here is") ||
			strings.Contains(strings.ToLower(line), "i've generated") {
			continue
		}

		// Remove numbering/bullets
		line = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(line, "")
		line = regexp.MustCompile(`^[-*•]\s*`).ReplaceAllString(line, "")
		line = strings.TrimSpace(line)

		// Only keep lines with site:
		if strings.Contains(line, "site:") {
			dorks = append(dorks, line)
		}
	}

	console.Logv(c.Verbose, "[LINGUISTIC-INTEL] Generated %d AI-powered creative dorks", len(dorks))
	return dorks
}
