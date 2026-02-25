package analysis

import (
	"regexp"
	"strings"
)

// fixDorkSyntax fixes common syntax issues in AI-generated dorks.
func fixDorkSyntax(dork string) string {
	// Replace pipe | with OR (neither Google nor Brave use |).
	dork = strings.ReplaceAll(dork, " | ", " OR ")
	dork = strings.ReplaceAll(dork, "|", " OR ")

	// Remove duplicate OR.
	dork = regexp.MustCompile(`\s+OR\s+OR\s+`).ReplaceAllString(dork, " OR ")

	// Fix spacing.
	dork = regexp.MustCompile(`\s+`).ReplaceAllString(dork, " ")
	dork = regexp.MustCompile(`OR\s+`).ReplaceAllString(dork, "OR ")

	return strings.TrimSpace(dork)
}

// cleanNestedParentheses removes nested/double parentheses and flattens OR expressions.
func cleanNestedParentheses(dork string) string {
	// Remove double/nested parentheses like ((expression)).
	for strings.Contains(dork, "((") || strings.Contains(dork, "))") {
		dork = strings.ReplaceAll(dork, "((", "(")
		dork = strings.ReplaceAll(dork, "))", ")")
	}

	// Pattern: (something) (something_else) - multiple grouped expressions.
	multiGroupPattern := regexp.MustCompile(`\)\s+\(`)
	if multiGroupPattern.MatchString(dork) {
		// Check if this is site:domain (main) after:... before:... pattern.
		// If so, keep it, otherwise flatten.
		if !regexp.MustCompile(`^site:[^\s]+\s+\([^)]+\)\s+(after:|before:)`).MatchString(dork) {
			// Remove all parentheses and let improveDorkSyntax re-add them properly.
			dork = strings.ReplaceAll(dork, "(", "")
			dork = strings.ReplaceAll(dork, ")", "")
			dork = regexp.MustCompile(`\s+`).ReplaceAllString(dork, " ")
		}
	}

	return strings.TrimSpace(dork)
}

// improveDorkSyntax adds parentheses around OR expressions while preserving date operators and exclusions.
func improveDorkSyntax(dork string) string {
	// First apply basic fixes.
	dork = fixDorkSyntax(dork)

	// Check if dork contains OR operator.
	if !strings.Contains(dork, " OR ") {
		return dork
	}

	// Find site: part.
	siteMatch := regexp.MustCompile(`^(site:[^\s]+)\s+(.+)$`).FindStringSubmatch(dork)
	if len(siteMatch) != 3 {
		return dork
	}

	sitePart := siteMatch[1]
	restPart := siteMatch[2]

	// Check if already has parentheses around the main query.
	// Pattern: (anything) after:... or (anything) before:... or (anything) -something.
	if regexp.MustCompile(`^\([^)]+\)(\s+(after:|before:|-)|$)`).MatchString(restPart) {
		return dork // Already properly formatted.
	}

	// Split into main query, date operators, and exclusions.
	var mainQuery []string
	var dateOps []string
	var exclusions []string

	// Split by spaces while preserving quoted strings.
	parts := splitPreservingQuotes(restPart)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for date operators (after:, before:).
		if strings.HasPrefix(part, "after:") || strings.HasPrefix(part, "before:") {
			dateOps = append(dateOps, part)
			// Check for exclusions (-site:, -inurl:, -filetype:, etc.).
		} else if strings.HasPrefix(part, "-") {
			exclusions = append(exclusions, part)
			// Check for OR (keep with main query).
		} else if part == "OR" {
			mainQuery = append(mainQuery, part)
			// Everything else is main query.
		} else {
			mainQuery = append(mainQuery, part)
		}
	}

	// If no main query, return as-is.
	if len(mainQuery) == 0 {
		return dork
	}

	// Build the improved dork.
	result := sitePart

	// Add main query in parentheses.
	mainQueryStr := strings.Join(mainQuery, " ")
	result += " (" + mainQueryStr + ")"

	// Add date operators after main query.
	if len(dateOps) > 0 {
		result += " " + strings.Join(dateOps, " ")
	}

	// Add exclusions at the end.
	if len(exclusions) > 0 {
		result += " " + strings.Join(exclusions, " ")
	}

	return result
}

// splitPreservingQuotes splits a string by spaces while preserving quoted strings.
func splitPreservingQuotes(s string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(s); i++ {
		char := s[i]

		if char == '"' {
			inQuotes = !inQuotes
			current.WriteByte(char)
		} else if char == ' ' && !inQuotes {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(char)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}
