package analysis

import "strings"

// extractSensitiveTypesFromSummary pulls token types from "Sensitive:" sections of a summary.
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

	// Fallback keyword detection if no explicit Sensitive: section.
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

// classifyResponseFinding derives a priority from the summary content.
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

	// If we saw "Sensitive" wording without explicit keywords, treat as high.
	if strings.Contains(lower, "sensitive") {
		return "high"
	}

	if strings.Contains(lower, "admin") || strings.Contains(lower, "dashboard") {
		return "high"
	}

	return ""
}
