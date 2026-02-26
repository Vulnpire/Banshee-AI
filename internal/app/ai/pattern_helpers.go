package ai

import (
	"regexp"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

func extractPatternsFromResults(results []string) []core.SuccessPattern {
	patterns := make(map[string]*core.SuccessPattern)

	for _, url := range results {
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

	var result []core.SuccessPattern
	for _, p := range patterns {
		result = append(result, *p)
	}

	return result
}

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

	host = strings.Split(host, ":")[0]

	if host != target && strings.HasSuffix(host, "."+target) {
		return host
	}

	return ""
}

func extractPathPattern(url string) string {
	re := regexp.MustCompile(`https?://[^/]+(/[^?#]*)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		path := matches[1]
		path = strings.TrimRight(path, "/")
		if path != "" && path != "/" {
			return path
		}
	}
	return ""
}

func extractParameters(url string) []string {
	var params []string
	re := regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]*)=`)
	matches := re.FindAllStringSubmatch(url, -1)
	for _, match := range matches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	return params
}

func extractFileType(url string) string {
	extensions := []string{".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".csv", ".xls", ".xlsx", ".pdf", ".sql", ".env", ".ini", ".conf", ".yaml", ".yml"}
	urlLower := strings.ToLower(url)
	for _, ext := range extensions {
		if strings.Contains(urlLower, ext) {
			return strings.TrimPrefix(ext, ".")
		}
	}
	return ""
}

func detectContext(url string) string {
	urlLower := strings.ToLower(url)

	if strings.Contains(urlLower, "admin") || strings.Contains(urlLower, "dashboard") || strings.Contains(urlLower, "panel") {
		return "admin"
	}
	if strings.Contains(urlLower, "api") || strings.Contains(urlLower, "/v1/") || strings.Contains(urlLower, "/v2/") {
		return "api"
	}
	if strings.Contains(urlLower, "config") || strings.Contains(urlLower, "settings") {
		return "config"
	}
	if strings.Contains(urlLower, "login") || strings.Contains(urlLower, "auth") || strings.Contains(urlLower, "signin") {
		return "auth"
	}
	if strings.Contains(urlLower, "upload") || strings.Contains(urlLower, "file") {
		return "upload"
	}

	return "general"
}
