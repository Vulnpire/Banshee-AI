package ai

import (
	"net/url"
	"strings"
)

func contains(values []string, item string) bool {
	for _, value := range values {
		if value == item {
			return true
		}
	}
	return false
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			u2, e2 := url.Parse("http://" + raw)
			if e2 == nil && u2.Host != "" {
				return u2.Host
			}
		}
		return ""
	}
	return u.Host
}

func getCategoryName(category string) string {
	categoryMap := map[string]string{
		"cms":                  "CMS",
		"web-frameworks":       "Framework",
		"programming-language": "Language",
		"web-servers":          "Web Server",
		"databases":            "Database",
		"analytics":            "Analytics",
		"javascript-libraries": "JS Library",
		"ui-frameworks":        "UI Framework",
		"devops":               "DevOps",
		"paas":                 "PaaS",
		"cdn":                  "CDN",
		"security":             "Security",
		"authentication":       "Auth",
		"hosting":              "Hosting",
		"marketing":            "Marketing",
		"payment":              "Payment",
		"ads":                  "Ads",
		"miscellaneous":        "Misc",
	}

	if name, ok := categoryMap[strings.ToLower(category)]; ok {
		return name
	}
	return "Other"
}
