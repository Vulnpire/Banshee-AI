package pipeline

import (
	"strings"
	"sync"

	"banshee/internal/app/analysis"
	"banshee/internal/app/core"
)

var monitorKeywordOnce sync.Once
var monitorKeywordList []string
var monitorKeywordErr error

func (c *Config) applyMonitorFilters(urls []string) []string {
	if !c.MonitorMode || len(urls) == 0 {
		return urls
	}

	filtered := make([]string, 0, len(urls))
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}

		if c.FilterMonitor && c.MonitorDocFocus {
			if !isDocumentLikeURL(url) {
				continue
			}
			keywords, err := getMonitorKeywords()
			if err == nil && len(keywords) > 0 && analysis.ShouldFilterDocument(url, keywords) {
				continue
			}
		}

		if c.FilterMonitor {
			if c.MonitorSeenURLs == nil {
				c.MonitorSeenURLs = core.NewSafeSet()
			}
			if !c.MonitorSeenURLs.Add(url) {
				continue
			}
		}

		filtered = append(filtered, url)
	}

	return filtered
}

func getMonitorKeywords() ([]string, error) {
	monitorKeywordOnce.Do(func() {
		monitorKeywordList, monitorKeywordErr = analysis.LoadNonSensitiveKeywords()
	})
	return monitorKeywordList, monitorKeywordErr
}

func isDocumentLikeURL(url string) bool {
	l := strings.ToLower(url)
	docExts := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx", ".odt", ".rtf"}
	for _, ext := range docExts {
		if strings.Contains(l, ext) {
			return true
		}
	}
	return false
}
