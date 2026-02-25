package pipeline

import "banshee/internal/app/analysis"

func filterDocumentAnalysisURLs(urls []string) []string {
	return analysis.FilterDocumentAnalysisURLs(urls)
}

func filterResponseAnalysisURLs(urls []string) ([]string, []string) {
	return analysis.FilterResponseAnalysisURLs(urls)
}

func normalizeRAOutput(summary string) string {
	return analysis.NormalizeRAOutput(summary)
}

func highlightSensitiveFindings(summary string) string {
	return analysis.HighlightSensitiveFindings(summary)
}

func extractDomainFromURL(url string) string {
	return analysis.ExtractDomainFromURL(url)
}
