package analysis

import (
	"context"

	"banshee/internal/app/core"
)

// DorkRun is injected by the runner to avoid importing the pipeline package here.
var DorkRun func(ctx context.Context, cfg *core.Config, ext string) []string

func AnalyzeDocumentForSensitiveInfo(cfg *core.Config, ctx context.Context, url string) {
	asConfig(cfg).analyzeDocumentForSensitiveInfo(ctx, url)
}

func AnalyzeInlineJavaScript(cfg *core.Config, ctx context.Context, url string, body string) (string, error) {
	return asConfig(cfg).analyzeInlineJavaScript(ctx, url, body)
}

func AnalyzeResponseOnlyHandler(cfg *core.Config, ctx context.Context) error {
	return asConfig(cfg).analyzeResponseOnly_handler(ctx)
}

func FilterDocumentAnalysisURLs(urls []string) []string {
	return filterDocumentAnalysisURLs(urls)
}

func FilterResponseAnalysisURLs(urls []string) ([]string, []string) {
	return filterResponseAnalysisURLs(urls)
}

func NormalizeRAOutput(summary string) string {
	return normalizeRAOutput(summary)
}

func HighlightSensitiveFindings(summary string) string {
	return highlightSensitiveFindings(summary)
}

func ExtractDomainFromURL(url string) string {
	return extractDomainFromURL(url)
}

func AnalyzeResponsesWithAI(cfg *core.Config, ctx context.Context, responsesFile string, urls []string) (map[string]string, error) {
	return asConfig(cfg).analyzeResponsesWithAI(ctx, responsesFile, urls)
}

func CheckPasteSitesForLeaks(cfg *core.Config, ctx context.Context) error {
	return asConfig(cfg).checkPasteSitesForLeaks(ctx)
}

func CollectHTTPResponses(cfg *core.Config, ctx context.Context, urls []string, responsesFile string) error {
	return asConfig(cfg).collectHTTPResponses(ctx, urls, responsesFile)
}

func IsCVEHuntingIntent(prompt string) bool {
	return isCVEHuntingIntent(prompt)
}

func PerformInlineCodeAnalysis(cfg *core.Config, ctx context.Context, urls []string) *InlineCodeAnalysisStats {
	return asConfig(cfg).performInlineCodeAnalysis(ctx, urls)
}

func RecordResponseFindings(cfg *core.Config, analysis map[string]string) {
	asConfig(cfg).recordResponseFindings(analysis)
}
