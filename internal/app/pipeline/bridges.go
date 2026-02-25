package pipeline

import (
	"context"

	"banshee/internal/app/ai"
	"banshee/internal/app/analysis"
	"banshee/internal/app/core"
	"banshee/internal/app/cve"
	"banshee/internal/app/search"
	"banshee/internal/app/tech"
	"banshee/internal/app/tenant"
)

func (c *Config) analyzeDocumentForSensitiveInfo(ctx context.Context, url string) {
	analysis.AnalyzeDocumentForSensitiveInfo(toCore(c), ctx, url)
}

func (c *Config) analyzeResponsesWithAI(ctx context.Context, responsesFile string, urls []string) (map[string]string, error) {
	return analysis.AnalyzeResponsesWithAI(toCore(c), ctx, responsesFile, urls)
}

func (c *Config) analyzeResultsForFollowUp(ctx context.Context, results []string, prompt string) []string {
	return ai.AnalyzeResultsForFollowUp(toCore(c), ctx, results, prompt)
}

func (c *Config) braveSearch(ctx context.Context, query string, offset int) ([]string, error) {
	return search.BraveSearch(toCore(c), ctx, query, offset)
}

func (c *Config) classifyAndScoreResults(ctx context.Context, results []string) ([]ai.ScoredResult, error) {
	return ai.ClassifyAndScoreResults(toCore(c), ctx, results)
}

func (c *Config) collectHTTPResponses(ctx context.Context, urls []string, responsesFile string) error {
	return analysis.CollectHTTPResponses(toCore(c), ctx, urls, responsesFile)
}

func (c *Config) correlateDiscoveries(ctx context.Context, results []string) []string {
	return ai.CorrelateDiscoveries(toCore(c), ctx, results)
}

func (c *Config) delayControl() {
	search.DelayControl(toCore(c))
}

func (c *Config) detectCompanyTimeline(ctx context.Context) *ai.CompanyTimeline {
	return ai.DetectCompanyTimeline(toCore(c), ctx)
}

func (c *Config) detectTargetLanguage(ctx context.Context) string {
	return ai.DetectTargetLanguage(toCore(c), ctx)
}

func (c *Config) detectTechStack(ctx context.Context) *ai.DetectedTech {
	return ai.DetectTechStack(toCore(c), ctx)
}

func (c *Config) displayBudgetAnalysis(predictions []ai.DorkPrediction) {
	ai.DisplayBudgetAnalysis(toCore(c), predictions)
}

func (c *Config) displayOptimizedDorks(optimized *ai.OptimizedDorks) {
	ai.DisplayOptimizedDorks(toCore(c), optimized)
}

func (c *Config) displayScoredResults(scored []ai.ScoredResult) {
	ai.DisplayScoredResults(toCore(c), scored)
}

func (c *Config) generateDorksFromSuccessfulURLs(ctx context.Context) ([]string, error) {
	return ai.GenerateDorksFromSuccessfulURLs(toCore(c), ctx)
}

func (c *Config) generateDorksWithAI(ctx context.Context, prompt string) ([]string, error) {
	return ai.GenerateDorksWithAI(toCore(c), ctx, prompt)
}

func (c *Config) generateMultiLangDorks(ctx context.Context, dorks []string, language string) []string {
	return ai.GenerateMultiLangDorks(toCore(c), ctx, dorks, language)
}

func (c *Config) generateRandomDorks(ctx context.Context) ([]string, error) {
	return ai.GenerateRandomDorks(toCore(c), ctx)
}

func (c *Config) generateResearchBasedDorks(ctx context.Context, target, researchData string) ([]string, error) {
	return ai.GenerateResearchBasedDorks(toCore(c), ctx, target, researchData)
}

func (c *Config) generateTechSpecificDorks(techStack *ai.DetectedTech) []string {
	return ai.GenerateTechSpecificDorks(toCore(c), techStack)
}

func (c *Config) getRandomApiKey() (string, error) {
	return search.GetRandomAPIKey(toCore(c))
}

func (c *Config) httpGetJSON(ctx context.Context, u string) (*core.GoogleResponse, *core.BraveResponse, int, error) {
	return search.HTTPGetJSON(toCore(c), ctx, u)
}

func (c *Config) intelligentDedupe(urls []string) []string {
	return ai.IntelligentDedupe(toCore(c), urls)
}

func (c *Config) notFound() {
	search.NotFound(toCore(c))
}

func (c *Config) optimizeDorks(ctx context.Context, dorkResults map[string][]string) (*ai.OptimizedDorks, error) {
	return ai.OptimizeDorks(toCore(c), ctx, dorkResults)
}

func (c *Config) performComprehensiveTechDetection(ctx context.Context) ([]string, []cve.CVEEntry) {
	return tech.PerformComprehensiveTechDetection(toCore(c), ctx)
}

func (c *Config) performInlineCodeAnalysis(ctx context.Context, urls []string) *analysis.InlineCodeAnalysisStats {
	return analysis.PerformInlineCodeAnalysis(toCore(c), ctx, urls)
}

func (c *Config) performOSINTResearch(ctx context.Context, target string) (string, error) {
	return ai.PerformOSINTResearch(toCore(c), ctx, target)
}

func (c *Config) predictDorkSuccess(ctx context.Context, dorks []string) ([]ai.DorkPrediction, error) {
	return ai.PredictDorkSuccess(toCore(c), ctx, dorks)
}

func (c *Config) printApexSummary() {
	tenant.PrintApexSummary(toCore(c))
}

func (c *Config) recordResponseFindings(analysisMap map[string]string) {
	analysis.RecordResponseFindings(toCore(c), analysisMap)
}

func (c *Config) recursivelyDiscoverSubdomains(ctx context.Context, subdomain string, currentDepth, maxDepth int) []string {
	return ai.RecursivelyDiscoverSubdomains(toCore(c), ctx, subdomain, currentDepth, maxDepth)
}

func (c *Config) resolveApexTargets(ctx context.Context, targets []string) ([]string, error) {
	return tenant.ResolveApexTargets(toCore(c), ctx, targets)
}

func (c *Config) sendURLsThroughProxy(ctx context.Context, urls []string) {
	search.SendURLsThroughProxy(toCore(c), ctx, urls)
}

func (c *Config) showContentInFile() {
	search.ShowContentInFile(toCore(c))
}
