package ai

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

func AnalyzeResultsForFollowUp(cfg *core.Config, ctx context.Context, results []string, prompt string) []string {
	return asConfig(cfg).analyzeResultsForFollowUp(ctx, results, prompt)
}

func AddDateOperators(dork string, timeline *CompanyTimeline) string {
	return addDateOperators(dork, timeline)
}

func CallGeminiCLI(cfg *core.Config, ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return asConfig(cfg).callGeminiCLI(ctx, systemPrompt, userPrompt)
}

func CallGeminiCLIWithLargeData(cfg *core.Config, ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return asConfig(cfg).callGeminiCLIWithLargeData(ctx, systemPrompt, userPrompt)
}

func CallGeminiCLIWithLargeDataOnce(cfg *core.Config, ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return asConfig(cfg).callGeminiCLIWithLargeDataOnce(ctx, systemPrompt, userPrompt)
}

func ClassifyAndScoreResults(cfg *core.Config, ctx context.Context, results []string) ([]ScoredResult, error) {
	return asConfig(cfg).classifyAndScoreResults(ctx, results)
}

func CorrelateDiscoveries(cfg *core.Config, ctx context.Context, results []string) []string {
	return asConfig(cfg).correlateDiscoveries(ctx, results)
}

func DetectCompanyTimeline(cfg *core.Config, ctx context.Context) *CompanyTimeline {
	return asConfig(cfg).detectCompanyTimeline(ctx)
}

func DetectTargetLanguage(cfg *core.Config, ctx context.Context) string {
	return asConfig(cfg).detectTargetLanguage(ctx)
}

func DetectTechStack(cfg *core.Config, ctx context.Context) *DetectedTech {
	return asConfig(cfg).detectTechStack(ctx)
}

func DisplayBudgetAnalysis(cfg *core.Config, predictions []DorkPrediction) {
	asConfig(cfg).displayBudgetAnalysis(predictions)
}

func DisplayOptimizedDorks(cfg *core.Config, optimized *OptimizedDorks) {
	asConfig(cfg).displayOptimizedDorks(optimized)
}

func DisplayScoredResults(cfg *core.Config, scored []ScoredResult) {
	asConfig(cfg).displayScoredResults(scored)
}

func GenerateDorksFromSuccessfulURLs(cfg *core.Config, ctx context.Context) ([]string, error) {
	return asConfig(cfg).generateDorksFromSuccessfulURLs(ctx)
}

func GenerateDorksWithAI(cfg *core.Config, ctx context.Context, prompt string) ([]string, error) {
	return asConfig(cfg).generateDorksWithAI(ctx, prompt)
}

func GenerateMultiLangDorks(cfg *core.Config, ctx context.Context, dorks []string, language string) []string {
	return asConfig(cfg).generateMultiLangDorks(ctx, dorks, language)
}

func GenerateRandomDorks(cfg *core.Config, ctx context.Context) ([]string, error) {
	return asConfig(cfg).generateRandomDorks(ctx)
}

func GenerateResearchBasedDorks(cfg *core.Config, ctx context.Context, target, researchData string) ([]string, error) {
	return asConfig(cfg).generateResearchBasedDorks(ctx, target, researchData)
}

func GenerateTechSpecificDorks(cfg *core.Config, tech *DetectedTech) []string {
	return asConfig(cfg).generateTechSpecificDorks(tech)
}

func IntelligentDedupe(cfg *core.Config, urls []string) []string {
	return asConfig(cfg).intelligentDedupe(urls)
}

func OptimizeDorks(cfg *core.Config, ctx context.Context, dorkResults map[string][]string) (*OptimizedDorks, error) {
	return asConfig(cfg).optimizeDorks(ctx, dorkResults)
}

func PerformOSINTResearch(cfg *core.Config, ctx context.Context, target string) (string, error) {
	return asConfig(cfg).performOSINTResearch(ctx, target)
}

func PredictDorkSuccess(cfg *core.Config, ctx context.Context, dorks []string) ([]DorkPrediction, error) {
	return asConfig(cfg).predictDorkSuccess(ctx, dorks)
}

func RecursivelyDiscoverSubdomains(cfg *core.Config, ctx context.Context, subdomain string, currentDepth, maxDepth int) []string {
	return asConfig(cfg).recursivelyDiscoverSubdomains(ctx, subdomain, currentDepth, maxDepth)
}
