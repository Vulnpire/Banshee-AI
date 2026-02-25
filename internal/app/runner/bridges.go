package runner

import (
	"context"
	"net/http"

	"banshee/internal/app/ai"
	"banshee/internal/app/analysis"
	"banshee/internal/app/core"
	"banshee/internal/app/search"
	"banshee/internal/app/utils"
	"banshee/internal/app/wayback"
)

type Config = core.Config
type SuccessfulURLInfo = core.SuccessfulURLInfo
type WaybackURL = wayback.WaybackURL

func loadConfigFile() *core.BansheeConfig {
	return core.LoadConfigFile()
}

func initializeConfigFiles() {
	core.InitializeConfigFiles()
}

func buildHTTPClient(proxy string, insecure bool) (*http.Client, error) {
	return search.BuildHTTPClient(proxy, insecure)
}

func buildExclusions(exclusions string, multiline bool) string {
	return search.BuildExclusions(exclusions, multiline)
}

func buildContentsQuery(contents string) string {
	return search.BuildContentsQuery(contents)
}

func buildInurlQuery(dict string) string {
	return search.BuildInurlQuery(dict)
}

func loadOOSFile(path string) []string {
	return search.LoadOOSFile(path)
}

func loadExistingOutputs(path string) map[string]struct{} {
	return search.LoadExistingOutputs(path)
}

func checkStdin() bool {
	return utils.CheckStdin()
}

func readStdin() ([]string, error) {
	return utils.ReadStdin()
}

func processWithWorkerPool(ctx context.Context, items []interface{}, workerCount int, processor func(context.Context, interface{}) (interface{}, error)) ([]interface{}, []error) {
	return utils.ProcessWithWorkerPool(ctx, items, workerCount, processor)
}

func fileExists(path string) bool {
	return search.FileExists(path)
}

func readLines(path string) ([]string, error) {
	return search.ReadLines(path)
}

func outputOrPrintUnique(urls []string, outputPath string) {
	search.OutputOrPrintUnique(urls, outputPath)
}

func uniqueStrings(values []string) []string {
	return search.UniqueStrings(values)
}

func clearAllWaybackCache() error {
	return wayback.ClearAllWaybackCache()
}

func cleanupWaybackCache(maxAgeDays int, maxSizeBytes int64) (int, error) {
	return wayback.CleanupWaybackCache(maxAgeDays, maxSizeBytes)
}

func loadWaybackIntelligence(domain string) (*core.WaybackIntelligence, error) {
	return wayback.LoadWaybackIntelligence(domain)
}

func queryWaybackCDX(ctx context.Context, domain string, statusCodes []string, verbose bool) ([]WaybackURL, error) {
	return wayback.QueryWaybackCDX(ctx, domain, statusCodes, verbose)
}

func filterExcludedURLs(urls []WaybackURL, exclusions string, verbose bool) []WaybackURL {
	return wayback.FilterExcludedURLs(urls, exclusions, verbose)
}

func extractWaybackIntelligence(domain string, urls []WaybackURL, verbose bool) *core.WaybackIntelligence {
	return wayback.ExtractWaybackIntelligence(domain, urls, verbose)
}

func saveWaybackIntelligence(domain string, intel *core.WaybackIntelligence) error {
	return wayback.SaveWaybackIntelligence(domain, intel)
}

func generateAIPoweredWaybackDorks(domain string, intel *core.WaybackIntelligence, aiPrompt string, quantity int, verbose bool, wafBypass bool) []string {
	return wayback.GenerateAIPoweredWaybackDorks(domain, intel, aiPrompt, quantity, verbose, wafBypass)
}

func deduplicateDorks(dorks []string) []string {
	return wayback.DeduplicateDorks(dorks)
}

func addDateOperators(dork string, timeline *ai.CompanyTimeline) string {
	return ai.AddDateOperators(dork, timeline)
}

func isCloudPrompt(prompt string) bool {
	return search.IsCloudPrompt(prompt)
}

func isCVEHuntingIntent(prompt string) bool {
	return analysis.IsCVEHuntingIntent(prompt)
}
