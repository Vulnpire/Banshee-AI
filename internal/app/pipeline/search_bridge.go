package pipeline

import "github.com/Vulnpire/Banshee-AI/internal/app/search"

func uniqueStrings(values []string) []string {
	return search.UniqueStrings(values)
}

func loadExistingOutputs(path string) map[string]struct{} {
	return search.LoadExistingOutputs(path)
}

func outputOrPrintUnique(urls []string, outputPath string) {
	search.OutputOrPrintUnique(urls, outputPath)
}

func convertToBraveDork(query string) string {
	return search.ConvertToBraveDork(query)
}

func filterOOSResults(results []string, patterns []string) ([]string, int) {
	return search.FilterOOSResults(results, patterns)
}

func filterLinks(links []string, target string, cloudMode bool) []string {
	return search.FilterLinks(links, target, cloudMode)
}

func applySubdomainOnlyFilter(dork string, target string) string {
	return search.ApplySubdomainOnlyFilter(dork, target)
}

func filterNewURLs(urls []string, existing map[string]struct{}) []string {
	return search.FilterNewURLs(urls, existing)
}

func isCloudDork(query string) bool {
	return search.IsCloudDork(query)
}

func buildInurlQuery(dict string) string {
	return search.BuildInurlQuery(dict)
}

func buildContentsQuery(contents string) string {
	return search.BuildContentsQuery(contents)
}

func readLines(path string) ([]string, error) {
	return search.ReadLines(path)
}

func fileExists(path string) bool {
	return search.FileExists(path)
}
