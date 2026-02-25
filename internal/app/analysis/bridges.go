package analysis

import (
	"context"
	"net/http"

	"banshee/internal/app/ai"
	"banshee/internal/app/search"
)

func (c *Config) callGeminiCLIWithLargeData(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return ai.CallGeminiCLIWithLargeData(toCore(c), ctx, systemPrompt, userPrompt)
}

func (c *Config) sendURLsThroughProxy(ctx context.Context, urls []string) {
	search.SendURLsThroughProxy(toCore(c), ctx, urls)
}

func buildHTTPClient(proxy string, insecure bool) (*http.Client, error) {
	return search.BuildHTTPClient(proxy, insecure)
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
