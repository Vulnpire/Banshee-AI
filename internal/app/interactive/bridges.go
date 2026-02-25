package interactive

import (
	"context"

	"banshee/internal/app/ai"
	"banshee/internal/app/search"
)

func (c *Config) callGeminiCLI(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return ai.CallGeminiCLI(toCore(c), ctx, systemPrompt, userPrompt)
}

func fileExists(path string) bool {
	return search.FileExists(path)
}

func readLines(path string) ([]string, error) {
	return search.ReadLines(path)
}
