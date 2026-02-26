package ai

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/search"
)

func detectCloudIntentWithAI(ctx context.Context, prompt, model string) bool {
	return search.DetectCloudIntentWithAI(ctx, prompt, model)
}

func parseExtensionsList(ext string) []string {
	return search.ParseExtensionsList(ext)
}

func buildCloudPromptHint(target string) string {
	return search.BuildCloudPromptHint(target)
}
