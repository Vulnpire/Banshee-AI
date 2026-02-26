package monitor

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/ai"
	"github.com/Vulnpire/Banshee-AI/internal/app/pipeline"
)

func (c *Config) detectTargetLanguage(ctx context.Context) string {
	return ai.DetectTargetLanguage(toCore(c), ctx)
}

func (c *Config) executeDorkPipeline(ctx context.Context, dorks []string) {
	pipeline.ExecuteDorkPipeline(toCore(c), ctx, dorks)
}

func (c *Config) generateDorksWithAI(ctx context.Context, prompt string) ([]string, error) {
	return ai.GenerateDorksWithAI(toCore(c), ctx, prompt)
}

func (c *Config) generateMultiLangDorks(ctx context.Context, dorks []string, language string) []string {
	return ai.GenerateMultiLangDorks(toCore(c), ctx, dorks, language)
}
