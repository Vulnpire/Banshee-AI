package ai

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// DorkRun is injected by the runner to avoid importing the pipeline package.
var DorkRun func(ctx context.Context, cfg *core.Config, ext string) []string

func (c *Config) dorkRun(ctx context.Context, ext string) []string {
	if DorkRun == nil {
		return nil
	}
	return DorkRun(ctx, toCore(c), ext)
}
