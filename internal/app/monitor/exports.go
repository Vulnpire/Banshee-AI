package monitor

import (
	"context"

	"banshee/internal/app/core"
)

func RunMonitor(cfg *core.Config, ctx context.Context, targets []string) error {
	return asConfig(cfg).runMonitor(ctx, targets)
}
