package tenant

import (
	"context"

	"banshee/internal/app/core"
)

func ResolveApexTargets(cfg *core.Config, ctx context.Context, targets []string) ([]string, error) {
	return asConfig(cfg).resolveApexTargets(ctx, targets)
}

func LogApexTargets(cfg *core.Config, targets []string) {
	asConfig(cfg).logApexTargets(targets)
}

func PrintApexSummary(cfg *core.Config) {
	asConfig(cfg).printApexSummary()
}
