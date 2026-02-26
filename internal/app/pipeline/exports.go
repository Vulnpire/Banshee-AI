package pipeline

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

func AiDorkAttack(cfg *core.Config, ctx context.Context) {
	asConfig(cfg).aiDorkAttack(ctx)
}

func AiDorkAttackMultiplePrompts(cfg *core.Config, ctx context.Context, prompts []string) {
	asConfig(cfg).aiDorkAttackMultiplePrompts(ctx, prompts)
}

func ContentsAttack(cfg *core.Config, ctx context.Context) {
	asConfig(cfg).contentsAttack(ctx)
}

func DictionaryAttack(cfg *core.Config, ctx context.Context) {
	asConfig(cfg).dictionaryAttack(ctx)
}

func DorkRun(cfg *core.Config, ctx context.Context, ext string) []string {
	return asConfig(cfg).dorkRun(ctx, ext)
}

func ExecuteDorkPipeline(cfg *core.Config, ctx context.Context, dorks []string) {
	asConfig(cfg).executeDorkPipeline(ctx, dorks)
}

func ExtensionAttack(cfg *core.Config, ctx context.Context) {
	asConfig(cfg).extensionAttack(ctx)
}

func MultiDorkAttack(cfg *core.Config, ctx context.Context, dorks []string) {
	asConfig(cfg).multiDorkAttack(ctx, dorks)
}

func PerformTLDMassScanning(cfg *core.Config, ctx context.Context, tlds []string) error {
	return asConfig(cfg).performTLDMassScanning(ctx, tlds)
}

func ProcessDomainsFromList(cfg *core.Config, ctx context.Context, domains []string) error {
	return asConfig(cfg).processDomainsFromList(ctx, domains)
}

func SubdomainAttack(cfg *core.Config, ctx context.Context) {
	asConfig(cfg).subdomainAttack(ctx)
}
