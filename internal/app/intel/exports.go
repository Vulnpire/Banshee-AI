package intel

import "banshee/internal/app/core"

func ViewIntelligence(cfg *core.Config, target string) error {
	return asConfig(cfg).viewIntelligence(target)
}

func ExportIntelligence(cfg *core.Config, target string) error {
	return asConfig(cfg).exportIntelligence(target)
}
