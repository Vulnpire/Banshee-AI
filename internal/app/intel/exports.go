package intel

import "github.com/Vulnpire/Banshee-AI/internal/app/core"

func ViewIntelligence(cfg *core.Config, target string) error {
	return asConfig(cfg).viewIntelligence(target)
}

func ExportIntelligence(cfg *core.Config, target string) error {
	return asConfig(cfg).exportIntelligence(target)
}
