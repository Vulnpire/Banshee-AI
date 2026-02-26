package interactive

import "github.com/Vulnpire/Banshee-AI/internal/app/core"

func LaunchInteractiveMode(cfg *core.Config) error {
	return asConfig(cfg).launchInteractiveMode()
}
