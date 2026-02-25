package interactive

import "banshee/internal/app/core"

func LaunchInteractiveMode(cfg *core.Config) error {
	return asConfig(cfg).launchInteractiveMode()
}
