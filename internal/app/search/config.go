package search

import "banshee/internal/app/core"

// Config aliases the shared core.Config for package methods.
type Config core.Config

func asConfig(cfg *core.Config) *Config {
	return (*Config)(cfg)
}

func toCore(cfg *Config) *core.Config {
	return (*core.Config)(cfg)
}
