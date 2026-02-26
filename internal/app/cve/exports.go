package cve

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

func EnhancedCVEDetection(cfg *core.Config, ctx context.Context) []CVEEntry {
	return asConfig(cfg).enhancedCVEDetection(ctx)
}

func GenerateCVEDorks(cfg *core.Config, cves []CVEEntry) []string {
	return asConfig(cfg).generateCVEDorks(cves)
}

func GenerateIndustryVulnDorks(cfg *core.Config, patterns []IndustryVulnPattern) []string {
	return asConfig(cfg).generateIndustryVulnDorks(patterns)
}

func MatchCVEsByTechnology(tech, version string) []CVEEntry {
	return matchCVEsByTechnology(tech, version)
}

func GetIndustryVulnPatterns(industry string) []IndustryVulnPattern {
	return getIndustryVulnPatterns(industry)
}

func UpdateCVEDatabase(cfg *core.Config, ctx context.Context) error {
	return asConfig(cfg).updateCVEDatabase(ctx)
}
