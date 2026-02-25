package intel

import (
	"context"

	"banshee/internal/app/cve"
)

func (c *Config) enhancedCVEDetection(ctx context.Context) []cve.CVEEntry {
	return cve.EnhancedCVEDetection(toCore(c), ctx)
}

func (c *Config) generateCVEDorks(cves []cve.CVEEntry) []string {
	return cve.GenerateCVEDorks(toCore(c), cves)
}

func (c *Config) generateIndustryVulnDorks(patterns []cve.IndustryVulnPattern) []string {
	return cve.GenerateIndustryVulnDorks(toCore(c), patterns)
}
