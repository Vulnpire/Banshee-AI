package tech

import "banshee/internal/app/cve"

func (c *Config) generateCVEDorks(cves []cve.CVEEntry) []string {
	return cve.GenerateCVEDorks(toCore(c), cves)
}
