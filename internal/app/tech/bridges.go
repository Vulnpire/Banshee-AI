package tech

import "github.com/Vulnpire/Banshee-AI/internal/app/cve"

func (c *Config) generateCVEDorks(cves []cve.CVEEntry) []string {
	return cve.GenerateCVEDorks(toCore(c), cves)
}
