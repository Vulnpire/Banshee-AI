package intel

import "github.com/Vulnpire/Banshee-AI/internal/app/cve"

type CVEEntry = cve.CVEEntry

var CVEDatabase = cve.CVEDatabase

func getIndustryVulnPatterns(industry string) []cve.IndustryVulnPattern {
	return cve.GetIndustryVulnPatterns(industry)
}
