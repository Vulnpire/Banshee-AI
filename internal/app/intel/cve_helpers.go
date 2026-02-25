package intel

import "banshee/internal/app/cve"

type CVEEntry = cve.CVEEntry

var CVEDatabase = cve.CVEDatabase

func getIndustryVulnPatterns(industry string) []cve.IndustryVulnPattern {
	return cve.GetIndustryVulnPatterns(industry)
}
