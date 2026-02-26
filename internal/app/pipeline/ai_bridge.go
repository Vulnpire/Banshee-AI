package pipeline

import "github.com/Vulnpire/Banshee-AI/internal/app/ai"

func addDateOperators(dork string, timeline *ai.CompanyTimeline) string {
	return ai.AddDateOperators(dork, timeline)
}
