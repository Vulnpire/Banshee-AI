package pipeline

import "banshee/internal/app/ai"

func addDateOperators(dork string, timeline *ai.CompanyTimeline) string {
	return ai.AddDateOperators(dork, timeline)
}
