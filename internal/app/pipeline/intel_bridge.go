package pipeline

import (
	"banshee/internal/app/core"
	"banshee/internal/app/intel"
)

func updateIntelligenceWithResults(intelData *core.TargetIntelligence, dorks []string, results map[string][]string) {
	intel.UpdateIntelligenceWithResults(intelData, dorks, results)
}

func saveTargetIntelligence(intelData *core.TargetIntelligence) error {
	return intel.SaveTargetIntelligence(intelData)
}

func loadTargetIntelligence(target string) *core.TargetIntelligence {
	return intel.LoadTargetIntelligence(target)
}

func generateLearnedPrompt(intelData *core.TargetIntelligence, basePrompt string, category string) string {
	return intel.GenerateLearnedPrompt(intelData, basePrompt, category)
}
