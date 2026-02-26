package ai

import (
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
	"github.com/Vulnpire/Banshee-AI/internal/app/intel"
)

func loadTargetIntelligence(target string) *core.TargetIntelligence {
	return intel.LoadTargetIntelligence(target)
}

func generateLearnedPrompt(intelData *core.TargetIntelligence, basePrompt string, category string) string {
	return intel.GenerateLearnedPrompt(intelData, basePrompt, category)
}

func loadLinguisticIntelligence(target string) *core.LinguisticIntelligence {
	return intel.LoadLinguisticIntelligence(target)
}

func saveLinguisticIntelligence(target string, intelData *core.LinguisticIntelligence) error {
	return intel.SaveLinguisticIntelligence(target, intelData)
}
