package intel

import "banshee/internal/app/core"

func ExtractPatternsFromResults(results []string) []core.SuccessPattern {
	return extractPatternsFromResults(results)
}

func ExtractSubdomain(url, target string) string {
	return extractSubdomain(url, target)
}

func ExtractPathPattern(url string) string {
	return extractPathPattern(url)
}

func ExtractParameters(url string) []string {
	return extractParameters(url)
}

func ExtractFileType(url string) string {
	return extractFileType(url)
}

func DetectContext(url string) string {
	return detectContext(url)
}

func LoadTargetIntelligence(target string) *core.TargetIntelligence {
	return loadTargetIntelligence(target)
}

func GenerateLearnedPrompt(intelData *core.TargetIntelligence, basePrompt string, category string) string {
	return generateLearnedPrompt(intelData, basePrompt, category)
}

func LoadLinguisticIntelligence(target string) *core.LinguisticIntelligence {
	return loadLinguisticIntelligence(target)
}

func SaveLinguisticIntelligence(target string, intelData *core.LinguisticIntelligence) error {
	return saveLinguisticIntelligence(target, intelData)
}

func SaveTargetIntelligence(intelData *core.TargetIntelligence) error {
	return saveTargetIntelligence(intelData)
}

func UpdateIntelligenceWithResults(intelData *core.TargetIntelligence, dorks []string, results map[string][]string) {
	updateIntelligenceWithResults(intelData, dorks, results)
}
