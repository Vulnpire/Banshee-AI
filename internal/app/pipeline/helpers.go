package pipeline

import "github.com/Vulnpire/Banshee-AI/internal/app/utils"

func checkGeminiCLI() error {
	return utils.CheckGeminiCLI()
}

func postFilterResults(results []string, exclusions string, target string) []string {
	return utils.PostFilterResults(results, exclusions, target)
}
