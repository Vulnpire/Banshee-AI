package pipeline

import "banshee/internal/app/utils"

func checkGeminiCLI() error {
	return utils.CheckGeminiCLI()
}

func postFilterResults(results []string, exclusions string, target string) []string {
	return utils.PostFilterResults(results, exclusions, target)
}
