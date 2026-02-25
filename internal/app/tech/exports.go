package tech

import (
	"context"
	"net/http"

	"banshee/internal/app/core"
	"banshee/internal/app/cve"
)

func DetectTechnologies(cfg *core.Config, ctx context.Context) []TechDetectionResult {
	return asConfig(cfg).detectTechnologies(ctx)
}

func FetchURLForFingerprinting(cfg *core.Config, targetURL string) (*http.Response, string, error) {
	return asConfig(cfg).fetchURLForFingerprinting(targetURL)
}

func PerformComprehensiveTechDetection(cfg *core.Config, ctx context.Context) ([]string, []cve.CVEEntry) {
	return asConfig(cfg).performComprehensiveTechDetection(ctx)
}
