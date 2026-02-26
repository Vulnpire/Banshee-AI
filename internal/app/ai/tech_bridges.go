package ai

import (
	"context"
	"net/http"

	"github.com/Vulnpire/Banshee-AI/internal/app/tech"
)

func (c *Config) detectTechnologies(ctx context.Context) []TechDetectionResult {
	return tech.DetectTechnologies(toCore(c), ctx)
}

func (c *Config) fetchURLForFingerprinting(targetURL string) (*http.Response, string, error) {
	return tech.FetchURLForFingerprinting(toCore(c), targetURL)
}
