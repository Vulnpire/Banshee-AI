package monitor

import (
	"context"

	"github.com/Vulnpire/Banshee-AI/internal/app/core"
	"github.com/Vulnpire/Banshee-AI/internal/app/wayback"
)

func loadWaybackIntelligence(domain string) (*core.WaybackIntelligence, error) {
	return wayback.LoadWaybackIntelligence(domain)
}

func queryWaybackCDX(ctx context.Context, domain string, statusCodes []string, verbose bool) ([]wayback.WaybackURL, error) {
	return wayback.QueryWaybackCDX(ctx, domain, statusCodes, verbose)
}

func filterExcludedURLs(urls []wayback.WaybackURL, exclusions string, verbose bool) []wayback.WaybackURL {
	return wayback.FilterExcludedURLs(urls, exclusions, verbose)
}

func extractWaybackIntelligence(domain string, urls []wayback.WaybackURL, verbose bool) *core.WaybackIntelligence {
	return wayback.ExtractWaybackIntelligence(domain, urls, verbose)
}

func saveWaybackIntelligence(domain string, intel *core.WaybackIntelligence) error {
	return wayback.SaveWaybackIntelligence(domain, intel)
}

func generateAIPoweredWaybackDorks(domain string, intel *core.WaybackIntelligence, aiPrompt string, quantity int, verbose bool, wafBypass bool) []string {
	return wayback.GenerateAIPoweredWaybackDorks(domain, intel, aiPrompt, quantity, verbose, wafBypass)
}
