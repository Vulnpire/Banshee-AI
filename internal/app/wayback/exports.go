package wayback

import (
	"context"

	"banshee/internal/app/core"
)

func QueryWaybackCDX(ctx context.Context, domain string, statusCodes []string, verbose bool) ([]WaybackURL, error) {
	return queryWaybackCDX(ctx, domain, statusCodes, verbose)
}

func FilterExcludedURLs(urls []WaybackURL, exclusions string, verbose bool) []WaybackURL {
	return filterExcludedURLs(urls, exclusions, verbose)
}

func ExtractWaybackIntelligence(domain string, urls []WaybackURL, verbose bool) *core.WaybackIntelligence {
	return extractWaybackIntelligence(domain, urls, verbose)
}

func SaveWaybackIntelligence(domain string, intel *core.WaybackIntelligence) error {
	return saveWaybackIntelligence(domain, intel)
}

func LoadWaybackIntelligence(domain string) (*core.WaybackIntelligence, error) {
	return loadWaybackIntelligence(domain)
}

func GenerateAIPoweredWaybackDorks(domain string, intel *core.WaybackIntelligence, aiPrompt string, quantity int, verbose bool, wafBypass bool) []string {
	return generateAIPoweredWaybackDorks(domain, intel, aiPrompt, quantity, verbose, wafBypass)
}

func DeduplicateDorks(dorks []string) []string {
	return deduplicateDorks(dorks)
}

func ClearAllWaybackCache() error {
	return clearAllWaybackCache()
}

func CleanupWaybackCache(maxAgeDays int, maxSizeBytes int64) (int, error) {
	return cleanupWaybackCache(maxAgeDays, maxSizeBytes)
}
