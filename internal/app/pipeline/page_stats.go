package pipeline

// PageStats tracks statistics per page for save mode.
type PageStats struct {
	PageNum      int
	TotalResults int
	UniqueNew    int
	SeenBefore   int
}

// trackPageStats analyzes if pagination should continue.
func trackPageStats(stats []PageStats) bool {
	if len(stats) < 3 {
		return true // Need at least 3 pages.
	}

	// Get last two pages.
	last := stats[len(stats)-1]
	secondLast := stats[len(stats)-2]

	// Stop if last two pages had < 5 unique results combined.
	if last.UniqueNew+secondLast.UniqueNew < 5 {
		return false
	}

	// Stop if last two pages had 0 unique.
	if last.UniqueNew == 0 && secondLast.UniqueNew == 0 {
		return false
	}

	return true
}
