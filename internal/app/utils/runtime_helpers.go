package utils

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	googleQuotaResetHour = 0
	braveQuotaResetDay   = 1
	maxWaitMinutes       = 30
)

// PostFilterResults applies post-filtering to remove URLs based on exclusions
// This is necessary because search engines (especially Brave) don't always respect exclusion operators
func PostFilterResults(results []string, exclusions string, target string) []string {
	if exclusions == "" {
		return results
	}

	// Check if www exclusion is present
	excludeWWW := strings.Contains(exclusions, "-www")
	if !excludeWWW {
		return results
	}

	// Filter out www.* URLs
	filtered := []string{}
	wwwPrefix := "www." + target
	for _, url := range results {
		// Check if URL contains www.Target
		if strings.Contains(url, "://www.") || strings.Contains(url, "://"+wwwPrefix) {
			continue // Skip www URLs
		}
		filtered = append(filtered, url)
	}

	return filtered
}

// CheckGeminiCLI checks if gemini-cli is installed
func CheckGeminiCLI() error {
	_, err := exec.LookPath("gemini-cli")
	if err != nil {
		return fmt.Errorf("gemini-cli not found. Install it with: npm install -g @google/generative-ai-cli")
	}
	return nil
}

// CheckStdin returns true if data is available on stdin
func CheckStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// calculateGoogleKeyResetTime estimates when Google API keys will refresh (daily reset)
func calculateGoogleKeyResetTime() time.Duration {
	now := time.Now().UTC()

	// Google CSE quota typically resets at midnight Pacific Time
	// Convert to UTC (Pacific Time is UTC-8 or UTC-7 depending on DST)
	pacificOffset := 8 * time.Hour // Simplified: assume PST (UTC-8)

	// Calculate next midnight Pacific in UTC
	nextReset := time.Date(now.Year(), now.Month(), now.Day(), googleQuotaResetHour, 0, 0, 0, time.UTC).Add(pacificOffset)

	// If we've passed today's reset, move to tomorrow
	if now.After(nextReset) {
		nextReset = nextReset.Add(24 * time.Hour)
	}

	return time.Until(nextReset)
}

// calculateBraveKeyResetTime estimates when Brave API keys will refresh (monthly reset)
func calculateBraveKeyResetTime() time.Duration {
	now := time.Now().UTC()

	// Brave quota resets on the 1st of each month at midnight UTC
	nextReset := time.Date(now.Year(), now.Month(), braveQuotaResetDay, 0, 0, 0, 0, time.UTC)

	// If we've passed this month's reset, move to next month
	if now.After(nextReset) || now.Day() >= braveQuotaResetDay {
		// Move to first day of next month
		if now.Month() == time.December {
			nextReset = time.Date(now.Year()+1, time.January, braveQuotaResetDay, 0, 0, 0, 0, time.UTC)
		} else {
			nextReset = time.Date(now.Year(), now.Month()+1, braveQuotaResetDay, 0, 0, 0, 0, time.UTC)
		}
	}

	return time.Until(nextReset)
}

// WaitForKeyRefresh waits for API keys to refresh with periodic retry
func WaitForKeyRefresh(ctx context.Context, engine string, verbose bool) error {
	var resetTime time.Duration
	var resetMsg string

	if engine == "google" {
		resetTime = calculateGoogleKeyResetTime()
		resetMsg = "Google API keys quota resets daily"
	} else if engine == "brave" {
		resetTime = calculateBraveKeyResetTime()
		resetMsg = "Brave API keys quota resets monthly"
	} else {
		return fmt.Errorf("unknown Engine: %s", engine)
	}

	maxWait := time.Duration(maxWaitMinutes) * time.Minute
	waitTime := resetTime
	if waitTime > maxWait {
		waitTime = maxWait
	}

	hours := int(resetTime.Hours())
	minutes := int(resetTime.Minutes()) % 60

	// ALL output to stderr
	fmt.Fprintf(os.Stderr, "\n[!] All %s API keys exhausted\n", engine)
	fmt.Fprintf(os.Stderr, "[*] %s in approximately %dh %dm\n", resetMsg, hours, minutes)
	fmt.Fprintf(os.Stderr, "[*] Waiting %d minutes before retrying...\n", int(waitTime.Minutes()))
	fmt.Fprintf(os.Stderr, "[*] Press Ctrl+C to cancel\n")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	deadline := time.Now().Add(waitTime)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "\n[!] Wait cancelled by user\n")
			return ctx.Err()

		case <-time.After(waitTime):
			fmt.Fprintf(os.Stderr, "\n[*] Retry period elapsed, attempting to use keys again...\n")
			return nil

		case <-ticker.C:
			remaining := time.Until(deadline)
			if remaining > 0 {
				mins := int(remaining.Minutes())
				secs := int(remaining.Seconds()) % 60
				if verbose {
					fmt.Fprintf(os.Stderr, "\r[*] Time until retry: %dm %ds    ", mins, secs)
				}
			}
		}
	}
}

// ReadStdin reads domains from stdin
func ReadStdin() ([]string, error) {
	var domains []string
	reader := bufio.NewReader(os.Stdin)

	for {
		line, err := reader.ReadString('\n')
		// Trim newline and surrounding whitespace
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, line)
		}

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return domains, nil
}
