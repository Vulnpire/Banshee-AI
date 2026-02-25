package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

func (c *Config) httpGetBraveJSON(ctx context.Context, query string, apiKey string, offset int) (*BraveResponse, int, int, error) {
	// Free tier: max offset 9, but count can be 20
	// Use count=20 to maximize results on first page (offset=0)
	u := fmt.Sprintf("%s?q=%s&count=20&offset=%d", core.BraveAPIURL, url.QueryEscape(query), offset)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, 0, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity") // Disable compression for proxy compatibility
	req.Header.Set("User-Agent", core.DefaultUserAgent)
	req.Header.Set("X-Subscription-Token", apiKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		console.Logv(c.Verbose, "[Brave] HTTP %d: %s", resp.StatusCode, string(body))
		return nil, resp.StatusCode, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, 0, fmt.Errorf("read body failed: %w", err)
	}

	// Return response size but don't log it here - will be logged with query
	responseSize := len(body)

	var br BraveResponse
	if err := json.Unmarshal(body, &br); err != nil {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		console.Logv(c.Verbose, "[Brave] JSON error. Preview: %s", preview)
		return nil, resp.StatusCode, responseSize, fmt.Errorf("decode error: %w", err)
	}

	return &br, resp.StatusCode, responseSize, nil
}

func (c *Config) braveSearch(ctx context.Context, query string, offset int) ([]string, error) {
	if len(c.BraveAPIKeys) == 0 {
		return nil, errors.New("no Brave API keys configured")
	}

	for {
		var lastErr error
		var triedKeys int
		maxTries := len(c.BraveAPIKeys)

		for triedKeys < maxTries {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			apiKey, err := c.getRandomBraveApiKey()
			if err != nil {
				// All keys exhausted or rate limited
				if strings.Contains(err.Error(), "rate limited") {
					// Wait 1 second and retry (rate limit issue)
					console.Logv(c.Verbose, "[Brave] All keys rate limited, waiting 1s...")
					time.Sleep(time.Second)
					continue
				}

				// All keys quota exhausted - wait for refresh
				if err := waitForKeyRefresh(ctx, "brave", c.Verbose); err != nil {
					return nil, err
				}

				// Clear exhausted keys and retry
				console.Logv(c.Verbose, "[Brave] Cleared exhausted keys, retrying...")
				c.ExhaustedBraveKeys = make(map[string]struct{})
				c.BraveKeyLastUsed = make(map[string]time.Time)
				continue // Retry from beginning
			}

			// Retry logic: up to 3 attempts for network errors
			var br *BraveResponse
			var statusCode int
			var responseSize int
			maxRetries := 3

			for attempt := 1; attempt <= maxRetries; attempt++ {
				br, statusCode, responseSize, err = c.httpGetBraveJSON(ctx, query, apiKey, offset)

				if err == nil {
					// Log combined query and response info on success
					console.Logv(c.Verbose, "[Brave] Query: %s | Response: %d bytes", query, responseSize)
					break
				}

				isNetworkError := strings.Contains(err.Error(), "timeout") ||
					strings.Contains(err.Error(), "dial tcp") ||
					strings.Contains(err.Error(), "EOF") ||
					strings.Contains(err.Error(), "connection refused") ||
					strings.Contains(err.Error(), "no such host")

				if isNetworkError && attempt < maxRetries {
					console.Logv(c.Verbose, "[Brave] Network error (attempt %d/%d): %v, retrying in 1s...", attempt, maxRetries, err)
					time.Sleep(time.Second)
					continue
				}

				break
			}

			// CRITICAL: Always wait 1 second after request to respect rate limit
			time.Sleep(time.Second)

			if err != nil {
				lastErr = err
				console.Logv(c.Verbose, "[Brave] Error: %v", err)

				if statusCode == 429 {
					c.ExhaustedBraveKeys[apiKey] = struct{}{}
				} else if statusCode == 401 || statusCode == 403 {
					c.ExhaustedBraveKeys[apiKey] = struct{}{}
				}

				triedKeys++
				continue
			}

			if br.Error != nil && br.Error.Message != "" {
				lastErr = fmt.Errorf("API error: %s", br.Error.Message)
				console.Logv(c.Verbose, "[Brave] %v", lastErr)

				// Check for query too long (422 error)
				if statusCode == 422 || br.Error.Code == 422 {
					console.Logv(c.Verbose, "[Brave] Query too long for Brave API (max 400 chars), skipping")
					return []string{}, nil
				}

				if statusCode == 429 || br.Error.Code == 429 {
					c.ExhaustedBraveKeys[apiKey] = struct{}{}
				}
				triedKeys++
				continue
			}

			if br.Web == nil || len(br.Web.Results) == 0 {
				console.Logv(c.Verbose, "[Brave] No results")
				return []string{}, nil
			}

			var links []string
			for _, result := range br.Web.Results {
				if result.URL != "" {
					links = append(links, result.URL)
				}
			}

			// Check if we're in cloud enumeration mode (either by flag or by query content)
			isCloudMode := strings.ToLower(c.RandomFocus) == "cloud" ||
				strings.ToLower(c.RandomFocus) == "cloud-assets" ||
				strings.ToLower(c.RandomFocus) == "s3" ||
				strings.ToLower(c.RandomFocus) == "azure" ||
				strings.ToLower(c.RandomFocus) == "gcp" ||
				isCloudDork(query)

			filtered := filterLinks(links, c.Target, isCloudMode)
			console.Logv(c.Verbose, "[Brave] Found %d results", len(filtered))

			return filtered, nil
		}

		// All keys failed - wait for refresh
		if lastErr != nil {
			console.Logv(c.Verbose, "[Brave] All keys failed: %v", lastErr)
		}

		if err := waitForKeyRefresh(ctx, "brave", c.Verbose); err != nil {
			return nil, err
		}

		// Clear exhausted keys and retry
		console.Logv(c.Verbose, "[Brave] Cleared exhausted keys, retrying...")
		c.ExhaustedBraveKeys = make(map[string]struct{})
		c.BraveKeyLastUsed = make(map[string]time.Time)
		// Loop continues to retry
	}
}
