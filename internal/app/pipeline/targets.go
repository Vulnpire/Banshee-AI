package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

func (c *Config) readDomainsFile(ctx context.Context) error {
	lines, err := readLines(c.DomainsFile)
	if err != nil {
		return fmt.Errorf("[!] Error, file not found: %s", c.DomainsFile)
	}

	// Reuse shared multi-domain logic so stdin and file inputs behave identically
	return c.processDomainsFromList(ctx, lines)
}

func (c *Config) processDomainsFromList(ctx context.Context, domains []string) error {
	if c.FindApex {
		if c.ApexResolved {
			if len(c.ApexTargets) > 0 {
				domains = c.ApexTargets
			}
		} else {
			expanded, err := c.resolveApexTargets(ctx, domains)
			if err != nil {
				return err
			}
			if len(expanded) > 0 {
				domains = expanded
			}
		}
	}

	// Random mode: generate random dorks for each domain
	if c.RandomMode {
		for i, target := range domains {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}

			c2 := *c
			c2.Target = target

			if c.Verbose && len(domains) > 1 {
				console.Logv(c.Verbose, "\n[%d/%d] Target: %s", i+1, len(domains), target)
			}

			// Generate random dorks for this domain
			var dorks []string
			var err error
			if c2.ResearchMode {
				researchData, researchErr := c2.performOSINTResearch(ctx, target)
				if researchErr != nil {
					console.LogErr("[!] Failed to perform OSINT research for %s: %v", target, researchErr)
					console.LogErr("[!] Falling back to standard random dork generation for %s", target)
					dorks, err = c2.generateRandomDorks(ctx)
				} else {
					dorks, err = c2.generateResearchBasedDorks(ctx, target, researchData)
				}
			} else {
				dorks, err = c2.generateRandomDorks(ctx)
			}
			if err != nil {
				console.LogErr("[!] Failed to generate random dorks for %s: %v", target, err)
				continue
			}

			if len(dorks) > 0 {
				c2.multiDorkAttack(ctx, dorks)
			}

			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		c.printApexSummary()
		return nil
	}

	// Preload AI prompts from file (if provided) so each target gets full SMART/LEARN pipelines
	var prompts []string
	if c.AiPrompt != "" && fileExists(c.AiPrompt) {
		loadedPrompts, err := readLines(c.AiPrompt)
		if err != nil {
			return fmt.Errorf("failed to read AI prompts file: %w", err)
		}
		if len(loadedPrompts) == 0 {
			return fmt.Errorf("no prompts found in file: %s", c.AiPrompt)
		}
		prompts = loadedPrompts
		console.Logv(c.Verbose, "[AI] Loaded %d prompts from file\n", len(prompts))
	}

	// Process each domain
	for i, target := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		c2 := *c
		c2.Target = target

		if c.Verbose && len(domains) > 1 {
			console.Logv(c.Verbose, "\n[%d/%d] Target: %s", i+1, len(domains), target)
		}

		// Detect target language for multi-lang on a per-domain basis
		if c2.MultiLang {
			c2.TargetLanguage = c2.detectTargetLanguage(ctx)
			if c2.TargetLanguage == "" {
				console.Logv(c2.Verbose, "[MULTI-LANG] Language detection failed, defaulting to English")
				c2.TargetLanguage = "en"
			} else {
				if c2.TargetLanguage != "en" {
					portion := c2.MultiLangMultiplier
					if portion < 0 || portion > 100 {
						portion = 25
					}
					console.Logv(c2.Verbose, "[MULTI-LANG] Will generate %d%% of dorks in target's language to save API quota", portion)
				} else {
					console.Logv(c2.Verbose, "[MULTI-LANG] Target uses English, no translation needed")
				}
			}
		}

		// Wayback Machine passive reconnaissance (if -foresee mode is enabled)
		var waybackIntel *core.WaybackIntelligence
		if c2.ForeseeMode {
			// Try to load cached intelligence first (unless --no-wayback-cache is set)
			if !c2.NoWaybackCache {
				waybackIntel, _ = loadWaybackIntelligence(target)
				if waybackIntel != nil {
					console.Logv(c2.Verbose, "[WAYBACK] Using cached intelligence (generated %s)", waybackIntel.ProcessedAt.Format("2006-01-02 15:04"))
				}
			}

			// If no cache, query Wayback
			if waybackIntel == nil {
				urls, err := queryWaybackCDX(ctx, target, c2.WaybackStatusCodes, c2.Verbose)
				if err == nil && len(urls) > 0 {
					// Apply exclusion filters if specified
					if c2.Exclusions != "" {
						urls = filterExcludedURLs(urls, c2.Exclusions, c2.Verbose)
					}

					// Extract and save intelligence
					if len(urls) > 0 {
						waybackIntel = extractWaybackIntelligence(target, urls, c2.Verbose)
						if waybackIntel != nil {
							if err := saveWaybackIntelligence(target, waybackIntel); err != nil {
								console.Logv(c2.Verbose, "[WAYBACK] Warning: Failed to save Intelligence: %v", err)
							}
						}
					}
				}
			}

			// Store wayback intelligence for Smart mode integration
			if waybackIntel != nil {
				c2.WaybackIntelligence = waybackIntel
			}
		}

		// AI mode: run full AI pipeline per target so SMART/LEARN/RESEARCH all work with stdin lists
		if c2.AiPrompt != "" {
			if len(prompts) > 0 {
				c2.aiDorkAttackMultiplePrompts(ctx, prompts)
			} else if c2.ResearchMode {
				if c2.Verbose {
					fmt.Fprintf(os.Stderr, "Research Mode: OSINT depth %d\n", c2.ResearchDepth)
				}

				researchData, researchErr := c2.performOSINTResearch(ctx, target)
				if researchErr != nil {
					console.LogErr("[!] Failed to perform OSINT research for %s: %v", target, researchErr)
					console.LogErr("[!] Falling back to standard AI dork generation for %s", target)
					c2.aiDorkAttack(ctx)
				} else {
					dorks, err := c2.generateResearchBasedDorks(ctx, target, researchData)
					if err != nil {
						console.LogErr("[!] Failed to generate research-based dorks for %s: %v", target, err)
						console.LogErr("[!] Falling back to standard AI dork generation for %s", target)
						c2.aiDorkAttack(ctx)
					} else if len(dorks) > 0 {
						c2.multiDorkAttack(ctx, dorks)
					} else {
						console.LogErr("[!] No research-based dorks generated for %s, falling back to standard AI mode", target)
						c2.aiDorkAttack(ctx)
					}
				}
			} else {
				c2.aiDorkAttack(ctx)
			}

			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}

		if c2.Dork != "" {
			// Check if dork is a file
			if fileExists(c2.Dork) {
				dorks, err := readLines(c2.Dork)
				if err != nil {
					console.LogErr("[!] Error reading dorks file: %v", err)
					continue
				}
				c2.multiDorkAttack(ctx, dorks)
			} else {
				res := c2.dorkRun(ctx, "")
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if len(res) == 0 {
					c2.notFound()
				} else {
					outputOrPrintUnique(res, c2.OutputPath)
				}
			}
		} else if c2.Extension != "" {
			c2.extensionAttack(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		} else if c2.Dictionary != "" {
			c2.dictionaryAttack(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		} else if c2.SubdomainMode {
			c2.subdomainAttack(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		} else if c2.Contents != "" {
			c2.contentsAttack(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
	c.printApexSummary()
	return nil
}

// dorkRun is the central querying routine
func (c *Config) dorkRun(ctx context.Context, ext string) []string {
	c.RequestStore = nil
	page := 0
	c.RequestCounter = 0
	c.NoResultCounter = 0
	c.ResultsFound = false
	if c.Pages == 0 {
		c.Pages = 10
	}

	useGoogle := (c.Engine == "both" || c.Engine == "google") && len(c.ApiKeys) > 0
	useBrave := (c.Engine == "both" || c.Engine == "brave") && len(c.BraveAPIKeys) > 0
	braveUsed := false // Track if we already used Brave (free tier: 1 page only)

	// SAVE MODE: Track page statistics for diminishing returns detection
	var pageStats []PageStats
	seenURLs := make(map[string]bool)

	for page < c.Pages {
		if ctx.Err() != nil {
			return c.RequestStore
		}

		startIdx := page*10 + 1
		var allResults []string

		// Build queries
		queries := c.buildQueries(ext)

		// Try Brave on first page only (free tier: offset must be 0 for max results)
		if useBrave && !braveUsed {
			bravePageResults := 0
			for _, query := range queries {
				if ctx.Err() != nil {
					return c.RequestStore
				}

				// Convert Google dork syntax to Brave-compatible format
				braveQuery := convertToBraveDork(query)

				// Always use offset=0 for free tier (gets max results)
				offset := 0
				braveResults, err := c.braveSearch(ctx, braveQuery, offset)
				if err != nil {
					console.Logv(c.Verbose, "Brave search failed: %v", err)

					if strings.Contains(err.Error(), "exhausted") || strings.Contains(err.Error(), "rate limited") {
						useBrave = false
						break
					}
				} else if len(braveResults) > 0 {
					// Apply post-filtering for www exclusion
					originalCount := len(braveResults)
					braveResults = postFilterResults(braveResults, c.ExcludeTargets, c.Target)
					if len(braveResults) < originalCount {
						console.Logv(c.Verbose, "[Brave] Filtered out %d www.* URLs", originalCount-len(braveResults))
					}
					// Apply out-of-scope filtering
					if len(c.OosPatterns) > 0 {
						beforeOOS := len(braveResults)
						braveResults, _ = filterOOSResults(braveResults, c.OosPatterns)
						if len(braveResults) < beforeOOS {
							console.Logv(c.Verbose, "[Brave] Filtered out %d out-of-scope URLs", beforeOOS-len(braveResults))
						}
					}
					allResults = append(allResults, braveResults...)
					bravePageResults += len(braveResults)
				}
			}
			if bravePageResults > 0 {
				console.Logv(c.Verbose, "[Brave] Page 1: %d results (free tier: 1 page max)", bravePageResults)
			}
			braveUsed = true // Only query Brave once on free tier
		}

		// Try Google if enabled
		if useGoogle {
			googleResults := c.googleSearch(ctx, queries, startIdx)
			if len(googleResults) > 0 {
				// Apply post-filtering for www exclusion
				originalCount := len(googleResults)
				googleResults = postFilterResults(googleResults, c.ExcludeTargets, c.Target)
				if len(googleResults) < originalCount {
					console.Logv(c.Verbose, "[Google] Filtered out %d www.* URLs", originalCount-len(googleResults))
				}
				// Apply out-of-scope filtering
				if len(c.OosPatterns) > 0 {
					beforeOOS := len(googleResults)
					googleResults, _ = filterOOSResults(googleResults, c.OosPatterns)
					if len(googleResults) < beforeOOS {
						console.Logv(c.Verbose, "[Google] Filtered out %d out-of-scope URLs", beforeOOS-len(googleResults))
					}
				}
				allResults = append(allResults, googleResults...)
				console.Logv(c.Verbose, "[Google] Page %d: %d results", page+1, len(googleResults))
				// If we got fewer than 10 results, stop further Google pagination to save quota
				if len(googleResults) < 10 {
					useGoogle = false
				}
			} else if len(c.ApiKeys) > 0 {
				if len(c.ExhaustedKeys) >= len(c.ApiKeys) {
					useGoogle = false
				}
			}
		}

		// Process combined results
		allResults = uniqueStrings(allResults)

		// SAVE MODE: Track unique new results
		uniqueNew := 0
		seenBefore := 0
		if c.SaveMode {
			for _, url := range allResults {
				if !seenURLs[url] {
					seenURLs[url] = true
					uniqueNew++
				} else {
					seenBefore++
				}
			}
			pageStats = append(pageStats, PageStats{
				PageNum:      page + 1,
				TotalResults: len(allResults),
				UniqueNew:    uniqueNew,
				SeenBefore:   seenBefore,
			})
			console.Logv(c.Verbose, "[SAVE] Page %d: %d new, %d seen before", page+1, uniqueNew, seenBefore)
		}

		if len(allResults) > 0 {
			c.RequestStore = append(c.RequestStore, allResults...)
			c.ResultsFound = true
			c.NoResultCounter = 0
			c.RequestCounter++
			if c.Delay == 0 && c.DynamicDelay > 0.05 {
				c.DynamicDelay -= 0.05
			}
		} else {
			c.NoResultCounter++
			if c.Delay == 0 {
				c.DynamicDelay += 0.1
			}
			if !c.ResultsFound {
				break
			}
		}

		c.ResultsFound = false
		page++

		// SAVE MODE: Check if we should stop pagination
		if c.SaveMode && len(pageStats) >= 3 {
			if !trackPageStats(pageStats) {
				console.Logv(c.Verbose, "[SAVE] Diminishing returns detected, stopping pagination")
				break
			}
		}

		if !useGoogle && braveUsed && len(c.ApiKeys) == 0 {
			console.Logv(c.Verbose, "[Info] Brave free tier exhausted (1 page), no Google keys available")
			break
		}
	}

	if len(c.RequestStore) == 0 {
		c.notFound()
		return nil
	}

	// Summary will be printed by the caller after all dorks are processed
	return c.RequestStore
}

func (c *Config) buildQueries(ext string) []string {
	withExcl := func(q string) string {
		if c.ExcludeTargets != "" {
			exclusions := c.ExcludeTargets
			// Handle -www exclusion: just use -www as-is (correct Google dork syntax)
			// Only skip if query already has -www to avoid duplicates
			if strings.Contains(exclusions, "-www") && strings.Contains(q, "-www") {
				// Query already has -www, remove it from exclusions to avoid duplicate
				exclusions = strings.ReplaceAll(exclusions, "-www", "")
				exclusions = strings.TrimSpace(exclusions)
			}
			// Note: -www works for both wildcard and non-wildcard queries
			// Example: site:dell.com -www excludes www.dell.com
			// Example: site:*.dell.com -www excludes www.dell.com
			if exclusions != "" {
				q = q + " " + exclusions
			}
		}
		return q
	}

	var queries []string

	switch {
	case c.Dork != "":
		// Check if dork already contains site: to avoid duplication
		dorkToUse := c.Dork
		if strings.Contains(strings.ToLower(c.Dork), "site:") || c.Target == "" {
			// Dork already has site: OR no target specified (universal search) - use as-is
			queries = append(queries, withExcl(dorkToUse))
		} else {
			// Dork doesn't have site: and target is specified - add it
			if c.IncludeSubdomains {
				queries = append(queries,
					withExcl(fmt.Sprintf("site:*.%s %s -www.%s", c.Target, dorkToUse, c.Target)),
					withExcl(fmt.Sprintf("site:*.*.%s %s", c.Target, dorkToUse)),
					withExcl(fmt.Sprintf("site:*.*.*.%s %s", c.Target, dorkToUse)),
					withExcl(fmt.Sprintf("site:*.%s %s -www.%s -blog.%s -support.%s -cdn.%s -docs.%s",
						c.Target, dorkToUse, c.Target, c.Target, c.Target, c.Target, c.Target)),
				)
			} else {
				queries = append(queries, withExcl(fmt.Sprintf("site:%s %s", c.Target, dorkToUse)))
			}
		}

	case ext != "":
		extToken := strings.TrimSpace(ext)
		buildQ := func(scope string) []string {
			return []string{
				withExcl(fmt.Sprintf(`%s filetype:%s`, scope, extToken)),
				withExcl(fmt.Sprintf(`%s ext:%s`, scope, extToken)),
			}
		}
		if c.IncludeSubdomains {
			for _, scope := range []string{
				fmt.Sprintf("site:%s", c.Target),
				fmt.Sprintf("site:*.%s", c.Target),
				fmt.Sprintf("site:*.*.%s", c.Target),
				fmt.Sprintf("site:*.*.*.%s", c.Target),
			} {
				queries = append(queries, buildQ(scope)...)
			}
		} else {
			queries = append(queries, buildQ(fmt.Sprintf("site:%s", c.Target))...)
		}

	case c.Dictionary != "":
		var terms []string
		if c.InUrl != "" {
			terms = strings.Split(c.InUrl, "|||")
		}
		if len(terms) == 0 {
			terms = []string{c.Dictionary}
		}
		buildQ := func(prefix, term string) string {
			q := fmt.Sprintf(`%s inurl:"%s"`, prefix, strings.TrimSpace(term))
			return withExcl(q)
		}
		if c.IncludeSubdomains {
			for _, t := range terms {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				queries = append(queries,
					buildQ(fmt.Sprintf("site:*.%s", c.Target), t),
					buildQ(fmt.Sprintf("site:*.*.%s", c.Target), t),
					buildQ(fmt.Sprintf("site:*.*.*.%s", c.Target), t),
				)
			}
		} else {
			for _, t := range terms {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				queries = append(queries, buildQ(fmt.Sprintf("site:%s", c.Target), t))
			}
		}

	case c.Contents != "":
		buildQ := func(prefix string) string {
			return withExcl(fmt.Sprintf(`%s %s`, prefix, c.InFile))
		}
		if c.IncludeSubdomains {
			queries = append(queries,
				buildQ(fmt.Sprintf("site:*.%s", c.Target)),
				buildQ(fmt.Sprintf("site:*.*.%s", c.Target)),
				buildQ(fmt.Sprintf("site:*.*.*.%s", c.Target)),
			)
		} else {
			queries = append(queries, buildQ(fmt.Sprintf("site:%s", c.Target)))
		}

	default:
		// Default case should only be reached with a target specified
		if c.Target != "" {
			queries = append(queries, withExcl(fmt.Sprintf("site:%s", c.Target)))
		}
	}

	return queries
}

func (c *Config) googleSearch(ctx context.Context, queries []string, startIdx int) []string {
	var triedKeys int
	maxTries := len(c.ApiKeys)

	for triedKeys < maxTries {
		if ctx.Err() != nil {
			return nil
		}

		apiKey, err := c.getRandomApiKey()
		if err != nil || apiKey == "" {
			// All keys exhausted - but don't wait, just return empty
			console.Logv(c.Verbose, "[Google] All API keys exhausted")
			return nil
		}

		base := fmt.Sprintf("%s?key=%s&cx=%s&start=%d", core.DefaultAPIURL, url.QueryEscape(apiKey), url.QueryEscape(core.DefaultCX), startIdx)

		var combined []string
		var respErr error

		for _, query := range queries {
			if ctx.Err() != nil {
				return combined
			}

			u := base + "&q=" + url.QueryEscape(strings.TrimSpace(query))

			// Retry logic for network errors
			var gr *GoogleResponse
			var responseSize int
			maxRetries := 3

			for attempt := 1; attempt <= maxRetries; attempt++ {
				gr, _, responseSize, err = c.httpGetJSON(ctx, u)

				if err == nil {
					break
				}

				isNetworkError := strings.Contains(err.Error(), "timeout") ||
					strings.Contains(err.Error(), "dial tcp") ||
					strings.Contains(err.Error(), "EOF") ||
					strings.Contains(err.Error(), "connection refused")

				if isNetworkError && attempt < maxRetries {
					console.Logv(c.Verbose, "[Google] Network error (attempt %d/%d), retrying in 1s...", attempt, maxRetries)
					time.Sleep(time.Second)
					continue
				}

				break
			}

			if err != nil {
				respErr = err
				continue
			}

			if startIdx == 1 {
				console.Logv(c.Verbose, "[Google] Query: %s | Response: %d bytes", query, responseSize)
			}

			if gr.Error != nil && gr.Error.Message != "" {
				if strings.Contains(strings.ToLower(gr.Error.Message), "quota") {
					c.ExhaustedKeys[apiKey] = struct{}{}
				}
				respErr = errors.New(gr.Error.Message)
				continue
			}

			var links []string
			for _, it := range gr.Items {
				links = append(links, it.Link)
			}

			// Check if we're in cloud enumeration mode (either by flag or by query content)
			isCloudMode := strings.ToLower(c.RandomFocus) == "cloud" ||
				strings.ToLower(c.RandomFocus) == "cloud-assets" ||
				strings.ToLower(c.RandomFocus) == "s3" ||
				strings.ToLower(c.RandomFocus) == "azure" ||
				strings.ToLower(c.RandomFocus) == "gcp" ||
				isCloudDork(query)

			links = filterLinks(links, c.Target, isCloudMode)
			combined = append(combined, links...)
		}

		combined = uniqueStrings(combined)
		if len(combined) > 0 {
			return combined
		}

		if respErr != nil {
			console.Logv(c.Verbose, "Google API Error: %v", respErr)
			triedKeys++
		} else {
			c.delayControl()
			triedKeys = maxTries
		}
		c.delayControl()
	}

	// All keys tried, return empty (don't wait)
	return nil
}

func (c *Config) dictionaryAttack(ctx context.Context) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "Target: %s\n", c.Target)
	}
	if c.InUrl == "" {
		c.InUrl = buildInurlQuery(c.Dictionary)
	}
	res := c.dorkRun(ctx, "")
	if len(res) == 0 {
		c.notFound()
		return
	}
	if c.OutputPath != "" {
		outputOrPrintUnique(res, c.OutputPath)
	} else {
		outputOrPrintUnique(res, "")
	}
}

func (c *Config) extensionAttack(ctx context.Context) {
	var exts []string
	if fileExists(c.Extension) {
		lines, _ := readLines(c.Extension)
		exts = lines
	} else if strings.Contains(c.Extension, ",") {
		for _, t := range strings.Split(c.Extension, ",") {
			if s := strings.TrimSpace(t); s != "" {
				exts = append(exts, s)
			}
		}
	} else if c.Extension != "" {
		exts = []string{strings.TrimSpace(c.Extension)}
	}

	var all []string
	for _, ext := range exts {
		select {
		case <-ctx.Done():
			console.LogErr("Operation cancelled: %v", ctx.Err())
			return
		default:
		}
		if c.Verbose {
			fmt.Printf("Checking Extension: %s\n", ext)
		}
		res := c.dorkRun(ctx, ext)
		if len(res) > 0 {
			all = append(all, res...)
		}
	}

	if len(all) == 0 {
		c.notFound()
		return
	}
	all = uniqueStrings(all)
	if c.OutputPath != "" {
		outputOrPrintUnique(all, c.OutputPath)
	} else {
		for _, u := range all {
			fmt.Println(u)
		}
	}
}

func (c *Config) performExtensionRequest(ctx context.Context, ext string) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "Checking Extension: %s\n", ext)
	}
	res := c.dorkRun(ctx, ext)
	if len(res) == 0 {
		c.notFound()
		return
	}
	c.showContentInFile()
	if c.OutputPath != "" {
		outputOrPrintUnique(res, c.OutputPath)
	}
}

func (c *Config) subdomainAttack(ctx context.Context) {
	// If AI is enabled (learn mode, ai prompt, or random mode), use AI-powered subdomain discovery
	if c.LearnMode || c.AiPrompt != "" || c.RandomMode {
		c.aiSubdomainAttack(ctx)
		return
	}

	// Default subdomain attack (original behavior)
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "Target: %s\n", c.Target)
	}
	res := c.dorkRun(ctx, "")
	if len(res) == 0 {
		c.notFound()
		return
	}
	// Print subdomains (awk -F/ '{print $3}' | sort -u)
	hostSet := map[string]struct{}{}
	for _, u := range res {
		h := hostOf(u)
		if h != "" && !strings.HasPrefix(h, "www.") {
			hostSet[h] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if c.OutputPath != "" {
		outputOrPrintUnique(hosts, c.OutputPath)
	} else {
		for _, h := range hosts {
			fmt.Println(h)
		}
	}
}

// aiSubdomainAttack uses AI to generate specialized dorks for subdomain discovery
func (c *Config) aiSubdomainAttack(ctx context.Context) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "Target: %s\n", c.Target)
		fmt.Fprintf(os.Stderr, "AI-powered subdomain enumeration\n")
	}

	// Load intelligence if in learn mode
	if c.LearnMode && c.Intelligence == nil {
		c.Intelligence = loadTargetIntelligence(c.Target)
		if c.Intelligence != nil && c.Intelligence.TotalScans > 0 {
			console.Logv(c.Verbose, "[LEARN] Loaded Intelligence: %d previous scans, %d discovered subdomains",
				c.Intelligence.TotalScans, len(c.Intelligence.DiscoveredSubdomains))
		}
	}

	// Generate subdomain-focused dorks using AI
	dorks, err := c.generateSubdomainDorks(ctx)
	if err != nil {
		console.LogErr("[!] Failed to generate subdomain dorks: %v", err)
		// Fallback to default behavior
		console.Logv(c.Verbose, "[AI] Falling back to default subdomain search")
		res := c.dorkRun(ctx, "")
		if len(res) > 0 {
			c.printSubdomains(res)
		} else {
			c.notFound()
		}
		return
	}

	if len(dorks) == 0 {
		console.LogErr("[!] No subdomain dorks were generated")
		c.notFound()
		return
	}

	// Execute each dork and collect all results
	var allResults []string
	dorkResults := make(map[string][]string)
	hostSet := map[string]struct{}{}

	for i, dork := range dorks {
		if ctx.Err() != nil {
			console.LogErr("[!] Operation cancelled")
			break
		}

		console.Logv(c.Verbose, "\n[AI] Executing dork %d/%d: %s", i+1, len(dorks), dork)

		originalDork := c.Dork
		c.Dork = dork
		results := c.dorkRun(ctx, "")
		c.Dork = originalDork

		if len(results) > 0 {
			allResults = append(allResults, results...)
			dorkResults[dork] = results
			console.Logv(c.Verbose, "[AI] Dork %d found %d results", i+1, len(results))

			// Extract hosts
			for _, u := range results {
				h := hostOf(u)
				if h != "" && !strings.HasPrefix(h, "www.") {
					hostSet[h] = struct{}{}
				}
			}
		} else {
			dorkResults[dork] = []string{}
			console.Logv(c.Verbose, "[AI] Dork %d found 0 results", i+1)
		}

		if i < len(dorks)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	// Update intelligence if in learn mode
	if c.LearnMode && c.Intelligence != nil {
		updateIntelligenceWithResults(c.Intelligence, dorks, dorkResults)
		if err := saveTargetIntelligence(c.Intelligence); err != nil {
			console.Logv(c.Verbose, "[LEARN] Warning: Failed to save Intelligence: %v", err)
		} else {
			console.Logv(c.Verbose, "[LEARN] Intelligence updated and saved")
		}
	}

	// SMART MODE: Post-scan optimization - analyze dorks and suggest improvements
	if c.SmartMode && len(dorkResults) > 0 {
		optimized, err := c.optimizeDorks(ctx, dorkResults)
		if err != nil {
			console.Logv(c.Verbose, "[SMART] Warning: Failed to optimize dorks: %v", err)
		} else if optimized != nil {
			c.displayOptimizedDorks(optimized)
		}
	}

	// Output subdomains
	if len(hostSet) == 0 {
		c.notFound()
		return
	}

	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	// DEEP MODE: Recursively discover sub-subdomains
	if c.DeepMode && len(hosts) > 0 {
		console.Logv(c.Verbose, "\n[DEEP] Starting recursive subdomain discovery (max depth: 3)")
		maxDepth := 3
		for _, subdomain := range hosts {
			if ctx.Err() != nil {
				break
			}
			deeperHosts := c.recursivelyDiscoverSubdomains(ctx, subdomain, 0, maxDepth)
			for _, dh := range deeperHosts {
				if _, exists := hostSet[dh]; !exists {
					hostSet[dh] = struct{}{}
					hosts = append(hosts, dh)
				}
			}
		}
		sort.Strings(hosts)
		console.Logv(c.Verbose, "[DEEP] Total subdomains after recursive discovery: %d", len(hosts))
	}

	console.Logv(c.Verbose, "\n[AI] Total unique subdomains found: %d", len(hosts))

	if c.OutputPath != "" {
		outputOrPrintUnique(hosts, c.OutputPath)
	} else {
		for _, h := range hosts {
			fmt.Println(h)
		}
	}
}

// generateSubdomainDorks generates AI-powered dorks for subdomain discovery
func (c *Config) generateSubdomainDorks(ctx context.Context) ([]string, error) {
	if err := checkGeminiCLI(); err != nil {
		return nil, err
	}

	// Use default quantity if not set
	if c.AiQuantity == 0 {
		c.AiQuantity = 10
	}

	// Build intelligence context
	intelligenceContext := ""
	if c.LearnMode && c.Intelligence != nil && c.Intelligence.TotalScans > 0 {
		intelligenceContext = "\n\n" + generateLearnedPrompt(c.Intelligence, "discover subdomains and assets", "subdomain")
		console.Logv(c.Verbose, "[LEARN] Enhanced subdomain discovery with historical intelligence")
	}

	systemInstructions := fmt.Sprintf(`You are a subdomain enumeration expert using Google dorking.

CRITICAL RULES:
1. Output ONLY dorks, one per line
2. NO explanations, NO numbering, NO markdown
3. ONLY use site:*.%s for subdomain discovery
4. DO NOT use pipe character |
5. Use OR (uppercase) if combining terms
6. Keep dorks simple and focused

EFFECTIVE SUBDOMAIN DISCOVERY METHODS:

Basic Discovery:
- site:*.%s -www (exclude www, find other subdomains)
- site:*.%s (all subdomains)

Targeted Subdomain Patterns:
- site:*.%s inurl:admin (admin subdomains)
- site:*.%s inurl:api (API subdomains)
- site:*.%s inurl:dev (development subdomains)
- site:*.%s inurl:staging (staging environments)
- site:*.%s inurl:test (test environments)
- site:*.%s inurl:uat (UAT environments)
- site:*.%s inurl:beta (beta versions)
- site:*.%s inurl:internal (internal resources)

Content-Based Discovery:
- site:*.%s intitle:"login" (login pages reveal subdomains)
- site:*.%s intitle:"dashboard" (dashboards)
- site:*.%s intitle:"admin" (admin panels)
- site:*.%s intitle:"portal" (portals)

Technology-Specific:
- site:*.%s inurl:jenkins (CI/CD)
- site:*.%s inurl:gitlab (version control)
- site:*.%s inurl:jira (project management)
- site:*.%s inurl:confluence (wikis)
- site:*.%s inurl:grafana (monitoring)
- site:*.%s inurl:kibana (logging)

File-Based Discovery:
- site:*.%s filetype:pdf (documents on subdomains)
- site:*.%s filetype:xml (XML files - often on APIs)
- site:*.%s filetype:json (JSON endpoints)

IMPORTANT:
- Each dork should be SIMPLE and FOCUSED
- Do NOT combine multiple searches with OR unless necessary
- Do NOT use cloud storage sites (s3.amazonaws.com) - that's asset discovery, not subdomain discovery
- Focus on finding pages that exist on SUBDOMAINS of %s

%s

Generate EXACTLY %d simple, effective subdomain discovery dorks. Output only the dorks, nothing else.`,
		c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target,
		c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target,
		c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target,
		c.Target, intelligenceContext, c.AiQuantity)

	userPrompt := fmt.Sprintf("Generate %d simple Google search dorks to discover subdomains of %s using site:*.%s operator. Focus on realistic subdomain patterns.",
		c.AiQuantity, c.Target, c.Target)

	console.Logv(c.Verbose, "[AI] Generating %d subdomain discovery dorks...", c.AiQuantity)

	// Execute with same method as other AI functions
	var args []string

	if c.AiModel != "" {

		args = []string{"--model", c.AiModel, "-p", userPrompt}

	} else {

		args = []string{"-p", userPrompt}

	}

	cmd := exec.Command("gemini-cli", args...)
	cmd.Stdin = strings.NewReader(systemInstructions)
	cmd.Env = os.Environ()
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}

	_, cmdCancel := context.WithTimeout(ctx, 60*time.Second)
	defer cmdCancel()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gemini-cli error: %v", err)
	}

	// Parse dorks from output
	lines := strings.Split(string(output), "\n")
	var dorks []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Remove markdown code blocks
		if strings.HasPrefix(line, "```") {
			continue
		}
		// Remove numbering (1. 2. etc.)
		line = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(line, "")
		// Must contain site: operator
		if strings.Contains(line, "site:") {
			dorks = append(dorks, line)
		}
	}

	console.Logv(c.Verbose, "[AI] Generated %d subdomain discovery dorks", len(dorks))
	return dorks, nil
}

// printSubdomains extracts and prints unique subdomains from URLs
func (c *Config) printSubdomains(urls []string) {
	hostSet := map[string]struct{}{}
	for _, u := range urls {
		h := hostOf(u)
		if h != "" && !strings.HasPrefix(h, "www.") {
			hostSet[h] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if c.OutputPath != "" {
		outputOrPrintUnique(hosts, c.OutputPath)
	} else {
		for _, h := range hosts {
			fmt.Println(h)
		}
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// try add scheme
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			u2, e2 := url.Parse("http://" + raw)
			if e2 == nil && u2.Host != "" {
				return u2.Host
			}
		}
		return ""
	}
	return u.Host
}

func (c *Config) contentsAttack(ctx context.Context) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "Target: %s\n", c.Target)
	}
	if fileExists(c.Contents) {
		lines, _ := readLines(c.Contents)
		for _, content := range lines {
			c2 := *c
			c2.Contents = content
			// Build intext for this single term
			c2.InFile = fmt.Sprintf(`intext:"%s"`, content)
			res := c2.dorkRun(ctx, "")
			if len(res) == 0 {
				c2.notFound()
				continue
			}
			if c2.Verbose {
				fmt.Fprintf(os.Stderr, "Files found containing: %s\n", content)
			}
			if c2.OutputPath != "" {
				outputOrPrintUnique(res, c2.OutputPath)
			} else {
				outputOrPrintUnique(res, "")
			}
		}
		return
	}
	// Single value path
	c.InFile = buildContentsQuery(c.Contents)
	res := c.dorkRun(ctx, "")
	if len(res) == 0 {
		c.notFound()
		return
	}
	if c.OutputPath != "" {
		outputOrPrintUnique(res, c.OutputPath)
	} else {
		outputOrPrintUnique(res, "")
	}
}

// performTLDMassScanning performs mass scanning of TLDs to discover domains and run tech detection
func (c *Config) performTLDMassScanning(ctx context.Context, tlds []string) error {
	var allDomains []string

	// For each TLD, perform Google dorking to discover domains
	for _, tld := range tlds {
		fmt.Printf("\n%s[TLD-SCAN]%s Discovering domains in %s TLD...\n", console.ColorCyan, console.ColorReset, tld)

		// Use Google search with site: operator to find domains
		// We'll search for common patterns to maximize domain discovery
		searchQueries := []string{
			fmt.Sprintf("site:%s", tld),                     // Basic site search
			fmt.Sprintf("site:%s inurl:index", tld),         // Index pages
			fmt.Sprintf("site:%s inurl:admin", tld),         // Admin panels
			fmt.Sprintf("site:%s inurl:login", tld),         // Login pages
			fmt.Sprintf("site:%s intitle:\"welcome\"", tld), // Welcome pages
		}

		discoveredDomains := make(map[string]bool)

		for _, query := range searchQueries {
			console.Logv(c.Verbose, "[TLD-SCAN] Searching: %s", query)

			// Perform Google search
			originalDork := c.Dork
			c.Dork = query

			results := c.dorkRun(ctx, "")
			c.Dork = originalDork // Restore original dork

			// Extract domains from URLs
			for _, result := range results {
				domain := extractDomainFromURL(result)
				if domain != "" && strings.HasSuffix(domain, tld) {
					discoveredDomains[domain] = true
				}
			}

			// Rate limiting between searches
			time.Sleep(2 * time.Second)
		}

		// Add discovered domains to the list
		for domain := range discoveredDomains {
			allDomains = append(allDomains, domain)
		}

		fmt.Printf("%s[TLD-SCAN]%s Discovered %d domains in %s\n", console.ColorGreen, console.ColorReset, len(discoveredDomains), tld)
	}

	if len(allDomains) == 0 {
		fmt.Printf("%s[TLD-SCAN]%s No domains discovered\n", console.ColorYellow, console.ColorReset)
		return nil
	}

	fmt.Printf("\n%s[TLD-SCAN]%s Total domains discovered: %d\n", console.ColorGreen, console.ColorReset, len(allDomains))
	fmt.Printf("%s[TLD-SCAN]%s Starting technology detection on discovered domains...\n\n", console.ColorCyan, console.ColorReset)

	// Perform tech detection on each discovered domain
	for i, domain := range allDomains {
		fmt.Printf("\n%s[%d/%d]%s Scanning %s\n", console.ColorCyan, i+1, len(allDomains), console.ColorReset, domain)

		// Temporarily set target to current domain
		originalTarget := c.Target
		c.Target = domain

		// Perform tech detection
		techDorks, detectedCVEs := c.performComprehensiveTechDetection(ctx)

		// Execute tech-based and CVE-based dorks
		if len(techDorks) > 0 {
			console.Logv(c.Verbose, "[TECH-DORK] Executing %d technology and CVE-based dorks for %s", len(techDorks), domain)
			c.multiDorkAttack(ctx, techDorks)
		}

		// Display CVE summary if any detected
		if len(detectedCVEs) > 0 {
			fmt.Printf("\n%s[CVE-DETECT]%s Found %d CVEs for %s:\n", console.ColorRed, console.ColorReset, len(detectedCVEs), domain)
			for _, cve := range detectedCVEs {
				severityColor := console.ColorYellow
				if cve.Severity == "critical" {
					severityColor = console.ColorRed
				}
				fmt.Printf("  %s[%s]%s %s - CVSS: %.1f - %s\n",
					severityColor, strings.ToUpper(cve.Severity), console.ColorReset,
					cve.CVEID, cve.CVSS, cve.Description)
			}
		}

		// Restore original target
		c.Target = originalTarget

		// Rate limiting between domains
		if i < len(allDomains)-1 {
			time.Sleep(3 * time.Second)
		}
	}

	fmt.Printf("\n%s[TLD-SCAN]%s Mass scanning complete. Scanned %d domains across %d TLD(s)\n",
		console.ColorGreen, console.ColorReset, len(allDomains), len(tlds))

	return nil
}
