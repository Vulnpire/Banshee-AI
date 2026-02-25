package monitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

// runMonitor orchestrates periodic monitoring cycles driven by --monitor.
func (c *Config) runMonitor(ctx context.Context, targets []string) error {
	intents, docFocus, recent := parseMonitorIntents(c.MonitorQuery)
	c.MonitorDocFocus = docFocus

	if c.FilterMonitor && c.MonitorSeenURLs == nil {
		c.MonitorSeenURLs = core.NewSafeSet()
	}

	seenDorks := loadDorkHistory(c.IgnoreFile)

	interval := time.Duration(c.MonitorMinutes) * time.Minute
	if interval <= 0 {
		interval = 60 * time.Minute
	}

	cycle := 1
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		console.Logv(c.Verbose, "[MONITOR] Cycle %d: targeting %d domain(s) with %d dorks each (every %d minutes)", cycle, len(targets), c.AiQuantity, c.MonitorMinutes)

		if err := c.runMonitorOnce(ctx, targets, intents, seenDorks, docFocus, recent); err != nil && !errors.Is(err, context.Canceled) {
			console.Logv(c.Verbose, "[MONITOR] Warning: %v", err)
		}

		cycle++

		if err := c.waitForNextCycle(ctx, interval); err != nil {
			return err
		}
	}
}

func (c *Config) runMonitorOnce(ctx context.Context, targets, intents []string, seenDorks map[string]struct{}, docFocus, recent bool) error {
	for i, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		c2 := *c
		c2.Target = target
		c2.MonitorMode = true
		c2.MonitorDocFocus = docFocus
		c2.MonitorSeenURLs = c.MonitorSeenURLs
		c2.SuppressAIDorkList = true

		if c2.MultiLang {
			c2.TargetLanguage = c2.detectTargetLanguage(ctx)
		}

		if c2.AnalyzeMonitor {
			c2.AnalyzeDocuments = true
			c2.AnalyzeResponses = true
			c2.InlineCodeAnalysis = false
		}

		waybackIntel := c2.prepareMonitorWaybackIntel(ctx, target)

		originalQuantity := c2.AiQuantity
		if originalQuantity < 1 {
			originalQuantity = 1
		}

		var fresh []string
		remaining := originalQuantity
		maxAttempts := 3

		for attempt := 1; attempt <= maxAttempts && remaining > 0; attempt++ {
			avoid := selectAvoidList(seenDorks, 20)
			prompt := buildMonitorPrompt(target, intents, remaining, c2.IncludeSubdomains, docFocus, recent, avoid)
			c2.AiPrompt = prompt
			c2.AiQuantity = remaining

			dorks, err := c2.generateMonitorDorks(ctx, target, prompt, remaining, waybackIntel, attempt)
			if err != nil {
				console.Logv(c.Verbose, "[MONITOR] Failed to generate dorks for %s (attempt %d/%d): %v", target, attempt, maxAttempts, err)
				continue
			}

			if c2.MultiLang && c2.TargetLanguage != "" {
				dorks = c2.generateMultiLangDorks(ctx, dorks, c2.TargetLanguage)
			}

			// Remove already used dorks and track new ones
			newDorks := filterNewDorks(dorks, seenDorks)
			if len(newDorks) == 0 {
				console.Logv(c.Verbose, "[MONITOR] No new dorks for %s (attempt %d/%d)", target, attempt, maxAttempts)
				continue
			}

			if len(newDorks) > remaining {
				newDorks = newDorks[:remaining]
			}

			fresh = append(fresh, newDorks...)
			remaining = originalQuantity - len(fresh)
		}

		c2.AiQuantity = originalQuantity

		if len(fresh) == 0 {
			console.Logv(c.Verbose, "[MONITOR] No new dorks for %s (cycle %d/%d)", target, i+1, len(targets))
			continue
		}

		c2.AiPrompt = fmt.Sprintf("monitor intent: %s", strings.Join(intents, ", "))

		// Persist dorks to ignore history (unless flushing)
		if c2.IgnoreFile != "" && !c2.FlushMode {
			if err := appendDorksToIgnoreFile(c2.IgnoreFile, fresh); err != nil {
				console.Logv(c.Verbose, "[MONITOR] Warning: failed to save dorks to ignore file: %v", err)
			}
		}

		if c2.MultiLang && c2.TargetLanguage != "" {
			c2.MultiLang = false
		}

		logMonitorDorks(c.Verbose, fresh)
		console.Logv(c.Verbose, "[MONITOR] Executing %d dorks for %s", len(fresh), target)
		c2.executeDorkPipeline(ctx, fresh)
	}

	return nil
}

func parseMonitorIntents(raw string) ([]string, bool, bool) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return []string{"sensitive assets"}, false, false
	}

	if raw == "all" {
		return []string{"all asset types (docs, creds, vulns, exposures, errors)"}, false, true
	}

	parts := strings.Split(raw, ",")
	var intents []string
	docSignals := 0
	nonDocSignals := 0
	recent := false

	isDocIntent := func(s string) bool {
		return strings.Contains(s, "doc") ||
			strings.Contains(s, "pdf") ||
			strings.Contains(s, "xls") ||
			strings.Contains(s, "sheet") ||
			strings.Contains(s, "ppt") ||
			strings.Contains(s, "report") ||
			strings.Contains(s, "invoice") ||
			strings.Contains(s, "statement") ||
			strings.Contains(s, "policy")
	}

	isNonDocIntent := func(s string) bool {
		signals := []string{
			"sqli", "xss", "redirect", "idor", "lfi", "rce", "ssrf",
			"api", "token", "secret", "key", "credential", "password",
			"login", "admin", "backup", "config", "database", "db",
			"exposure", "leak", "source", "git",
		}
		for _, sig := range signals {
			if strings.Contains(s, sig) {
				return true
			}
		}
		return false
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		intents = append(intents, part)
		if isDocIntent(part) {
			docSignals++
		}
		if isNonDocIntent(part) {
			nonDocSignals++
		}
		if strings.Contains(part, "new") || strings.Contains(part, "recent") || strings.Contains(part, "latest") || strings.Contains(part, "fresh") {
			recent = true
		}
	}

	if len(intents) == 0 {
		intents = []string{"sensitive assets"}
	}

	docFocus := docSignals > 0 && nonDocSignals == 0
	return intents, docFocus, recent
}

func buildMonitorPrompt(target string, intents []string, quantity int, includeSubdomains, docFocus, recent bool, avoid []string) string {
	intentDesc := strings.Join(intents, ", ")
	subdomainNote := "only this host"
	if includeSubdomains {
		subdomainNote = "the domain and all subdomains"
	}

	docNote := ""
	if docFocus {
		docNote = " Prioritize documents (pdf, doc, docx, xls, xlsx, csv, ppt, pptx) and skip marketing fluff."
	}

	timeNote := ""
	if recent {
		timeNote = " Prefer recent results. Use date operators like after:2023/after:2024 when useful."
	}

	avoidNote := ""
	if len(avoid) > 0 {
		avoidNote = "\nAvoid these previously used dorks: " + strings.Join(avoid, " | ")
	}

	return fmt.Sprintf(
		"Generate EXACTLY %d diverse Google/Brave dorks for site:%s covering %s. Target %s.%s%s\nReturn plain dorks, no numbering.%s",
		quantity,
		target,
		intentDesc,
		subdomainNote,
		docNote,
		timeNote,
		avoidNote,
	)
}

func filterNewDorks(dorks []string, seen map[string]struct{}) []string {
	var fresh []string
	for _, d := range dorks {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, exists := seen[d]; exists {
			continue
		}
		seen[d] = struct{}{}
		fresh = append(fresh, d)
	}
	return fresh
}

func selectAvoidList(seen map[string]struct{}, max int) []string {
	if len(seen) == 0 || max <= 0 {
		return nil
	}
	count := 0
	avoid := make([]string, 0, max)
	for dork := range seen {
		avoid = append(avoid, dork)
		count++
		if count >= max {
			break
		}
	}
	return avoid
}

func loadDorkHistory(path string) map[string]struct{} {
	history := make(map[string]struct{})
	if path == "" || !fileExists(path) {
		return history
	}

	lines, err := readLines(path)
	if err != nil {
		return history
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			history[line] = struct{}{}
		}
	}
	return history
}

func (c *Config) prepareMonitorWaybackIntel(ctx context.Context, target string) *core.WaybackIntelligence {
	if !c.ForeseeMode {
		return nil
	}

	var waybackIntel *core.WaybackIntelligence
	if !c.NoWaybackCache {
		waybackIntel, _ = loadWaybackIntelligence(target)
		if waybackIntel != nil {
			console.Logv(c.Verbose, "[WAYBACK] Using cached intelligence (generated %s)", waybackIntel.ProcessedAt.Format("2006-01-02 15:04"))
		}
	} else {
		console.Logv(c.Verbose, "[WAYBACK] Bypassing cache (--no-wayback-cache)")
	}

	if waybackIntel == nil {
		urls, err := queryWaybackCDX(ctx, target, c.WaybackStatusCodes, c.Verbose)
		if err != nil {
			console.Logv(c.Verbose, "[WAYBACK] Query failed: %v", err)
		} else if len(urls) > 0 {
			if c.Exclusions != "" {
				urls = filterExcludedURLs(urls, c.Exclusions, c.Verbose)
				if len(urls) == 0 {
					console.Logv(c.Verbose, "[WAYBACK] All URLs excluded by -x filters")
				}
			}
			if len(urls) > 0 {
				waybackIntel = extractWaybackIntelligence(target, urls, c.Verbose)
				if waybackIntel != nil {
					if err := saveWaybackIntelligence(target, waybackIntel); err != nil {
						console.Logv(c.Verbose, "[WAYBACK] Warning: Failed to save Intelligence: %v", err)
					}
					console.Logv(c.Verbose, "[WAYBACK] Intelligence updated for %s", target)
				}
			}
		}
	}

	if waybackIntel != nil {
		c.WaybackIntelligence = waybackIntel
	}

	return waybackIntel
}

func (c *Config) generateMonitorDorks(ctx context.Context, target, prompt string, quantity int, intel *core.WaybackIntelligence, attempt int) ([]string, error) {
	if intel != nil && attempt == 1 {
		dorks := generateAIPoweredWaybackDorks(target, intel, prompt, quantity, c.Verbose, c.WafBypass)
		if len(dorks) < quantity {
			remaining := quantity - len(dorks)
			if remaining > 0 {
				c.AiQuantity = remaining
				supplemental, err := c.generateDorksWithAI(ctx, prompt)
				if err == nil && len(supplemental) > 0 {
					dorks = append(dorks, supplemental...)
				} else if err != nil {
					console.Logv(c.Verbose, "[WAYBACK-AI] Supplemental generation failed: %v", err)
				}
			}
		}
		return dorks, nil
	}
	return c.generateDorksWithAI(ctx, prompt)
}

func logMonitorDorks(verbose bool, dorks []string) {
	console.Logv(verbose, "[AI] Generated %d dorks:", len(dorks))
	if !verbose {
		return
	}
	for i, dork := range dorks {
		fmt.Printf("  %d. %s\n", i+1, dork)
	}
}

func (c *Config) waitForNextCycle(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return nil
	}

	monitorTag := "[MONITOR]"
	if !console.GlobalNoColors {
		monitorTag = console.ColorCyan + monitorTag + console.ColorReset
	}

	end := time.Now().Add(interval)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fmt.Fprint(os.Stderr, "\n")
	for {
		remaining := time.Until(end)
		if remaining <= 0 {
			fmt.Fprintf(os.Stderr, "\r%s Next run in 00m00s\033[K\n", monitorTag)
			return nil
		}

		mins := int(remaining.Minutes())
		secs := int(remaining.Seconds()) % 60
		fmt.Fprintf(os.Stderr, "\r%s Next run in %02dm%02ds\033[K", monitorTag, mins, secs)

		select {
		case <-ctx.Done():
			fmt.Fprint(os.Stderr, "\n")
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}
}
