package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// aiDorkAttack executes AI-generated dorks
func (c *Config) aiDorkAttack(ctx context.Context) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "Target: %s\n", c.Target)
		fmt.Fprintf(os.Stderr, "AI Prompt: %s\n", c.AiPrompt)

		// Display AI model being used
		modelDisplay := c.AiModel
		if modelDisplay == "" {
			modelDisplay = "default (gemini-cli default)"
		}
		fmt.Fprintf(os.Stderr, "%s[AI-MODEL]%s %s\n", console.ColorCyan, console.ColorReset, modelDisplay)

		// Display detected language if multi-lang is enabled
		if c.MultiLang {
			if c.TargetLanguage != "" {
			console.Logv(c.Verbose, "[MULTI-LANG] Detected language: %s", c.TargetLanguage)
			} else {
			console.Logv(c.Verbose, "[MULTI-LANG] Language detection failed, using English")
			}
		}
	}

	// Generate dorks using AI
	dorks, err := c.generateDorksWithAI(ctx, c.AiPrompt)
	if err != nil {
		console.LogErr("[!] Failed to generate dorks: %v", err)
		return
	}

	if len(dorks) == 0 {
		console.LogErr("[!] No dorks were generated")
		return
	}

	c.executeDorkPipeline(ctx, dorks)
}

func (c *Config) executeDorkPipeline(ctx context.Context, dorks []string) {
	// SMART: Learn from successful URLs and generate focused dorks
	// TODO: Implement generateDorksFromSuccessfulURLs
	/*
		if c.SmartMode {
			smartDorks, err := c.generateDorksFromSuccessfulURLs(ctx)
			if err != nil {
				console.Logv(c.Verbose, "[SMART] Warning: Failed to generate dorks from successful URLs: %v", err)
			} else if len(smartDorks) > 0 {
				console.Logv(c.Verbose, "[SMART] Adding %d focused dorks from successful URL patterns", len(smartDorks))
				dorks = append(dorks, smartDorks...)
			}
		}
	*/

	// TECH-DETECT: Auto-detect tech stack and add specialized dorks
	if c.TechDetect {
		detectedTech := c.detectTechStack(ctx)
		techDorks := c.generateTechSpecificDorks(detectedTech)
		if len(techDorks) > 0 {
			console.Logv(c.Verbose, "[TECH-DETECT] Adding %d tech-specific dorks", len(techDorks))
			dorks = append(dorks, techDorks...)
		}
	}

	// MULTI-LANG: Expand dorks into target language variants when enabled
	if c.MultiLang && c.TargetLanguage != "" {
		dorks = c.generateMultiLangDorks(ctx, dorks, c.TargetLanguage)
	}

	// INCLUDE-DATES: Detect company timeline and add date operators
	var timeline *CompanyTimeline
	if c.IncludeDates {
		timeline = c.detectCompanyTimeline(ctx)
		if timeline != nil {
			console.Logv(c.Verbose, "[DATES] Applying strategic date operators to dorks")
			// Apply date operators to existing dorks
			for i := range dorks {
				dorks[i] = addDateOperators(dorks[i], timeline)
			}
		}
	}

	// BUDGET: Smart Query Budget Optimization - predict which dorks will work
	var predictions []DorkPrediction
	if c.BudgetMode {
		var err error
		predictions, err = c.predictDorkSuccess(ctx, dorks)
		if err != nil {
			console.Logv(c.Verbose, "[BUDGET] Warning: Failed to analyze dorks: %v", err)
		} else if len(predictions) > 0 {
			c.displayBudgetAnalysis(predictions)

			// Filter dorks based on predictions (skip low-probability ones)
			filteredDorks := []string{}
			for _, pred := range predictions {
				if !pred.ShouldSkip {
					filteredDorks = append(filteredDorks, pred.Dork)
				}
			}

			if len(filteredDorks) < len(dorks) {
				console.Logv(c.Verbose, "[BUDGET] Filtered %d → %d dorks (skipped %d low-probability)",
					len(dorks), len(filteredDorks), len(dorks)-len(filteredDorks))
				dorks = filteredDorks
			}
		}
	}

	// Execute each dork and track results for learning
	var allResults []string
	dorkResults := make(map[string][]string) // Track results per dork for learning

	for i, dork := range dorks {
		if ctx.Err() != nil {
			console.LogErr("[!] Operation cancelled")
			break
		}

		console.Logv(c.Verbose, "\n[AI] Executing dork %d/%d: %s", i+1, len(dorks), dork)

		// Store original dork, temporarily set it
		originalDork := c.Dork
		c.Dork = dork

		// Run the dork search
		results := c.dorkRun(ctx, "")
		results = c.applyMonitorFilters(results)
		if len(results) > 0 {
			allResults = append(allResults, results...)
			dorkResults[dork] = results
			console.Logv(c.Verbose, "[AI] Dork %d found %d results", i+1, len(results))

			// PROGRESSIVE SUBDOMAIN DEPTH: If -a is set and results found, try deeper wildcards
			if c.IncludeSubdomains {
				currentDork := dork
				// Count current wildcard depth (max 3: *.*.*.domain.com)
				wildcardCount := strings.Count(currentDork, "site:*.")

				for depth := wildcardCount + 1; depth <= 3; depth++ {
					if ctx.Err() != nil {
						break
					}

					// Create deeper dork by adding another *.
					deeperDork := strings.Replace(currentDork, "site:*.", "site:*.*.", 1)

					console.Logv(c.Verbose, "[AI] Trying deeper subdomain search (depth %d): %s", depth, deeperDork)
					c.Dork = deeperDork
					deeperResults := c.dorkRun(ctx, "")
					deeperResults = c.applyMonitorFilters(deeperResults)

					if len(deeperResults) > 0 {
						allResults = append(allResults, deeperResults...)
						dorkResults[deeperDork] = deeperResults
						console.Logv(c.Verbose, "[AI] Deeper search (depth %d) found %d results", depth, len(deeperResults))
						currentDork = deeperDork // Update for next iteration
						time.Sleep(2 * time.Second)
					} else {
						console.Logv(c.Verbose, "[AI] No results at depth %d, stopping progression", depth)
						break // Stop if no results found at this depth
					}
				}
			}

			// SMART MODE: Generate and execute follow-up dorks (contextual to the original prompt)
			if c.SmartMode {
				followUpDorks := c.analyzeResultsForFollowUp(ctx, results, c.AiPrompt)
				if len(followUpDorks) > 0 {
					for j, followUpDork := range followUpDorks {
						if ctx.Err() != nil {
							break
						}

						// Apply subdomain-only filter if -a flag is set
						if c.IncludeSubdomains {
							followUpDork = applySubdomainOnlyFilter(followUpDork, c.Target)
						}

						console.Logv(c.Verbose, "[SMART] Executing follow-up dork %d/%d: %s", j+1, len(followUpDorks), followUpDork)
						c.Dork = followUpDork
						followUpResults := c.dorkRun(ctx, "")
						followUpResults = c.applyMonitorFilters(followUpResults)
						if len(followUpResults) > 0 {
							allResults = append(allResults, followUpResults...)
							dorkResults[followUpDork] = followUpResults
							console.Logv(c.Verbose, "[SMART] Follow-up dork %d found %d results", j+1, len(followUpResults))
						}
						time.Sleep(2 * time.Second)
					}
				}

				// MULTI-LAYER CORRELATION: Cross-correlate discoveries for deeper intelligence
				// Only run if --correlation flag is set
				if c.CorrelationMode {
					correlatedDorks := c.correlateDiscoveries(ctx, allResults)
					if len(correlatedDorks) > 0 {
						console.Logv(c.Verbose, "[SMART-CORRELATION] Executing %d correlated dorks...", len(correlatedDorks))
						for j, correlatedDork := range correlatedDorks {
							if ctx.Err() != nil {
								break
							}

							// Apply subdomain-only filter if -a flag is set
							if c.IncludeSubdomains {
								correlatedDork = applySubdomainOnlyFilter(correlatedDork, c.Target)
							}

							console.Logv(c.Verbose, "[SMART-CORRELATION] Executing correlated dork %d/%d: %s", j+1, len(correlatedDorks), correlatedDork)
							c.Dork = correlatedDork
							correlatedResults := c.dorkRun(ctx, "")
							correlatedResults = c.applyMonitorFilters(correlatedResults)
							if len(correlatedResults) > 0 {
								allResults = append(allResults, correlatedResults...)
								dorkResults[correlatedDork] = correlatedResults
								console.Logv(c.Verbose, "[SMART-CORRELATION] Correlated dork %d found %d results", j+1, len(correlatedResults))
							}
							time.Sleep(2 * time.Second)
						}
					}
				}
			}
		} else {
			dorkResults[dork] = []string{}
			console.Logv(c.Verbose, "[AI] Dork %d found 0 results", i+1)
		}

		// Restore original dork
		c.Dork = originalDork

		// Small delay between dorks (adaptive if enabled)
		if i < len(dorks)-1 {
			if c.AdaptiveMode {
				time.Sleep(time.Duration(c.DynamicDelay * float64(time.Second)))
			} else {
				time.Sleep(2 * time.Second)
			}
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

	// Deduplicate results
	originalCount := len(allResults)
	allResults = uniqueStrings(allResults)       // First pass: basic dedup
	allResults = c.intelligentDedupe(allResults) // Second pass: intelligent dedup if enabled

	// Show dedupe stats if verbose and dedup is enabled
	if c.Verbose && c.DedupeMode && originalCount > len(allResults) {
		console.Logv(c.Verbose, "[DEDUPE] %d URLs deduplicated (reduced from %d to %d)",
			originalCount-len(allResults), originalCount, len(allResults))
	}

	// Identify URLs already present in the output file to avoid re-analysis
	existingOutputs := loadExistingOutputs(c.OutputPath)
	analysisTargets := filterNewURLs(allResults, existingOutputs)
	if c.Verbose && len(existingOutputs) > 0 && len(analysisTargets) < len(allResults) {
		console.Logv(c.Verbose, "[OUTPUT] Skipping analysis for %d URLs already present in output file", len(allResults)-len(analysisTargets))
	}
	var documentTargets []string
	if c.AnalyzeDocuments && len(analysisTargets) > 0 {
		documentTargets = filterDocumentAnalysisURLs(analysisTargets)
	}

	// SCORING: Classify and score results for prioritization
	if c.ScoringMode && len(allResults) > 0 {
		scored, err := c.classifyAndScoreResults(ctx, allResults)
		if err != nil {
			console.Logv(c.Verbose, "[SCORING] Warning: Failed to score results: %v", err)
		} else if len(scored) > 0 {
			c.displayScoredResults(scored)
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

	// INLINE-CODE-ANALYSIS: Analyze inline JavaScript from HTML responses (after SMART)
	var inlineCodeStats *InlineCodeAnalysisStats
	if c.InlineCodeAnalysis && len(analysisTargets) > 0 {
		inlineCodeStats = c.performInlineCodeAnalysis(ctx, analysisTargets)
		// Display inline code analysis statistics
		if inlineCodeStats != nil && inlineCodeStats.ScannedURLs > 0 {
			if inlineCodeStats.FindingsCount > 0 {
				fmt.Printf("%s[INLINE-CODE-ANALYSIS]%s Scanned %d URLs' inline HTML | %sFound %d vulnerabilities%s\n",
					console.ColorCyan, console.ColorReset, inlineCodeStats.ScannedURLs, console.ColorRed, inlineCodeStats.FindingsCount, console.ColorReset)
			} else {
				fmt.Printf("%s[INLINE-CODE-ANALYSIS]%s Scanned %d URLs' inline HTML | %sNo vulnerabilities found%s\n",
					console.ColorCyan, console.ColorReset, inlineCodeStats.ScannedURLs, console.ColorGreen, console.ColorReset)
			}
		}
	}

	// Output results
	if len(allResults) == 0 {
		c.notFound()
		return
	}

	console.Logv(c.Verbose, "\n[AI] Total unique results: %d", len(allResults))

	// Send URLs through proxy if configured
	c.sendURLsThroughProxy(ctx, allResults)

	// RESPONSE-ANALYSIS: Analyze HTTP responses with AI
	responsesAnalyzed := false
	if c.AnalyzeResponses && len(analysisTargets) > 0 {
		filteredURLs, skippedURLs := filterResponseAnalysisURLs(analysisTargets)
		if len(skippedURLs) > 0 {
			console.Logv(c.Verbose, "[RESPONSE-ANALYSIS] Skipping %d non-sensitive/static/document URLs from response analysis", len(skippedURLs))
		}
		if len(filteredURLs) == 0 {
			console.Logv(c.Verbose, "[RESPONSE-ANALYSIS] No URLs selected for response analysis after filtering")
			goto outputResults
		}

		// Create temporary responses file
		targetName := strings.ReplaceAll(c.Target, ".", "_")
		if targetName == "" {
			targetName = "unknown"
		}
		responsesFile := filepath.Join("/tmp", targetName, "responses.txt")

		// Create directory if it doesn't exist
		if err := os.MkdirAll(filepath.Dir(responsesFile), 0755); err != nil {
			console.LogErr("[!] Failed to create responses directory: %v", err)
		} else {
			// Collect HTTP responses
			if err := c.collectHTTPResponses(ctx, filteredURLs, responsesFile); err != nil {
				console.LogErr("[!] Failed to collect responses: %v", err)
			} else {
				// Analyze responses with AI
				analysis, err := c.analyzeResponsesWithAI(ctx, responsesFile, filteredURLs)
				if err != nil {
					console.LogErr("[!] Failed to analyze responses: %v", err)
				} else if len(analysis) > 0 {
					responsesAnalyzed = true

					// Persist critical findings into intelligence for future recommendations
					if c.LearnMode && c.Intelligence != nil {
						c.recordResponseFindings(analysis)
						if err := saveTargetIntelligence(c.Intelligence); err != nil {
							console.Logv(c.Verbose, "[LEARN] Warning: Failed to save response findings: %v", err)
						}
					}

					// Output analysis results
					console.Logv(c.Verbose, "\n%s[RESPONSE-ANALYSIS]%s Results:", console.ColorGreen, console.ColorReset)
					// Separate findings vs no-findings
					noFindings := []string{}
					for url, summary := range analysis {
						summary = normalizeRAOutput(summary)
						// Output format: URL | [RA] - summary (with color coding and red highlighting for sensitive data)
						// Use different colors based on content
						lowerSummary := strings.ToLower(summary)
						summaryColor := console.ColorGreen
						if strings.Contains(lowerSummary, "aws_") || strings.Contains(lowerSummary, "private key") || strings.Contains(lowerSummary, "session key") || strings.Contains(lowerSummary, "dsn:") || strings.Contains(lowerSummary, "credential") || strings.Contains(lowerSummary, "password") || strings.Contains(lowerSummary, "token") {
							summaryColor = console.ColorRed
						} else if strings.Contains(lowerSummary, "error") || strings.Contains(lowerSummary, "failed") || strings.Contains(lowerSummary, "parsing") {
							summaryColor = console.ColorOrange
						} else if strings.Contains(lowerSummary, "sensitive") || strings.Contains(lowerSummary, "admin") || strings.Contains(lowerSummary, "api") {
							summaryColor = console.ColorYellow
						}

						// Separate no-finding placeholder
						if strings.HasPrefix(summary, "No findings") {
							noFindings = append(noFindings, url)
							continue
						}

						// Highlight sensitive findings in red (within the yellow text)
						highlightedSummary := highlightSensitiveFindings(summary)

						fmt.Printf("%s | %s[RA]%s - %s%s%s\n", url, console.ColorCyan, console.ColorReset, summaryColor, highlightedSummary, console.ColorReset)
					}
					if len(skippedURLs) > 0 {
						fmt.Printf("\n%s[RESPONSE-ANALYSIS]%s Skipped URLs (%d):\n", console.ColorYellow, console.ColorReset, len(skippedURLs))
						for _, u := range skippedURLs {
							fmt.Println(u)
						}
					}
					if len(noFindings) > 0 {
						fmt.Printf("\n%s[RESPONSE-ANALYSIS]%s No findings (%d):\n", console.ColorYellow, console.ColorReset, len(noFindings))
						for _, u := range noFindings {
							fmt.Println(u)
						}
					}
				}
				// Flush all output before continuing to next domain
				os.Stdout.Sync()

				// Clean up responses file after analysis
				os.Remove(responsesFile)
			}
		}
	}

	outputResults:
	if c.OutputPath != "" {
		outputOrPrintUnique(allResults, c.OutputPath)
	}

	// Avoid double-printing URLs when response analysis already summarized them
	if responsesAnalyzed && !c.AnalyzeDocuments {
		return
	}

	if c.AnalyzeDocuments {
		// Analyze documents in parallel using worker pool (even when saving to file)
		if c.Verbose && len(documentTargets) > 0 {
			console.Logv(true, "[DOCUMENT-ANALYSIS] Processing %d documents with %d workers", len(documentTargets), c.Workers)
		}

		// Convert URLs to interface{} for worker pool
		items := make([]interface{}, len(documentTargets))
		for i, url := range documentTargets {
			items[i] = url
		}

		// Document analysis processor with timeout
		docProcessor := func(ctx context.Context, item interface{}) (interface{}, error) {
			url := item.(string)

			// Add per-document timeout (5 minutes max per document)
			docCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()

			// Run analysis in goroutine to respect timeout
			done := make(chan struct{})
			go func() {
				defer close(done)
				c.analyzeDocumentForSensitiveInfo(docCtx, url)
			}()

			select {
			case <-done:
				// Analysis completed
				return nil, nil
			case <-docCtx.Done():
				// Timeout or cancellation
				console.Logv(c.Verbose, "[DOC-ANALYZE] ✗ Timeout analyzing: %s", url)
				return nil, docCtx.Err()
			}
		}

		if len(items) > 0 {
			processWithWorkerPool(ctx, items, c.Workers, docProcessor)
			console.Logv(c.Verbose, "[DOCUMENT-ANALYSIS] Completed analysis of %d documents", len(items))
		}
		return
	}

	// Default output when not analyzing documents and not saving to file
	if c.OutputPath == "" {
		for _, u := range allResults {
			fmt.Println(u)
		}
	}
}

// aiDorkAttackMultiplePrompts executes multiple AI prompts from a file
func (c *Config) aiDorkAttackMultiplePrompts(ctx context.Context, prompts []string) {
	// Filter out empty lines and comments first
	var validPrompts []string
	for _, prompt := range prompts {
		prompt = strings.TrimSpace(prompt)
		if prompt != "" && !strings.HasPrefix(prompt, "#") {
			validPrompts = append(validPrompts, prompt)
		}
	}

	if len(validPrompts) == 0 {
		console.LogErr("[!] No valid prompts found (all lines are empty or comments)")
		return
	}

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "Target: %s\n", c.Target)
		fmt.Fprintf(os.Stderr, "AI Prompts: %d prompts from file\n", len(validPrompts))
	}

	var allResults []string

	for i, prompt := range validPrompts {
		if ctx.Err() != nil {
			console.LogErr("[!] Operation cancelled")
			break
		}

		fmt.Fprintf(os.Stderr, "\n[Prompt %d/%d] %s\n", i+1, len(validPrompts), prompt)

		// Generate dorks for this prompt
		dorks, err := c.generateDorksWithAI(ctx, prompt)
		if err != nil {
			console.LogErr("[!] Failed to generate dorks for prompt %d: %v", i+1, err)
			continue
		}

		if len(dorks) == 0 {
			console.LogErr("[!] No dorks generated for prompt %d", i+1)
			continue
		}

		// Execute dorks for this prompt
		for j, dork := range dorks {
			if ctx.Err() != nil {
				console.LogErr("[!] Operation cancelled")
				break
			}

			console.Logv(c.Verbose, "[AI] Executing dork %d/%d: %s", j+1, len(dorks), dork)

			originalDork := c.Dork
			c.Dork = dork

			results := c.dorkRun(ctx, "")
			if len(results) > 0 {
				allResults = append(allResults, results...)
				console.Logv(c.Verbose, "[AI] Dork %d found %d results", j+1, len(results))
			} else {
				console.Logv(c.Verbose, "[AI] Dork %d found 0 results", j+1)
			}

			c.Dork = originalDork

			if j < len(dorks)-1 {
				time.Sleep(2 * time.Second)
			}
		}

		// Small delay between prompts
		if i < len(validPrompts)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	// Output combined results
	if len(allResults) == 0 {
		c.notFound()
		return
	}

	allResults = uniqueStrings(allResults)
	console.Logv(c.Verbose, "\n[AI] Total unique results from all prompts: %d", len(allResults))

	// Send URLs through proxy if configured
	c.sendURLsThroughProxy(ctx, allResults)

	existingOutputs := loadExistingOutputs(c.OutputPath)
	analysisTargets := filterNewURLs(allResults, existingOutputs)
	if c.Verbose && len(existingOutputs) > 0 && len(analysisTargets) < len(allResults) {
		console.Logv(c.Verbose, "[OUTPUT] Skipping document analysis for %d URLs already present in output file", len(allResults)-len(analysisTargets))
	}

	if c.OutputPath != "" {
		outputOrPrintUnique(allResults, c.OutputPath)
	}

	// Analyze documents if requested (even when saving to file)
	if c.AnalyzeDocuments {
		for _, u := range analysisTargets {
			c.analyzeDocumentForSensitiveInfo(ctx, u)
		}
		return
	}

	// Default output when not analyzing documents and not writing to file
	if c.OutputPath == "" {
		for _, u := range allResults {
			fmt.Println(u)
		}
	}
}

// multiDorkAttack executes multiple dorks from a file
func (c *Config) multiDorkAttack(ctx context.Context, dorks []string) {
	// Filter out empty lines and comments
	var validDorks []string
	for _, dork := range dorks {
		dork = strings.TrimSpace(dork)
		if dork != "" && !strings.HasPrefix(dork, "#") {
			validDorks = append(validDorks, dork)
		}
	}

	if len(validDorks) == 0 {
		console.LogErr("[!] No valid dorks found (all lines are empty or comments)")
		return
	}

	// Apply multi-language dork generation if enabled
	if c.MultiLang && c.TargetLanguage != "" {
		validDorks = c.generateMultiLangDorks(ctx, validDorks, c.TargetLanguage)
	}

	// Only print target/dorks info if NOT in foresee mode (already printed earlier in Wayback)
	if !c.ForeseeMode {
		console.Logv(c.Verbose, "Target: %s", c.Target)
		console.Logv(c.Verbose, "Dorks: %d dorks from file", len(validDorks))
	}

	// Track unique results across all dorks for final count
	seenResults := core.NewSafeSet()
	dorkResults := make(map[string][]string)
	executedDorks := []string{}
	trackResults := c.SmartMode || (c.LearnMode && c.Intelligence != nil)

	isCloudFocus := false
	switch strings.ToLower(c.RandomFocus) {
	case "cloud", "cloud-assets", "s3", "azure", "gcp":
		isCloudFocus = true
	}
	deferPrint := c.ForeseeMode || c.ResearchMode || isCloudFocus

	totalFound := 0
	cancelled := false

	for i, dork := range validDorks {
		if ctx.Err() != nil {
			console.LogErr("[!] Operation cancelled")
			cancelled = true
			break
		}

		console.Logv(c.Verbose, "\n[Dork %d/%d] %s", i+1, len(validDorks), dork)

		// Store original dork, temporarily set it
		originalDork := c.Dork
		c.Dork = dork

		// Run the dork search
		results := c.dorkRun(ctx, "")
		if trackResults {
			executedDorks = append(executedDorks, dork)
			dorkResults[dork] = results
		}

		// Print results immediately as they're found (one by one)
		// UNLESS in foresee mode - then print at end for cleaner output
		newCount := 0
		if len(results) > 0 {
			for _, url := range results {
				// Only print if we haven't seen this URL before
				if seenResults.Add(url) {
					// Only print immediately if not deferring bulk output
					if !deferPrint {
						fmt.Println(url)
						// Flush after EACH URL for immediate visibility in pipes
						os.Stdout.Sync()
					}
					newCount++
					totalFound++
				}
			}

			console.Logv(c.Verbose, "[Dork %d] Found %d results (%d new)", i+1, len(results), newCount)
		} else {
			console.Logv(c.Verbose, "[Dork %d] Found 0 results", i+1)
		}

		// Restore original dork
		c.Dork = originalDork

		// Small delay between dorks
		if i < len(validDorks)-1 && ctx.Err() == nil {
			time.Sleep(2 * time.Second)
		}
	}

	// Final summary (defer logging of total to later so it appears near final output)
	totalSummary := ""
	if totalFound == 0 {
		if !cancelled {
			c.notFound()
		}
	} else {
		totalSummary = fmt.Sprintf("\n[Total] Unique results across all dorks: %d", totalFound)
	}

	// Collect all results
	var allResults []string
	if totalFound > 0 {
		allResults = append(allResults, seenResults.Values()...)

		// Apply intelligent deduplication if enabled
		allResults = c.intelligentDedupe(allResults)
	}

	// Identify URLs already present in the output file to avoid re-analysis
	existingOutputs := loadExistingOutputs(c.OutputPath)
	analysisTargets := filterNewURLs(allResults, existingOutputs)
	if c.Verbose && len(existingOutputs) > 0 && len(analysisTargets) < len(allResults) {
		console.Logv(c.Verbose, "[OUTPUT] Skipping analysis for %d URLs already present in output file", len(allResults)-len(analysisTargets))
	}

	// Update intelligence if in learn mode
	if trackResults && c.LearnMode && c.Intelligence != nil && len(executedDorks) > 0 {
		updateIntelligenceWithResults(c.Intelligence, executedDorks, dorkResults)
		if err := saveTargetIntelligence(c.Intelligence); err != nil {
			console.Logv(c.Verbose, "[LEARN] Warning: Failed to save Intelligence: %v", err)
		} else {
			console.Logv(c.Verbose, "[LEARN] Intelligence updated and saved")
		}
	}

	// SMART MODE: Post-scan optimization - analyze dorks and suggest improvements
	if trackResults && c.SmartMode && len(dorkResults) > 0 {
		optimized, err := c.optimizeDorks(ctx, dorkResults)
		if err != nil {
			console.Logv(c.Verbose, "[SMART] Warning: Failed to optimize dorks: %v", err)
		} else if optimized != nil {
			c.displayOptimizedDorks(optimized)
		}
	}

	// Log total unique results after post-scan steps for clearer ordering
	if totalSummary != "" {
		console.Logv(c.Verbose, totalSummary)
	}

	// Send URLs through proxy if configured
	if totalFound > 0 && len(allResults) > 0 {
		c.sendURLsThroughProxy(ctx, allResults)
	}

	// Handle file output if specified (write all collected unique results)
	if c.OutputPath != "" && totalFound > 0 && len(allResults) > 0 {
		sort.Strings(allResults)
		outputOrPrintUnique(allResults, c.OutputPath)
	}

	// INLINE-CODE-ANALYSIS: Analyze inline JavaScript from HTML responses (same as normal AI mode)
	var inlineCodeStats *InlineCodeAnalysisStats
	if c.InlineCodeAnalysis && totalFound > 0 && len(analysisTargets) > 0 {
		inlineCodeStats = c.performInlineCodeAnalysis(ctx, analysisTargets)
		// Display inline code analysis statistics
		if inlineCodeStats != nil && inlineCodeStats.ScannedURLs > 0 {
			if inlineCodeStats.FindingsCount > 0 {
				fmt.Printf("%s[INLINE-CODE-ANALYSIS]%s Scanned %d URLs' inline HTML | %sFound %d vulnerabilities%s\n",
					console.ColorCyan, console.ColorReset, inlineCodeStats.ScannedURLs, console.ColorRed, inlineCodeStats.FindingsCount, console.ColorReset)
			} else {
				fmt.Printf("%s[INLINE-CODE-ANALYSIS]%s Scanned %d URLs' inline HTML | %sNo vulnerabilities found%s\n",
					console.ColorCyan, console.ColorReset, inlineCodeStats.ScannedURLs, console.ColorGreen, console.ColorReset)
			}
		}
	}

	// DOC-ANALYZE: Analyze documents for sensitive information (same as normal AI mode)
	if c.AnalyzeDocuments && totalFound > 0 && len(analysisTargets) > 0 {
		console.Logv(c.Verbose, "\n[DOC-ANALYZE] Starting parallel document analysis for %d URLs (using 3 workers)...", len(analysisTargets))

		// Use 3 workers for document analysis to avoid 429 rate limit errors
		maxWorkers := 3
		if c.Workers < maxWorkers {
			maxWorkers = c.Workers
		}

		// Convert URLs to interface{} for worker pool with index for rate limiting
		type urlWithIndex struct {
			index int
			url   string
		}

		urlItems := make([]interface{}, len(analysisTargets))
		for i, url := range analysisTargets {
			urlItems[i] = urlWithIndex{index: i, url: url}
		}

		// Process URLs in parallel with rate limiting
		urlProcessor := func(ctx context.Context, item interface{}) (interface{}, error) {
			uwi := item.(urlWithIndex)

			// Add staggered delay between documents to avoid rate limiting (429 errors)
			if uwi.index > 0 {
				delay := time.Duration(uwi.index) * 2 * time.Second
				time.Sleep(delay)
			}

			// analyzeDocumentForSensitiveInfo already filters for document extensions internally
			c.analyzeDocumentForSensitiveInfo(ctx, uwi.url)
			return nil, nil
		}

		processWithWorkerPool(ctx, urlItems, maxWorkers, urlProcessor)
		console.Logv(c.Verbose, "[DOC-ANALYZE] Document analysis complete")
	}

	// RESPONSE-ANALYSIS: Analyze HTTP responses with AI
	if c.AnalyzeResponses && totalFound > 0 && len(analysisTargets) > 0 {
		// Filter out PDFs, documents, and static files (same as non-passive mode)
		filteredURLs, skippedURLs := filterResponseAnalysisURLs(analysisTargets)
		if len(skippedURLs) > 0 {
			console.Logv(c.Verbose, "[RESPONSE-ANALYSIS] Skipping %d non-sensitive/static/document URLs from response analysis", len(skippedURLs))
		}
		if len(filteredURLs) == 0 {
			console.Logv(c.Verbose, "[RESPONSE-ANALYSIS] No URLs selected for response analysis after filtering")
		} else {
			// Create temporary responses file
			targetName := strings.ReplaceAll(c.Target, ".", "_")
			if targetName == "" {
				targetName = "unknown"
			}
			responsesFile := filepath.Join("/tmp", targetName, "responses.txt")

			// Create directory if it doesn't exist
			if err := os.MkdirAll(filepath.Dir(responsesFile), 0755); err != nil {
				console.LogErr("[!] Failed to create responses directory: %v", err)
			} else {
				// Collect HTTP responses
				if err := c.collectHTTPResponses(ctx, filteredURLs, responsesFile); err != nil {
					console.LogErr("[!] Failed to collect responses: %v", err)
				} else {
					// Analyze responses with AI
					analysis, err := c.analyzeResponsesWithAI(ctx, responsesFile, filteredURLs)
					if err != nil {
						console.LogErr("[!] Failed to analyze responses: %v", err)
					} else if len(analysis) > 0 {
						// Categorize results
						findings := make(map[string]string)
						noFindings := []string{}

						for url, summary := range analysis {
							if strings.Contains(summary, "No findings") {
								noFindings = append(noFindings, url)
							} else {
								findings[url] = summary
							}
						}

						// Output results with findings
						if len(findings) > 0 {
							console.Logv(c.Verbose, "\n%s[RESPONSE-ANALYSIS]%s Results:", console.ColorGreen, console.ColorReset)
							for url, summary := range findings {
								// Use different colors based on content
								summaryColor := console.ColorGreen
								if strings.Contains(strings.ToLower(summary), "error") || strings.Contains(strings.ToLower(summary), "failed") {
									summaryColor = console.ColorOrange
								} else if strings.Contains(strings.ToLower(summary), "sensitive") || strings.Contains(strings.ToLower(summary), "admin") || strings.Contains(strings.ToLower(summary), "credential") {
									summaryColor = console.ColorYellow
								}

								highlightedSummary := highlightSensitiveFindings(summary)
								fmt.Printf("%s | %s[RA]%s - %s%s%s\n", url, console.ColorCyan, console.ColorReset, summaryColor, highlightedSummary, console.ColorReset)
							}
						}

						// Output no findings section (collapsed)
						if len(noFindings) > 0 {
							console.Logv(c.Verbose, "\n%s[RESPONSE-ANALYSIS]%s No findings (%d):", console.ColorGray, console.ColorReset, len(noFindings))
							for _, url := range noFindings {
								console.Logv(c.Verbose, "%s", url)
							}
						}

						// Output skipped URLs section
						if len(skippedURLs) > 0 {
							console.Logv(c.Verbose, "\n%s[RESPONSE-ANALYSIS]%s Skipped (%d):", console.ColorGray, console.ColorReset, len(skippedURLs))
							for _, url := range skippedURLs {
								console.Logv(c.Verbose, "%s", url)
							}
						}
					}

					// Clean up responses file after analysis
					os.Remove(responsesFile)
				}
			}
		}
	}

	// TECH-DETECT: Automatically scan discovered subdomains
	if c.TechDetect && totalFound > 0 && c.Target != "" && len(allResults) > 0 {
		console.Logv(c.Verbose, "\n%s[TECH-DETECT]%s Analyzing discovered subdomains...", console.ColorCyan, console.ColorReset)

		// Extract unique subdomains from found URLs
		discoveredDomains := make(map[string]bool)
		for _, url := range allResults {
			domain := extractDomainFromURL(url)
			if domain != "" && domain != c.Target {
				discoveredDomains[domain] = true
			}
		}

		if len(discoveredDomains) > 0 {
			maxSubdomains := 10
			if len(discoveredDomains) > maxSubdomains {
				console.Logv(c.Verbose, "%s[TECH-DETECT]%s Found %d subdomains, analyzing first %d (to avoid excessive scanning)", console.ColorCyan, console.ColorReset, len(discoveredDomains), maxSubdomains)
			} else {
				console.Logv(c.Verbose, "%s[TECH-DETECT]%s Found %d unique subdomains to analyze", console.ColorCyan, console.ColorReset, len(discoveredDomains))
			}

			// Run tech detection on discovered subdomains (limit to 10)
			subdomainCount := 0
			for domain := range discoveredDomains {
				if subdomainCount >= maxSubdomains {
					break
				}
				subdomainCount++

				console.Logv(c.Verbose, "\n%s[%d/%d]%s Analyzing %s", console.ColorCyan, subdomainCount, maxSubdomains, console.ColorReset, domain)

				// Temporarily change target to discovered subdomain
				originalTarget := c.Target
				c.Target = domain

				// Perform tech detection
				_, detectedCVEs := c.performComprehensiveTechDetection(ctx)

				if len(detectedCVEs) > 0 {
					console.Logv(c.Verbose, "%s[CVE-DETECT]%s Found %d CVEs for %s:", console.ColorRed, console.ColorReset, len(detectedCVEs), domain)
					for _, cve := range detectedCVEs {
						severityColor := console.ColorYellow
						if cve.Severity == "critical" {
							severityColor = console.ColorRed
						}
						console.Logv(c.Verbose, "  %s[%s]%s %s - CVSS: %.1f", severityColor, strings.ToUpper(cve.Severity), console.ColorReset, cve.CVEID, cve.CVSS)
					}
				}

				// Restore original target
				c.Target = originalTarget

				// Rate limiting between subdomains
				if subdomainCount < maxSubdomains && subdomainCount < len(discoveredDomains) {
					time.Sleep(2 * time.Second)
				}
			}

			console.Logv(c.Verbose, "\n%s[TECH-DETECT]%s Subdomain analysis complete", console.ColorGreen, console.ColorReset)
		}
	}

	// FINAL RESULTS OUTPUT: Print all results at the very end (foresee or research mode)
	if (c.ForeseeMode || c.ResearchMode) && !c.AnalyzeResponses && c.OutputPath == "" && totalFound > 0 && len(allResults) > 0 {
		// For foresee/research mode: print all results at the end after ALL analysis is complete
		// Skip if analyzing responses (results shown in analysis output) or using -o flag
		// Suppress extra summary headers to avoid clutter

		// Sort and print final results
		sortedResults := make([]string, len(allResults))
		copy(sortedResults, allResults)
		sort.Strings(sortedResults)

		for _, url := range sortedResults {
			fmt.Println(url)
		}
	}

	// CLOUD/DEFERRED OUTPUT: Print bulk results at the very end for deferred modes (e.g., cloud focus)
	if deferPrint && !c.ForeseeMode && !c.ResearchMode && totalFound > 0 && len(allResults) > 0 {
		// Also echo total for deferred modes right before URLs
		if totalSummary != "" {
			fmt.Fprintln(os.Stderr, totalSummary)
		}
		sortedResults := append([]string(nil), allResults...)
		sort.Strings(sortedResults)
		for _, url := range sortedResults {
			fmt.Println(url)
		}
		os.Stdout.Sync()
	}
}

// executeAIDorks executes pre-generated dorks by substituting the target domain
func (c *Config) executeAIDorks(ctx context.Context, templateDorks []string) {
	// Substitute domain in each dork
	var dorks []string
	for _, templateDork := range templateDorks {
		// Replace any site:*.domain with site:*.c.Target
		// This handles dorks generated with a different domain
		dork := regexp.MustCompile(`site:[^\s]+`).ReplaceAllString(templateDork, fmt.Sprintf("site:%s", c.Target))
		dorks = append(dorks, dork)
	}

	if c.Verbose {
		fmt.Printf("AI Prompt: %s\n", c.AiPrompt)
		console.Logv(c.Verbose, "[AI] Executing %d dorks for %s", len(dorks), c.Target)
	}

	// Execute each dork
	var allResults []string
	for i, dork := range dorks {
		if ctx.Err() != nil {
			console.LogErr("[!] Operation cancelled")
			break
		}

		console.Logv(c.Verbose, "\n[AI] Executing dork %d/%d: %s", i+1, len(dorks), dork)

		// Store original dork, temporarily set it
		originalDork := c.Dork
		c.Dork = dork

		// Run the dork search
		results := c.dorkRun(ctx, "")
		if len(results) > 0 {
			allResults = append(allResults, results...)
			console.Logv(c.Verbose, "[AI] Dork %d found %d results", i+1, len(results))
		} else {
			console.Logv(c.Verbose, "[AI] Dork %d found 0 results", i+1)
		}

		// Restore original dork
		c.Dork = originalDork

		// Small delay between dorks
		if i < len(dorks)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	// Output results
	if len(allResults) == 0 {
		c.notFound()
		return
	}

	allResults = uniqueStrings(allResults)
	console.Logv(c.Verbose, "\n[AI] Total unique results for %s: %d", c.Target, len(allResults))

	// Send URLs through proxy if configured
	c.sendURLsThroughProxy(ctx, allResults)

	existingOutputs := loadExistingOutputs(c.OutputPath)
	analysisTargets := filterNewURLs(allResults, existingOutputs)
	if c.Verbose && len(existingOutputs) > 0 && len(analysisTargets) < len(allResults) {
		console.Logv(c.Verbose, "[OUTPUT] Skipping document analysis for %d URLs already present in output file", len(allResults)-len(analysisTargets))
	}

	if c.OutputPath != "" {
		outputOrPrintUnique(allResults, c.OutputPath)
	} else {
		for _, u := range allResults {
			// Only print URL if NOT analyzing documents (to avoid duplicate output)
			// When analyzing, the analysis function will print it nicely with context
			if !c.AnalyzeDocuments {
				fmt.Println(u)
			} else {
				// Analyze documents if flag is set (only analyzes document extensions, excludes URLs/endpoints)
				c.analyzeDocumentForSensitiveInfo(ctx, u)
			}
		}
	}

	if c.AnalyzeDocuments && c.OutputPath != "" {
		for _, u := range analysisTargets {
			c.analyzeDocumentForSensitiveInfo(ctx, u)
		}
	}
}
