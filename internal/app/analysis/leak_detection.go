package analysis

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
)

// checkPasteSitesForLeaks checks paste sites for leaked credentials
func (c *Config) checkPasteSitesForLeaks(ctx context.Context) error {
	console.Logv(c.Verbose, "[LEAK] Starting paste site credential check")

	// Parse keywords from file if it's a file path
	if c.Keywords != "" {
		if fileExists(c.Keywords) {
			lines, err := readLines(c.Keywords)
			if err != nil {
				return fmt.Errorf("failed to read keywords file: %w", err)
			}
			var keywordList []string
			for _, line := range lines {
				kw := strings.TrimSpace(line)
				if kw != "" && !strings.HasPrefix(kw, "#") {
					keywordList = append(keywordList, kw)
				}
			}
			c.Keywords = strings.Join(keywordList, ",")
			console.Logv(c.Verbose, "[LEAK] Loaded %d keywords from file", len(keywordList))
		}
		console.Logv(c.Verbose, "[LEAK] Keywords: %s", c.Keywords)
	}

	// Parse target - could be a file, stdin (newline-separated), or single domain
	var targets []string
	if strings.Contains(c.LeakTarget, "\n") {
		// Handle stdin input (newline-separated domains)
		lines := strings.Split(c.LeakTarget, "\n")
		for _, line := range lines {
			target := strings.TrimSpace(line)
			if target != "" && !strings.HasPrefix(target, "#") {
				targets = append(targets, target)
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("no valid targets from stdin")
		}
	} else if fileExists(c.LeakTarget) {
		// Read targets from file
		lines, err := readLines(c.LeakTarget)
		if err != nil {
			return fmt.Errorf("failed to read leak target file: %w", err)
		}
		for _, line := range lines {
			target := strings.TrimSpace(line)
			if target != "" && !strings.HasPrefix(target, "#") {
				targets = append(targets, target)
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("no valid targets in file: %s", c.LeakTarget)
		}
	} else {
		// Single target (domain)
		targets = append(targets, c.LeakTarget)
	}

	if len(targets) == 1 {
		console.Logv(c.Verbose, "[LEAK] Target: %s", targets[0])
	} else {
		console.Logv(c.Verbose, "[LEAK] Targets: %s", strings.Join(targets, ", "))
		console.Logv(c.Verbose, "[LEAK] Checking %d target(s)", len(targets))
	}

	// Process each target
	allResults := make(map[string][]string) // map[paste_url][]matched_terms

	for i, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if len(targets) > 1 {
			console.Logv(c.Verbose, "\n[LEAK] [%d/%d] Checking: %s", i+1, len(targets), target)
		}

		// Generate leak detection dorks
		var dorks []string
		if c.AiPrompt != "" {
			// Use AI to generate intelligent leak detection dorks
			aiDorks, err := c.generateAILeakDorks(ctx, target)
			if err != nil {
				console.LogErr("[!] Failed to generate AI leak dorks for %s: %v", target, err)
				// Fallback to standard dorks
				dorks = c.generateLeakDorks(target)
			} else {
				dorks = aiDorks
			}
		} else {
			// Standard leak detection dorks
			dorks = c.generateLeakDorks(target)
		}

		console.Logv(c.Verbose, "[LEAK] Generated %d dorks for %s", len(dorks), target)

		// Execute dorks and collect results
		for j, dork := range dorks {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			console.Logv(c.Verbose, "[LEAK] [Dork %d/%d] %s", j+1, len(dorks), dork)

			// Temporarily set the dork
			originalDork := c.Dork
			c.Dork = dork

			// Run the dork search
			if DorkRun == nil {
				return fmt.Errorf("dork runner not initialized")
			}
			results := DorkRun(ctx, toCore(c), "")

			// Restore original dork
			c.Dork = originalDork

			// Collect results
			for _, url := range results {
				if _, exists := allResults[url]; !exists {
					allResults[url] = []string{target}
					// Print result immediately
					fmt.Println(url)
					os.Stdout.Sync()

					// Analyze documents if flag is set (only analyzes document extensions, excludes URLs/endpoints)
					if c.AnalyzeDocuments {
						c.analyzeDocumentForSensitiveInfo(ctx, url)
					}
				} else {
					// Add target to existing result
					allResults[url] = append(allResults[url], target)
				}
			}

			// Small delay between dorks
			if j < len(dorks)-1 {
				time.Sleep(2 * time.Second)
			}
		}

		// Delay between targets
		if i < len(targets)-1 {
			time.Sleep(3 * time.Second)
		}
	}

	// Summary
	if len(allResults) == 0 {
		console.Logv(c.Verbose, "\n[LEAK] No results found")
		return nil
	}

	console.Logv(c.Verbose, "\n[LEAK] Summary: Found %d potential leak(s)", len(allResults))

	// Send URLs through proxy if configured
	var urls []string
	for url := range allResults {
		urls = append(urls, url)
	}
	c.sendURLsThroughProxy(ctx, urls)

	// Write to output file if specified
	if c.OutputPath != "" {
		sort.Strings(urls)
		outputOrPrintUnique(urls, c.OutputPath)
	}

	return nil
}

// generateLeakDorks generates standard dorks for leak detection
func (c *Config) generateLeakDorks(target string) []string {
	// Common paste sites and leak repositories
	pasteSites := []string{
		"pastebin.com",
		"ghostbin.com",
		"paste.ee",
		"justpaste.it",
		"controlc.com",
		"hastebin.com",
		"privatebin.net",
		"rentry.co",
		"paste.centos.org",
		"paste2.org",
		"ideone.com",
		"codepad.org",
		"gist.github.com",
		"gitlab.com/-/snippets",
		"bitbucket.org/snippets",
	}

	// Default keywords if not specified
	keywords := []string{"password", "api", "token", "secret", "credentials", "key"}
	if c.Keywords != "" {
		keywords = strings.Split(c.Keywords, ",")
		for i := range keywords {
			keywords[i] = strings.TrimSpace(keywords[i])
		}
	}

	var dorks []string

	// Generate dorks for each paste site
	for _, site := range pasteSites {
		// Basic dork with target
		dorks = append(dorks, fmt.Sprintf(`site:%s "%s"`, site, target))

		// Dork with keywords
		for _, keyword := range keywords {
			if keyword == "" {
				continue
			}
			dorks = append(dorks, fmt.Sprintf(`site:%s "%s" "%s"`, site, target, keyword))
		}

		// Email pattern dork (if target looks like a domain)
		if strings.Contains(target, ".") && !strings.Contains(target, " ") {
			dorks = append(dorks, fmt.Sprintf(`site:%s "@%s"`, site, target))
		}
	}

	return dorks
}

// generateAILeakDorks uses AI to generate intelligent leak detection dorks
func (c *Config) generateAILeakDorks(ctx context.Context, target string) ([]string, error) {
	// Check if gemini-cli is installed
	if err := checkGeminiCLI(); err != nil {
		return nil, err
	}

	console.Logv(c.Verbose, "[LEAK-AI] Generating intelligent leak detection dorks...")

	// Build AI prompt for leak detection
	systemInstructions := fmt.Sprintf(`You are a security analyst specializing in credential leak detection on paste sites.

TARGET: %s

PASTE SITES TO SEARCH:
- pastebin.com
- ghostbin.com
- paste.ee
- justpaste.it
- gist.github.com
- gitlab.com/-/snippets
- bitbucket.org/snippets
- hastebin.com
- rentry.co
- ideone.com
- codepad.org

KEYWORDS (if specified): %s

CRITICAL OUTPUT RULES:
1. Output ONLY dorks, one per line
2. NO explanations, NO numbering, NO markdown, NO extra text
3. Each dork MUST start with: site:<paste-site>
4. Do NOT use site:%s - use specific paste sites listed above
5. Use simple quoted strings - DO NOT use parentheses or OR operators
6. Keep dorks simple and focused - use 2-3 quoted terms maximum per dork

DORK GENERATION STRATEGY:
Create dorks that search paste sites for:
1. Direct mentions of the target (domain, company name, etc.)
2. Email addresses from the target domain (@target.com)
3. Combinations with credential Keywords: password, token, api, secret, key, credentials
4. Database dumps mentioning the target
5. Config files with the target name
6. Code snippets with hardcoded credentials for the target
7. API keys and tokens related to the target

CORRECT FORMAT EXAMPLES (simple quoted strings only):
site:pastebin.com "%s"
site:pastebin.com "%s" "password"
site:gist.github.com "%s" "credentials"
site:paste.ee "@%s"
site:ghostbin.com "%s" "api"
site:pastebin.com "%s" "database"
site:gist.github.com "%s" "config"
site:paste.ee "%s" "token"
site:pastebin.com "%s" "secret"
site:gist.github.com "%s" "key"

WRONG FORMAT (DO NOT USE):
site:pastebin.com "%s" (password OR credentials OR token) ← NEVER use parentheses or OR
site:pastebin.com "%s" password ← ALWAYS use quotes around search terms

IMPORTANT:
- Focus on paste sites, NOT the target domain itself
- Each dork should target a SPECIFIC paste site (not site:%s)
- Use ONLY simple quoted strings like: site:pastebin.com "target" "keyword"
- NO parentheses, NO OR operators, NO complex boolean logic
- Keep it simple - Google works better with simple quoted terms

Generate EXACTLY 20 dorks for detecting leaked credentials related to %s on paste sites.`,
		target, c.Keywords, target, target, target, target, target)

	userPrompt := fmt.Sprintf("Generate 20 paste site dorks to find leaked credentials for: %s", target)

	// Execute AI generation
	quantity := 20
	maxAttempts := 3
	executionMethods := []struct {
		name string
		exec func() (*exec.Cmd, error)
	}{
		{
			name: "pipe-direct",
			exec: func() (*exec.Cmd, error) {
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
				return cmd, nil
			},
		},
		{
			name: "pipe-bash",
			exec: func() (*exec.Cmd, error) {
				var bashCmd string

				if c.AiModel != "" {

					bashCmd = fmt.Sprintf("echo %s | gemini-cli --model %s -p %s",

						shellescape(systemInstructions),

						shellescape(c.AiModel),

						shellescape(userPrompt))

				} else {

					bashCmd = fmt.Sprintf("echo %s | gemini-cli -p %s",

						shellescape(systemInstructions),

						shellescape(userPrompt))

				}
				cmd := exec.Command("bash", "-c", bashCmd)
				cmd.Env = os.Environ()
				if home, err := os.UserHomeDir(); err == nil {
					cmd.Dir = home
				}
				return cmd, nil
			},
		},
	}

	var lastErr error

	for _, method := range executionMethods {
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			_, cmdCancel := context.WithTimeout(ctx, 60*time.Second)

			cmd, err := method.exec()
			if err != nil {
				cmdCancel()
				continue
			}

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			done := make(chan error, 1)
			go func() {
				done <- cmd.Run()
			}()

			spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			spinIdx := 0
			ticker := time.NewTicker(100 * time.Millisecond)

		selectLoop:
			for {
				select {
				case err := <-done:
					ticker.Stop()
					cmdCancel()

					if c.Verbose {
						fmt.Fprint(os.Stderr, "\r\033[K")
					}

					if err != nil {
						lastErr = err
						break selectLoop
					}

					output := stdout.String()
					if output == "" {
						lastErr = fmt.Errorf("empty response")
						break selectLoop
					}

					console.Logv(c.Verbose, "[LEAK-AI] Received response (%d bytes)", len(output))

					lines := strings.Split(output, "\n")
					var dorks []string

					for _, line := range lines {
						line = strings.TrimSpace(line)

						if line == "" ||
							strings.HasPrefix(line, "```") ||
							strings.HasPrefix(line, "#") ||
							strings.Contains(strings.ToLower(line), "here are") ||
							strings.Contains(strings.ToLower(line), "here is") {
							continue
						}

						line = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(line, "")
						line = regexp.MustCompile(`^[-*•]\s*`).ReplaceAllString(line, "")
						line = strings.TrimSpace(line)

						line = fixDorkSyntax(line)
						line = cleanNestedParentheses(line)
						line = improveDorkSyntax(line)

						if strings.Contains(line, "site:") {
							dorks = append(dorks, line)
						}
					}

					if len(dorks) == 0 {
						lastErr = fmt.Errorf("no valid dorks generated")
						break selectLoop
					}

					if len(dorks) > quantity {
						dorks = dorks[:quantity]
					}

					console.Logv(c.Verbose, "[LEAK-AI] Generated %d AI-powered leak detection dorks", len(dorks))
					return dorks, nil

				case <-ticker.C:
					if c.Verbose {
						fmt.Fprintf(os.Stderr, "\r[LEAK-AI] %s Generating dorks...", spinner[spinIdx%len(spinner)])
						spinIdx++
					}
				}
			}

			ticker.Stop()
			cmdCancel()

			if attempt < maxAttempts {
				time.Sleep(time.Second)
			}
		}
	}

	return nil, fmt.Errorf("AI leak dork generation failed: %v", lastErr)
}
