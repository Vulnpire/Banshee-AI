package ai

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
)

// generateDorksWithAI uses gemini-cli to generate custom dorks and ensures the requested quantity is honored.
func (c *Config) generateDorksWithAI(ctx context.Context, prompt string) ([]string, error) {
	targetQuantity := c.AiQuantity
	if targetQuantity < 1 {
		targetQuantity = 1
	}
	if targetQuantity > 50 {
		targetQuantity = 50
	}

	// Always restore to the sanitized target quantity after generation
	defer func() {
		c.AiQuantity = targetQuantity
	}()
	c.AiQuantity = targetQuantity

	var allDorks []string
	seen := make(map[string]struct{})
	remaining := targetQuantity

	for remaining > 0 {
		batchSize := min(remaining, 10)

		maxBatchRetries := 3
		batchAttempt := 1

		for {
			// Build a batch-specific prompt that tells the model to avoid already-seen dorks
			batchPrompt := prompt
			if len(seen) > 0 {
				avoidList := make([]string, 0, min(len(seen), 20))
				for dork := range seen {
					avoidList = append(avoidList, dork)
					if len(avoidList) >= 20 {
						break
					}
				}
				batchPrompt = fmt.Sprintf("%s\n\nYou MUST return exactly %d NEW dorks. Do NOT repeat existing dorks. Avoid these: %s", prompt, batchSize, strings.Join(avoidList, " | "))
				console.Logv(c.Verbose, "[AI] Avoid list applied for this batch (%d items)", len(avoidList))
			}

			// Use the same generation technique for each batch
			c.AiQuantity = batchSize
			dorks, err := c.generateDorksWithAIOnce(ctx, batchPrompt)
			c.AiQuantity = targetQuantity

			if err != nil {
				if batchAttempt < maxBatchRetries {
					console.Logv(c.Verbose, "[AI] Batch generation failed (attempt %d/%d): %v. Retrying...", batchAttempt, maxBatchRetries, err)
					batchAttempt++
					time.Sleep(1 * time.Second)
					continue
				}
				if len(allDorks) > 0 {
					return allDorks, err
				}
				return nil, err
			}

			added := 0
			for _, dork := range dorks {
				if _, exists := seen[dork]; exists {
					continue
				}
				seen[dork] = struct{}{}
				allDorks = append(allDorks, dork)
				added++
				if len(allDorks) == targetQuantity {
					break
				}
			}

			if added == 0 {
				if batchAttempt < maxBatchRetries {
					console.Logv(c.Verbose, "[AI] No new dorks returned (attempt %d/%d), retrying batch...", batchAttempt, maxBatchRetries)
					batchAttempt++
					time.Sleep(1 * time.Second)
					continue
				}
				return allDorks, fmt.Errorf("AI did not provide new dorks after %d retries; generated %d/%d", maxBatchRetries, len(allDorks), targetQuantity)
			}

			break
		}

		remaining = targetQuantity - len(allDorks)
		if remaining <= 0 {
			break
		}

		console.Logv(c.Verbose, "[AI] Generated %d/%d dorks, requesting %d more to satisfy -quantity", len(allDorks), targetQuantity, remaining)
	}

	if len(allDorks) > targetQuantity {
		allDorks = allDorks[:targetQuantity]
	}

	return allDorks, nil
}

// generateDorksWithAIOnce performs a single AI generation pass using the current quantity.
func (c *Config) generateDorksWithAIOnce(ctx context.Context, prompt string) ([]string, error) {
	// Check if gemini-cli is installed
	if err := checkGeminiCLI(); err != nil {
		return nil, err
	}

	// Load intelligence if in learn mode
	if c.LearnMode && c.Target != "" && c.Intelligence == nil {
		c.Intelligence = loadTargetIntelligence(c.Target)
		if c.Intelligence != nil && c.Intelligence.TotalScans > 0 {
			console.Logv(c.Verbose, "[LEARN] Loaded Intelligence: %d previous scans, %d successful dorks",
				c.Intelligence.TotalScans, len(c.Intelligence.SuccessfulDorks))
		}
	}

	// Validate quantity
	if c.AiQuantity < 1 {
		c.AiQuantity = 1
	}
	if c.AiQuantity > 50 {
		c.AiQuantity = 50
	}

	// Simplify long prompts only if --simplify flag is set
	simplifiedPrompt := prompt
	if c.Simplify && len(prompt) > 30 {
		words := strings.Fields(prompt)
		keyWords := []string{}

		for _, word := range words {
			word = strings.ToLower(strings.Trim(word, ".,!?"))
			if word != "the" && word != "and" && word != "that" &&
				word != "might" && word != "be" && word != "to" &&
				word != "a" && word != "an" && word != "or" {
				keyWords = append(keyWords, word)
				if len(keyWords) >= 4 {
					break
				}
			}
		}
		simplifiedPrompt = strings.Join(keyWords, " ")

		console.Logv(c.Verbose, "[AI] Simplified: '%s' → '%s'", prompt, simplifiedPrompt)
	}

	// Cloud awareness: AI intent only (or explicit random cloud focus)
	cloudMode := false
	if strings.EqualFold(c.RandomFocus, "cloud") ||
		strings.EqualFold(c.RandomFocus, "cloud-assets") ||
		strings.EqualFold(c.RandomFocus, "s3") ||
		strings.EqualFold(c.RandomFocus, "azure") ||
		strings.EqualFold(c.RandomFocus, "gcp") {
		cloudMode = true
	} else if detectCloudIntentWithAI(ctx, prompt, c.AiModel) || detectCloudIntentWithAI(ctx, simplifiedPrompt, c.AiModel) {
		cloudMode = true
	}

	// System instructions via stdin (cloud uses focused cloud generator; otherwise general rules)
	var systemInstructions string
	if cloudMode {
		systemInstructions = getFocusedInstructions("cloud", c.Target, "", c.AiQuantity)
	} else {
		systemInstructions = fmt.Sprintf(`You are an elite Google dorking expert for vulnerability research and reconnaissance.

	CRITICAL OUTPUT RULES:
	1. Output ONLY dorks, one per line
	2. NO explanations, NO numbering, NO markdown, NO extra text
	3. Each dork MUST start with: site:%s
	4. Use OR (not |) for alternatives inside parentheses
	5. Use ONLY ONE set of parentheses for OR groups
	6. Generate DIVERSE dorks - avoid redundancy

	OPERATORS YOU MUST USE:
	- site: (domain scope)
	- inurl: (URL paths)
	- intitle: (page title)
	- intext: (page content)
	- filetype: or ext: (file extensions)
	- after:YYYY (dates after year)
	- before:YYYY (dates before year)

	CVE & VULNERABILITY DETECTION:
	If user asks for a specific CVE by number (CVE-YYYY-XXXXX) or name (log4shell, spring4shell, etc.), generate dorks that:
	1. Target the specific vulnerable patterns/paths/signatures for that CVE
	2. Look for exposed indicators (error messages, version strings, specific endpoints)
	3. Search for proof-of-concept paths commonly used in exploits
	4. NEVER generate lazy dorks like intext:"CVE-2025-55182" - that's useless!
	5. Be CREATIVE - think about what the vulnerability exposes and target THAT

	Common CVE Examples:
	- react2shell (CVE-2025-55182): inurl:"_next/static" (Next.js static directory)
	- log4shell (CVE-2021-44228): intext:"${jndi:" OR inurl:log4j OR intext:"org.apache.logging.log4j"
	- spring4shell (CVE-2022-22965): inurl:"/actuator/" OR inurl:"spring" intext:"error"
	- heartbleed (CVE-2014-0160): intext:"OpenSSL/1.0.1" OR intext:"heartbeat"
	- ProxyShell (CVE-2021-34473): inurl:"/autodiscover/" OR inurl:"/ews/" OR inurl:"/mapi/"
	- ProxyLogon (CVE-2021-26855): inurl:"/owa/auth/" OR inurl:"/ecp/" intext:"error"
	- JNDI Injection: intext:"${jndi:ldap:" OR intext:"${jndi:rmi:" OR intext:"${jndi:dns:"
	- SSTI (Server-Side Template Injection): inurl:"{{" OR intext:"{{7*7}}" OR inurl:"/render"
	- Path Traversal: inurl:"../" OR inurl:"..../" OR inurl:"..%2f" intext:"error"
	- XXE (XML External Entity): filetype:xml intext:"<!ENTITY" OR intext:"<!DOCTYPE"
	- Insecure Deserialization: intext:"java.io.ObjectInputStream" OR intext:"pickle.loads"
	- SQL Injection indicators: inurl:? intext:"SQL syntax" OR intext:"mysql_fetch"
	- GraphQL introspection: inurl:"/graphql" OR inurl:"/graphiql" OR intext:"__schema"
	- Kubernetes exposure: inurl:"/api/v1/" OR inurl:"/metrics" intext:"kubernetes"
	- Docker exposure: inurl:"/v2/_catalog" OR inurl:"/containers/json"

	For CVE-YYYY-XXXXX format:
	- Research the CVE to understand WHAT it exploits (path, endpoint, parameter, header, etc.)
	- Generate dorks targeting the VULNERABLE COMPONENT, not the CVE number
	- Look for version strings, error messages, specific paths, or misconfigurations
	- Think: "If I were exploiting this CVE, what would I search for?"

	For unknown CVEs, use intelligent pattern matching based on the CVE name/description.

	PARAMETER DISCOVERY (for SQLi, XSS, redirect, IDOR prompts):
	When user asks for SQLi, XSS, redirect, IDOR, or parameter testing:
	- USE: inurl:? inurl:id= OR inurl:? inurl:& OR inurl:? inurl:user= OR inurl:? inurl:page=
	- These find pages with URL parameters that are vulnerable to injection

	REAL-WORLD EXAMPLES BY CATEGORY:

	Admin Panels:
	site:%s (inurl:admin OR inurl:administrator OR intitle:"admin panel")
	site:%s (inurl:cpanel OR inurl:controlpanel OR inurl:dashboard)
	site:%s (inurl:wp-admin OR inurl:wp-login)

	SQLi/XSS/Injection Targets:
	site:%s inurl:? inurl:id=
	site:%s inurl:? inurl:&
	site:%s (inurl:? inurl:page= OR inurl:? inurl:user=)
	site:%s (inurl:search OR inurl:query) inurl:?

	Sensitive Files:
	site:%s (filetype:sql OR filetype:db OR filetype:backup)
	site:%s (inurl:.env OR inurl:config.php OR inurl:.git)
	site:%s (filetype:log OR filetype:bak) intext:password

	API Endpoints:
	site:%s (inurl:api/v1 OR inurl:api/v2 OR inurl:graphql)
	site:%s inurl:api (filetype:json OR inurl:swagger)
	site:%s (inurl:/api/ OR inurl:/rest/) inurl:docs

	Config/Backup Files:
	site:%s (inurl:backup OR inurl:.old OR inurl:.bak)
	site:%s (intext:"DB_PASSWORD" OR intext:"api_key")
	site:%s (filetype:yml OR filetype:ini) intext:password

	Exposed Directories:
	site:%s intitle:"index of" (inurl:backup OR inurl:admin)
	site:%s intitle:"directory listing" inurl:files
	site:%s inurl:phpmyadmin

	AVOID REDUNDANCY:
	❌ BAD: Generate 5 dorks all looking for admin panels with slight variations
	✅ GOOD: Generate diverse dorks: admin panel, SQL file, API endpoint, config file, backup

	CORRECT FORMAT:
	site:%s (operator1 OR operator2)
	site:%s inurl:path filetype:ext
	site:%s inurl:? inurl:param=

	INCORRECT EXAMPLES (DO NOT USE):
	❌ site:%s (filetype:pdf) (intext:2021)
	❌ site:%s (intitle:"index of" (intext:"2021"))
	❌ site:%s filetype:pdf OR filetype:doc (no parentheses for OR)

	Generate EXACTLY %d dorks. Output only the dorks, nothing else.`,
			c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.AiQuantity)
	}

	// If extensions are specified, instruct AI to constrain filetypes (no ext:)
	if c.Extension != "" {
		allowedExts := parseExtensionsList(c.Extension)
		if len(allowedExts) > 0 {
			var parts []string
			for _, e := range allowedExts {
				parts = append(parts, "filetype:"+strings.ToLower(e))
			}
			systemInstructions += fmt.Sprintf("\n\nFILETYPE CONSTRAINTS:\n- Only use these filetypes: %s\n- Do NOT use ext: operator\n- Do NOT use any other filetypes", strings.Join(parts, " OR "))
		}
	}

	// User prompt via -p flag - enhance with intelligence if learning mode is enabled
	userPrompt := ""
	// If extensions are provided, guide the model explicitly
	extFocus := ""
	if c.Extension != "" {
		allowedExts := parseExtensionsList(c.Extension)
		if len(allowedExts) > 0 {
			extFocus = fmt.Sprintf(" Focus ONLY on these document types: %s.", strings.ToUpper(strings.Join(allowedExts, ", ")))
		}
	}
	if c.LearnMode && c.Intelligence != nil && c.Intelligence.TotalScans > 0 {
		enhancedPrompt := generateLearnedPrompt(c.Intelligence, simplifiedPrompt, "")
		userPrompt = enhancedPrompt
		console.Logv(c.Verbose, "[LEARN] Enhanced prompt with historical intelligence")
	} else {
		if cloudMode {
			userPrompt = fmt.Sprintf("Generate %d advanced cloud enumeration dorks for %s. User request: %s.%s", c.AiQuantity, c.Target, simplifiedPrompt, extFocus)
		} else {
			userPrompt = fmt.Sprintf("Generate %d Google search dorks for site:%s to: %s%s", c.AiQuantity, c.Target, simplifiedPrompt, extFocus)
		}
	}

	// Inject cloud-specific guidance when the prompt implies cloud enumeration
	if cloudMode {
		cloudHint := buildCloudPromptHint(c.Target)
		userPrompt = fmt.Sprintf("%s\n\nCLOUD ENUMERATION FOCUS:\n%s", userPrompt, cloudHint)
	}

	console.Logv(c.Verbose, "[AI] Generating %d dorks with AI...", c.AiQuantity)

	// Try multiple execution methods
	maxAttempts := 3
	executionMethods := []struct {
		name string
		exec func() (*exec.Cmd, error)
	}{
		{
			name: "pipe-direct",
			exec: func() (*exec.Cmd, error) {
				// echo "instructions" | gemini-cli --model "model-name" -p "prompt"
				// Only add --model flag if aiModel is specified
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
				// bash -c 'echo "instructions" | gemini-cli --model "model-name" -p "prompt"'
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
		{
			name: "pipe-sh",
			exec: func() (*exec.Cmd, error) {
				var shCmd string
				if c.AiModel != "" {
					shCmd = fmt.Sprintf("echo %s | gemini-cli --model %s -p %s",
						shellescape(systemInstructions),
						shellescape(c.AiModel),
						shellescape(userPrompt))
				} else {
					shCmd = fmt.Sprintf("echo %s | gemini-cli -p %s",
						shellescape(systemInstructions),
						shellescape(userPrompt))
				}
				cmd := exec.Command("sh", "-c", shCmd)
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

			// 60 second timeout
			cmdCtx, cmdCancel := context.WithTimeout(ctx, 60*time.Second)

			cmd, err := method.exec()
			if err != nil {
				cmdCancel()
				continue
			}

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			// Run with spinner
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
						if cmdCtx.Err() == context.DeadlineExceeded {
							lastErr = fmt.Errorf("timeout (method: %s, attempt: %d/%d)", method.name, attempt, maxAttempts)
							console.Logv(c.Verbose, "[AI] %v", lastErr)
							break selectLoop
						}

						stderrStr := stderr.String()
						// Ignore deprecation warnings
						if !strings.Contains(stderrStr, "DeprecationWarning") && stderrStr != "" {
							lastErr = fmt.Errorf("error (method: %s): %s", method.name, stderrStr)
							console.Logv(c.Verbose, "[AI] %v", lastErr)
							break selectLoop
						}
					}

					output := stdout.String()
					if output == "" {
						lastErr = fmt.Errorf("empty response (method: %s)", method.name)
						console.Logv(c.Verbose, "[AI] %v", lastErr)
						break selectLoop
					}

					// Parse output
					console.Logv(c.Verbose, "[AI] Received response (%d bytes)", len(output))

					lines := strings.Split(output, "\n")
					var dorks []string

					for _, line := range lines {
						line = strings.TrimSpace(line)

						// Skip empty, markdown, explanations
						if line == "" ||
							strings.HasPrefix(line, "```") ||
							strings.HasPrefix(line, "#") ||
							strings.Contains(strings.ToLower(line), "here are") ||
							strings.Contains(strings.ToLower(line), "here is") ||
							strings.Contains(strings.ToLower(line), "i've generated") {
							continue
						}

						// Remove numbering and bullets
						line = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(line, "")
						line = regexp.MustCompile(`^[-*•]\s*`).ReplaceAllString(line, "")
						line = strings.TrimSpace(line)

						// Fix syntax, clean nested parens, and improve with proper parentheses
						line = fixDorkSyntax(line)
						line = cleanNestedParentheses(line)
						line = improveDorkSyntax(line)

						// Apply subdomain-only filter if -a flag is set
						if c.IncludeSubdomains {
							line = applySubdomainOnlyFilter(line, c.Target)
						}

						// Must contain site: to be valid
						if strings.Contains(line, "site:") {
							dorks = append(dorks, line)
						}
					}

					if len(dorks) == 0 {
						lastErr = fmt.Errorf("no valid dorks in output")
						if c.Verbose {
							console.Logv(c.Verbose, "[AI] %v. Raw output:\n%s", lastErr, output)
						}
						break selectLoop
					}

						// Limit to requested quantity
						if len(dorks) > c.AiQuantity {
							dorks = dorks[:c.AiQuantity]
						}

						// Enforce extension constraints if provided
						if c.Extension != "" {
							allowedExts := parseExtensionsList(c.Extension)
							if len(allowedExts) > 0 {
								console.Logv(c.Verbose, "[EXT] Enforcing extensions on AI dorks: %v", allowedExts)
								dorks = enforceExtensions(dorks, allowedExts)
							}
						}

						// If AI returned fewer than requested, proceed with what we have (don't hard fail)
						if len(dorks) < c.AiQuantity {
							console.Logv(c.Verbose, "[AI] Only received %d/%d dorks; retrying to satisfy quantity", len(dorks), c.AiQuantity)
							lastErr = fmt.Errorf("insufficient dorks (%d/%d)", len(dorks), c.AiQuantity)
							break selectLoop
						}

					if !c.SuppressAIDorkList {
						console.Logv(c.Verbose, "[AI] Generated %d dorks:", len(dorks))
						if c.Verbose {
							for i, dork := range dorks {
								fmt.Printf("  %d. %s\n", i+1, dork)
							}
						}
					}

					return dorks, nil

				case <-ticker.C:
					if c.Verbose {
						spinnerChar := console.ColorizeSpinner(spinner[spinIdx%len(spinner)])
						aiTag := console.ColorizeVerboseOutput("[AI]")
						fmt.Fprintf(os.Stderr, "\r%s %s Waiting for AI response...", aiTag, spinnerChar)
						spinIdx++
					}
				}
			}

			ticker.Stop()
			cmdCancel()

			// Small delay between retries
			if attempt < maxAttempts {
				time.Sleep(time.Second)
			}
		}
	}

	// All methods failed
	return nil, fmt.Errorf("gemini-cli failed after all attempts. Last error: %v\n\nDiagnostics:\n1. Test: echo \"test\" | gemini-cli -p \"say hello\"\n2. Check: echo $GEMINI_API_KEY\n3. Verify: which gemini-cli", lastErr)
}

// generateRandomDorks generates diverse random dorks for various asset types
func (c *Config) generateRandomDorks(ctx context.Context) ([]string, error) {
	// Check if gemini-cli is installed
	if err := checkGeminiCLI(); err != nil {
		return nil, err
	}

	// Load intelligence if in learn mode
	if c.LearnMode && c.Target != "" && c.Intelligence == nil {
		c.Intelligence = loadTargetIntelligence(c.Target)
		if c.Intelligence != nil && c.Intelligence.TotalScans > 0 {
			console.Logv(c.Verbose, "[LEARN] Loaded Intelligence: %d previous scans, %d successful dorks",
				c.Intelligence.TotalScans, len(c.Intelligence.SuccessfulDorks))
		}
	}

	// Validate quantity
	if c.AiQuantity < 1 {
		c.AiQuantity = 1
	}
	if c.AiQuantity > 50 {
		c.AiQuantity = 50
	}

	// Load ignore list if provided (unless in flush mode)
	var ignoredDorks []string
	if c.IgnoreFile != "" && !c.FlushMode && fileExists(c.IgnoreFile) {
		dorks, err := readLines(c.IgnoreFile)
		if err != nil {
			console.Logv(c.Verbose, "[AI] Warning: Could not read ignore file: %v", err)
		} else {
			ignoredDorks = dorks
			console.Logv(c.Verbose, "[AI] Loaded %d dorks to ignore from: %s", len(ignoredDorks), c.IgnoreFile)
		}
	} else if c.FlushMode {
		console.Logv(c.Verbose, "[AI] Flush mode enabled - ignoring previous dorks")
	}

	// Build ignore context for Gemini
	ignoreContext := ""
	if len(ignoredDorks) > 0 {
		ignoreContext = "\n\nPREVIOUSLY USED DORKS (DO NOT GENERATE THESE):\n"
		for _, dork := range ignoredDorks {
			ignoreContext += dork + "\n"
		}
	}

	// Enhance with intelligence context if in learn mode
	intelligenceContext := ""
	if c.LearnMode && c.Intelligence != nil && c.Intelligence.TotalScans > 0 {
		intelligenceContext = "\n\n" + generateLearnedPrompt(c.Intelligence, "generate new dorks", c.RandomFocus)
		console.Logv(c.Verbose, "[LEARN] Enhanced generation with historical intelligence")
	}

	// Determine focus and build appropriate system instructions
	var systemInstructions string
	var userPrompt string

	if c.RandomFocus != "" {
		// Focused random dork generation
		focusInstructions := getFocusedInstructions(c.RandomFocus, c.Target, ignoreContext, c.AiQuantity)
		systemInstructions = focusInstructions + intelligenceContext
		userPrompt = fmt.Sprintf("Generate %d Google search dorks for site:%s focused on %s vulnerabilities/assets",
			c.AiQuantity, c.Target, c.RandomFocus)
		console.Logv(c.Verbose, "[AI] Generating %d random dorks focused on: %s", c.AiQuantity, c.RandomFocus)
	} else {
		// Completely diverse random dork generation (original behavior)
		systemInstructions = fmt.Sprintf(`You are a Google dorking expert specializing in security reconnaissance. Your task is to generate DIVERSE and CREATIVE search dorks for site:%s to discover various types of security-relevant assets.

CRITICAL OUTPUT RULES:
1. Output ONLY dorks, one per line
2. NO explanations, NO numbering, NO markdown, NO extra text
3. Each dork MUST start with: site:%s
4. Generate DIVERSE dorks across DIFFERENT categories
5. Use OR (not |) for alternatives inside parentheses
6. Use ONLY ONE set of parentheses for OR groups

CATEGORIES TO EXPLORE (pick different ones for each dork):
1. Admin Panels & Dashboards: inurl:admin, inurl:dashboard, inurl:panel, intitle:"admin", intitle:"dashboard"
2. Authentication: inurl:login, inurl:signin, inurl:auth, intitle:"login", intitle:"sign in"
3. API Endpoints: inurl:api, inurl:swagger, inurl:graphql, inurl:v1, inurl:rest
4. Configuration Files: filetype:env, filetype:conf, filetype:config, filetype:ini, filetype:yaml, filetype:yml
5. Backup Files: filetype:bak, filetype:backup, filetype:old, filetype:save, inurl:backup
6. Database Files: filetype:sql, filetype:db, filetype:sqlite, filetype:mdb
7. Logs: filetype:log, inurl:logs, intitle:"log"
8. Exposed Directories: intitle:"index of", intext:"parent directory", intitle:"directory listing"
9. Source Code: filetype:java, filetype:php, filetype:asp, filetype:aspx, filetype:jsp
10. Credentials: intext:password, intext:username, intext:api_key, intext:secret
11. Documents: filetype:pdf, filetype:doc, filetype:docx, filetype:xls, filetype:xlsx
12. Upload Functionality: inurl:upload, inurl:file, inurl:attachment
13. Development/Staging: inurl:dev, inurl:test, inurl:staging, inurl:beta
14. Version Control: inurl:.git, inurl:.svn, inurl:.env
15. Potential XSS: inurl:search, inurl:query, inurl:redirect, inurl:url, inurl:? inurl:q=
16. Potential SQLi: inurl:? inurl:id=, inurl:? inurl:page=, inurl:? inurl:cat=, inurl:? inurl:product=
17. Parameter Mining: inurl:? inurl:&, inurl:? OR inurl:&, inurl:? inurl:search
18. Open Redirects: inurl:redirect, inurl:url, inurl:return, inurl:next
19. Sensitive Paths: inurl:includes, inurl:config, inurl:admin, inurl:phpinfo

DORK QUALITY RULES:
- Combine operators creatively (e.g., filetype + intext, inurl + intitle)
- Use date operators when relevant: after:YYYY before:YYYY
- Target different attack surfaces each time
- Be specific and actionable
- Avoid generic dorks like "site:domain.com admin"

PARENTHESES RULES:
- Group OR expressions: (operator1 OR operator2 OR operator3)
- NO nested parentheses
- Date operators go OUTSIDE parentheses

CORRECT FORMAT EXAMPLES:
site:%s (inurl:admin OR inurl:dashboard)
site:%s (filetype:env OR filetype:config OR filetype:ini)
site:%s (inurl:api OR inurl:swagger) (filetype:json OR filetype:yaml)
site:%s (inurl:? inurl:id= OR inurl:? inurl:page=) intext:mysql
site:%s intitle:"index of" (filetype:sql OR filetype:bak)
site:%s (inurl:upload OR inurl:file) after:2020
site:%s inurl:? inurl:& (intext:"error" OR intext:"warning")
site:%s (inurl:search OR inurl:query) (inurl:? OR inurl:&)%s

Generate EXACTLY %d DIVERSE dorks exploring DIFFERENT categories. Output only the dorks, nothing else.`,
			c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, c.Target, ignoreContext, c.AiQuantity)

		systemInstructions += intelligenceContext

		userPrompt = fmt.Sprintf("Generate %d diverse Google search dorks for site:%s to discover various security-relevant assets (admin panels, APIs, exposed files, potential vulnerabilities, etc.)",
			c.AiQuantity, c.Target)
		console.Logv(c.Verbose, "[AI] Generating %d random diverse dorks with AI...", c.AiQuantity)
	}

	// Try multiple execution methods
	maxAttempts := 3
	maxRateLimitRetries := 5 // NEW: separate retry limit for rate limiting
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
		{
			name: "pipe-sh",
			exec: func() (*exec.Cmd, error) {
				var shCmd string
				if c.AiModel != "" {
					shCmd = fmt.Sprintf("echo %s | gemini-cli --model %s -p %s",
						shellescape(systemInstructions),
						shellescape(c.AiModel),
						shellescape(userPrompt))
				} else {
					shCmd = fmt.Sprintf("echo %s | gemini-cli -p %s",
						shellescape(systemInstructions),
						shellescape(userPrompt))
				}
				cmd := exec.Command("sh", "-c", shCmd)
				cmd.Env = os.Environ()
				if home, err := os.UserHomeDir(); err == nil {
					cmd.Dir = home
				}
				return cmd, nil
			},
		},
	}

	// If the combined prompt is large, avoid shell-based fallbacks to prevent ARG_MAX/shell truncation
	payloadLen := len(systemInstructions) + len(userPrompt)
	if payloadLen > 4000 {
		executionMethods = executionMethods[:1] // keep only pipe-direct
		console.Logv(c.Verbose, "[OSINT] Large prompt detected (%d bytes), using direct stdin execution only", payloadLen)
	}

	var lastErr error

	for _, method := range executionMethods {
		rateLimitRetries := 0

		// Rate limit retry wrapper
		for rateLimitRetries <= maxRateLimitRetries {
			if rateLimitRetries > 0 {
				console.Logv(c.Verbose, "[AI] Rate limit retry %d/%d", rateLimitRetries, maxRateLimitRetries)
			}

			// Regular attempt loop (network errors, timeouts, etc)
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}

				cmdCtx, cmdCancel := context.WithTimeout(ctx, 60*time.Second)

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

				wasRateLimited := false

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
							if cmdCtx.Err() == context.DeadlineExceeded {
								lastErr = fmt.Errorf("timeout (method: %s, attempt: %d/%d)", method.name, attempt, maxAttempts)
								console.Logv(c.Verbose, "[AI] %v", lastErr)
								break selectLoop
							}

							stderrStr := stderr.String()

							// Check for rate limit error
							if strings.Contains(stderrStr, "429 Too Many Requests") ||
								strings.Contains(stderrStr, "503 Service Unavailable") ||
								strings.Contains(stderrStr, "quota") ||
								strings.Contains(stderrStr, "Quota exceeded") ||
								strings.Contains(stderrStr, "overloaded") {

								// Parse retry delay from error message
								retryDelay := parseRetryDelay(stderrStr)
								if retryDelay > 0 {
									console.Logv(c.Verbose, "[AI] Rate limited. Waiting %.1f seconds before retry...", retryDelay.Seconds())

									// Wait with countdown
									waitWithCountdown(ctx, retryDelay, c.Verbose)

									if ctx.Err() != nil {
										return nil, ctx.Err()
									}

									wasRateLimited = true
									lastErr = fmt.Errorf("rate limited (will retry)")
									break selectLoop
								}
							}

							if !strings.Contains(stderrStr, "DeprecationWarning") && stderrStr != "" {
								lastErr = fmt.Errorf("error (method: %s): %s", method.name, stderrStr)
								console.Logv(c.Verbose, "[AI] %v", lastErr)
								break selectLoop
							}
						}

						output := stdout.String()
						if output == "" {
							lastErr = fmt.Errorf("empty response (method: %s)", method.name)
							console.Logv(c.Verbose, "[AI] %v", lastErr)
							break selectLoop
						}

						console.Logv(c.Verbose, "[AI] Received response (%d bytes)", len(output))

						lines := strings.Split(output, "\n")
						var dorks []string

						for _, line := range lines {
							line = strings.TrimSpace(line)

							if line == "" ||
								strings.HasPrefix(line, "```") ||
								strings.HasPrefix(line, "#") ||
								strings.Contains(strings.ToLower(line), "here are") ||
								strings.Contains(strings.ToLower(line), "here is") ||
								strings.Contains(strings.ToLower(line), "i've generated") {
								continue
							}

							line = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(line, "")
							line = regexp.MustCompile(`^[-*•]\s*`).ReplaceAllString(line, "")
							line = strings.TrimSpace(line)

							line = fixDorkSyntax(line)
							line = cleanNestedParentheses(line)
							line = improveDorkSyntax(line)

							// Apply subdomain-only filter if -a flag is set
							if c.IncludeSubdomains {
								line = applySubdomainOnlyFilter(line, c.Target)
							}

							// Accept dorks with site: OR dorks for cloud enumeration (which may omit site:)
							isCloudMode := strings.ToLower(c.RandomFocus) == "cloud" ||
								strings.ToLower(c.RandomFocus) == "cloud-assets" ||
								strings.ToLower(c.RandomFocus) == "s3" ||
								strings.ToLower(c.RandomFocus) == "azure" ||
								strings.ToLower(c.RandomFocus) == "gcp"

							// Cloud mode: accept dorks with or without site: operator
							// Normal mode: require site: operator
							if strings.Contains(line, "site:") || (isCloudMode && len(line) > 5) {
								dorks = append(dorks, line)
							}
						}

						if len(dorks) == 0 {
							lastErr = fmt.Errorf("no valid dorks in output")
							if c.Verbose {
								console.Logv(c.Verbose, "[AI] %v. Raw output:\n%s", lastErr, output)
							}
							break selectLoop
						}

						if len(dorks) > c.AiQuantity {
							dorks = dorks[:c.AiQuantity]
						}

						focusMsg := ""
						if c.RandomFocus != "" {
							focusMsg = fmt.Sprintf(" (%s-focused)", c.RandomFocus)
						}
						console.Logv(c.Verbose, "[AI] Generated %d random dorks%s:", len(dorks), focusMsg)
						if c.Verbose {
							for i, dork := range dorks {
								fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, dork)
							}
						}

						// Save to ignore file if specified (unless in flush mode)
						if c.IgnoreFile != "" && !c.FlushMode {
							if err := appendDorksToIgnoreFile(c.IgnoreFile, dorks); err != nil {
								console.Logv(c.Verbose, "[AI] Warning: Could not save to ignore file: %v", err)
							} else {
								console.Logv(c.Verbose, "[AI] Saved %d dorks to ignore file: %s", len(dorks), c.IgnoreFile)
							}
						} else if c.FlushMode {
							console.Logv(c.Verbose, "[AI] Flush mode - dorks not saved to ignore file")
						}

						return dorks, nil

					case <-ticker.C:
						if c.Verbose {
							fmt.Fprintf(os.Stderr, "\r[AI] %s Generating random dorks...", spinner[spinIdx%len(spinner)])
							spinIdx++
						}
					}
				}

				ticker.Stop()
				cmdCancel()

				// If rate limited, break out of attempt loop and retry in rate limit loop
				if wasRateLimited {
					rateLimitRetries++
					console.Logv(c.Verbose, "[AI] Retrying after cooldown...")
					break // Break out of attempt loop, continue in rate limit loop
				}

				// Regular error - wait before next attempt
				if attempt < maxAttempts {
					time.Sleep(time.Second)
				}
			}

			// If we were rate limited, continue the rate limit retry loop
			// Otherwise break out (either success or all attempts failed)
			if rateLimitRetries == 0 || rateLimitRetries > maxRateLimitRetries {
				break
			}
		}

		// If we got here and last error was rate limit, we exceeded rate limit retries
		if rateLimitRetries > maxRateLimitRetries {
			lastErr = fmt.Errorf("exceeded rate limit retries (%d attempts)", maxRateLimitRetries)
		}
	}

	return nil, fmt.Errorf("gemini-cli failed after all attempts. Last error: %v\n\nDiagnostics:\n1. Test: echo \"test\" | gemini-cli -p \"say hello\"\n2. Check: echo $GEMINI_API_KEY\n3. Verify: which gemini-cli", lastErr)

}

// parseRetryDelay extracts retry delay from Gemini rate limit error message
func parseRetryDelay(errMsg string) time.Duration {
	// Pattern 1: "Please retry in 14.150910985s"
	re1 := regexp.MustCompile(`Please retry in ([0-9.]+)s`)
	if matches := re1.FindStringSubmatch(errMsg); len(matches) > 1 {
		if seconds, err := time.ParseDuration(matches[1] + "s"); err == nil {
			return seconds
		}
	}

	// Pattern 2: "retryDelay":"14s"
	re2 := regexp.MustCompile(`"retryDelay":"(\d+)s"`)
	if matches := re2.FindStringSubmatch(errMsg); len(matches) > 1 {
		if seconds, err := time.ParseDuration(matches[1] + "s"); err == nil {
			return seconds
		}
	}

	// Default: 15 seconds if can't parse
	return 15 * time.Second
}

// waitWithCountdown waits for duration with visual countdown
func waitWithCountdown(ctx context.Context, duration time.Duration, verbose bool) {
	if !verbose {
		// Silent wait
		select {
		case <-time.After(duration):
			return
		case <-ctx.Done():
			return
		}
	}

	// Verbose countdown
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	remaining := duration

	for remaining > 0 {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "\r\033[K[AI] Wait cancelled\n")
			return
		case <-ticker.C:
			remaining -= time.Second
			if remaining > 0 {
				fmt.Fprintf(os.Stderr, "\r[AI] ⏳ Cooldown: %.0fs remaining...", remaining.Seconds())
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\r\033[K[AI] ✓ Cooldown complete\n")
}

// getFocusedInstructions returns specialized system instructions based on vulnerability focus
func getFocusedInstructions(focus, target, ignoreContext string, quantity int) string {
	baseRules := fmt.Sprintf(`You are a Google dorking expert specializing in security reconnaissance. 

CRITICAL OUTPUT RULES:
1. Output ONLY dorks, one per line
2. NO explanations, NO numbering, NO markdown, NO extra text
3. Each dork MUST start with: site:%s
4. Use OR (not |) for alternatives inside parentheses
5. Use ONLY ONE set of parentheses for OR groups

PARENTHESES RULES:
- Group OR expressions: (operator1 OR operator2 OR operator3)
- NO nested parentheses
- Date operators go OUTSIDE parentheses`, target)

	var focusedInstructions string

	switch strings.ToLower(focus) {
	case "sqli", "sql", "sql-injection":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: SQL Injection Vulnerabilities

TARGET PATTERNS:
- URL parameters with inurl:& for multi-param discovery: inurl:? inurl:&, inurl:? inurl:id=, inurl:? inurl:page=
- Error messages: intext:"mysql", intext:"sql syntax", intext:"mysqli", intext:"sqlserver", intext:"database error"
- Database-driven Pages: inurl:view, inurl:detail, inurl:article, inurl:news, inurl:show
- Admin/Login panels with parameters: inurl:admin, inurl:login combined with parameters
- Search functionality: inurl:search, inurl:query combined with parameters

DORK EXAMPLES (use inurl:& to find pages with multiple parameters):
site:%s inurl:? inurl:& intext:mysql
site:%s inurl:? inurl:id= (intext:"mysql" OR intext:"sql")
site:%s (inurl:view OR inurl:detail) inurl:? inurl:&
site:%s inurl:? inurl:page= (intext:"database error" OR intext:"mysqli")
site:%s (inurl:search OR inurl:query) inurl:? inurl:&
site:%s inurl:? (inurl:cat= OR inurl:product= OR inurl:user=)%s

Generate EXACTLY %d dorks focused on SQL injection. PRIORITIZE inurl:& to find multi-parameter pages.`, baseRules, target, target, target, target, target, target, ignoreContext, quantity)

	case "xss", "cross-site-scripting":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: Cross-Site Scripting (XSS) Vulnerabilities

TARGET PATTERNS:
- Search forms with inurl:&: inurl:search inurl:?, inurl:query inurl:&, inurl:q= inurl:&
- User input fields: inurl:comment, inurl:message, inurl:feedback, inurl:contact
- Redirect parameters: inurl:redirect, inurl:url=, inurl:return=, inurl:next=
- Error Pages: intitle:"error", intitle:"404", intitle:"not found"
- Profile/User Pages: inurl:profile, inurl:user, inurl:member

DORK EXAMPLES (use inurl:& for multi-param XSS):
site:%s inurl:search inurl:? inurl:&
site:%s inurl:query (inurl:? inurl:q= OR inurl:? inurl:keyword=)
site:%s (inurl:comment OR inurl:message) inurl:? inurl:&
site:%s (inurl:redirect OR inurl:url=) inurl:?
site:%s (inurl:profile OR inurl:user) inurl:? (inurl:name= OR inurl:id=)
site:%s (inurl:search OR inurl:find) inurl:? inurl:&%s

Generate EXACTLY %d dorks focused on XSS. PRIORITIZE inurl:& to find reflection points with multiple parameters.`, baseRules, target, target, target, target, target, target, ignoreContext, quantity)

	case "redirect", "open-redirect":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: Open Redirect Vulnerabilities

TARGET PATTERNS:
- Redirect params with inurl:&: inurl:redirect inurl:?, inurl:url= inurl:&, inurl:return inurl:?
- Return URLs: inurl:return, inurl:returnto, inurl:ret=, inurl:next=, inurl:continue=
- Login/Logout redirects: inurl:login, inurl:logout, inurl:signin combined with redirect params
- External link warnings: intitle:"external", intitle:"leaving", intext:"redirect"

DORK EXAMPLES (use inurl:& for multi-param redirects):
site:%s inurl:redirect inurl:? inurl:&
site:%s (inurl:url= OR inurl:return) inurl:?
site:%s (inurl:login OR inurl:logout) (inurl:redirect OR inurl:return)
site:%s inurl:next inurl:? inurl:&
site:%s (inurl:goto= OR inurl:link= OR inurl:continue=) inurl:?
site:%s inurl:redir inurl:? inurl:&%s

Generate EXACTLY %d dorks focused on open redirect. PRIORITIZE inurl:& to find complex redirect chains.`, baseRules, target, target, target, target, target, target, ignoreContext, quantity)

	case "exposure", "exposed", "disclosure", "info":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: Information Exposure & Sensitive Data Disclosure

TARGET PATTERNS:
- Config files: filetype:env, filetype:config, filetype:ini, filetype:yaml, filetype:xml
- Backup files: filetype:bak, filetype:backup, filetype:old, filetype:save, inurl:backup
- Database files: filetype:sql, filetype:db, filetype:sqlite, filetype:mdb
- Log files: filetype:log, inurl:logs, intitle:"log"
- Exposed directories: intitle:"index of", intext:"parent directory"
- Credentials: intext:password, intext:api_key, intext:secret, intext:token
- Version control: inurl:.git, inurl:.svn, inurl:.env

DORK EXAMPLES:
site:%s (filetype:env OR filetype:config OR filetype:ini)
site:%s intitle:"index of" (filetype:bak OR filetype:sql)
site:%s (inurl:.git OR inurl:.svn) intitle:"index of"
site:%s (filetype:log OR inurl:logs) (intext:password OR intext:error)%s

Generate EXACTLY %d dorks focused on information exposure. Target configuration, backups, and sensitive files.`, baseRules, target, target, target, target, ignoreContext, quantity)

	case "lfi", "local-file-inclusion", "rfi", "file-inclusion":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: Local/Remote File Inclusion Vulnerabilities

TARGET PATTERNS:
- File parameters: inurl:file=, inurl:path=, inurl:page=, inurl:include=, inurl:doc=
- Template/Theme loading: inurl:template=, inurl:theme=, inurl:skin=
- Language/Locale files: inurl:lang=, inurl:language=, inurl:locale=
- Include directives: inurl:include, inurl:require, inurl:load

DORK EXAMPLES:
site:%s (inurl:file= OR inurl:path= OR inurl:page=) (inurl:? OR inurl:= OR inurl:&)
site:%s (inurl:include= OR inurl:require=) inurl:?
site:%s (inurl:template= OR inurl:theme=) (inurl:? OR inurl:=)
site:%s (inurl:lang= OR inurl:language=) (filetype:php OR filetype:asp)%s

Generate EXACTLY %d dorks focused on file inclusion vulnerabilities. Target file loading parameters.`, baseRules, target, target, target, target, ignoreContext, quantity)

	case "rce", "command-injection", "code-execution":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: Remote Code Execution & Command Injection

TARGET PATTERNS:
- Command parameters: inurl:cmd=, inurl:command=, inurl:exec=, inurl:execute=
- Upload functionality: inurl:upload, inurl:file, inurl:attachment
- Shell interfaces: intitle:"shell", intitle:"cmd", intitle:"terminal", intitle:"console"
- Debugging/Test endpoints: inurl:debug, inurl:test, inurl:dev, inurl:eval

DORK EXAMPLES:
site:%s (inurl:cmd= OR inurl:command= OR inurl:exec=)
site:%s (inurl:upload OR inurl:file) (filetype:php OR filetype:asp)
site:%s (intitle:shell OR intitle:terminal OR intitle:console)
site:%s (inurl:debug OR inurl:test) (inurl:? OR inurl:=)%s

Generate EXACTLY %d dorks focused on command injection and code execution. Target command parameters and upload endpoints.`, baseRules, target, target, target, target, ignoreContext, quantity)

	case "idor", "broken-access", "authorization":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: IDOR & Broken Access Control

TARGET PATTERNS:
- ID params with inurl:&: inurl:id= inurl:&, inurl:uid= inurl:?, inurl:user_id= inurl:&
- Profile/Account Pages: inurl:profile, inurl:account, inurl:user, inurl:member, inurl:dashboard
- Document access: inurl:document, inurl:file, inurl:download, inurl:view
- Order/Transaction Pages: inurl:order, inurl:invoice, inurl:receipt, inurl:transaction

DORK EXAMPLES (use inurl:& for multi-param IDOR):
site:%s (inurl:profile OR inurl:account) inurl:? inurl:&
site:%s inurl:id= inurl:? inurl:&
site:%s (inurl:document OR inurl:file) inurl:? (inurl:id= OR inurl:doc=)
site:%s (inurl:order OR inurl:invoice) inurl:? inurl:id=
site:%s (inurl:user OR inurl:member) inurl:? inurl:&
site:%s inurl:download inurl:? (inurl:id= OR inurl:file=)%s

Generate EXACTLY %d dorks focused on IDOR. PRIORITIZE inurl:& to find resources with multiple access control parameters.`, baseRules, target, target, target, target, target, target, ignoreContext, quantity)

	case "api", "endpoints":
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: API Endpoints & Documentation

TARGET PATTERNS:
- API paths: inurl:api, inurl:/v1/, inurl:/v2/, inurl:rest, inurl:graphql
- API docs: inurl:swagger, inurl:openapi, inurl:api-docs, intitle:"api documentation"
- Endpoints: inurl:endpoint, inurl:service, inurl:method
- JSON/XML responses: filetype:json, filetype:xml

DORK EXAMPLES:
site:%s (inurl:api OR inurl:rest) (inurl:/v1/ OR inurl:/v2/)
site:%s (inurl:swagger OR inurl:openapi OR inurl:api-docs)
site:%s inurl:graphql (intitle:playground OR intitle:explorer)
site:%s (inurl:api OR inurl:endpoint) (filetype:json OR filetype:xml)%s

Generate EXACTLY %d dorks focused on API discovery. Target API paths, documentation, and endpoints.`, baseRules, target, target, target, target, ignoreContext, quantity)

	case "cloud", "cloud-assets", "s3", "azure", "gcp":
		focusedInstructions = fmt.Sprintf(`You are a Google dorking expert specializing in advanced cloud asset discovery and misconfiguration hunting.

OUTPUT RULES:
- Output ONLY dorks, one per line.
- NO explanations, NO numbering, NO markdown, NO extra text.
- Prefer including "%[1]s" or site:%[1]s in each query; when targeting provider hosts directly, include "%[1]s" as a keyword (not as site:).
- Use OR (not |) inside a single set of parentheses; avoid nested parentheses.
- Favor filetype: filters (not ext:).
- ONE PROVIDER PER DORK: do NOT chain multiple different cloud hostnames in the same dork. Each dork should focus on a single provider family.

GOAL: Generate EXACTLY %[2]d cloud-focused dorks that find exposed storage, repos, credentials, and shared documents for %[1]s.

CLOUD TARGETS (one per dork):
- AWS: s3.amazonaws.com, s3-us-west-2.amazonaws.com, s3-external-1.amazonaws.com, s3.dualstack.us-east-1.amazonaws.com, *.s3.amazonaws.com, cloudfront.net, r2.cloudflarestorage.com
- Azure: blob.core.windows.net, dev.azure.com, *.azurewebsites.net, *.file.core.windows.net, *.dfs.core.windows.net, sharepoint.com, onedrive.live.com
- GCP: storage.googleapis.com, storage.cloud.google.com, *.appspot.com, googleapis.com, drive.google.com, docs.google.com
- Others: digitaloceanspaces.com, wasabisys.com, linodeobjects.com, aliyuncs.com, supabase.co, firebaseio.com, dropbox.com/s, box.com/s

NAMING & CONTENT PATTERNS:
- Bucket/space names: %[1]s-backup, %[1]s-assets, %[1]s-files, %[1]s-uploads, %[1]s-dev, %[1]s-prod, %[1]s-staging, %[1]s-media, %[1]s-public, %[1]s-private.
- Credentials/secrets: aws_access_key_id, secret_access_key, azure_storage_account, sas token, gcp storage key, access_token.
- Combine with filetype:json, filetype:xml, filetype:conf, filetype:env, filetype:log, filetype:txt when useful.
- Index browsing: intitle:"index of" with a single provider host.

EXAMPLE STRUCTURES (one provider per dork):
site:%[1]s (intext:s3.amazonaws.com OR intext:"bucket") (filetype:json OR filetype:xml)
"%[1]s" site:s3.amazonaws.com intitle:"index of" ("%[1]s-backup" OR "%[1]s-prod")
"%[1]s" site:cloudfront.net (filetype:json OR filetype:txt) intext:access_key
"%[1]s" site:blob.core.windows.net (filetype:json OR filetype:xml) intext:sas
"%[1]s" site:dev.azure.com intext:token filetype:txt
"%[1]s" site:sharepoint.com inurl:/Shared%20Documents filetype:pdf
"%[1]s" site:onedrive.live.com intext:"/download" filetype:docx
"%[1]s" site:storage.googleapis.com (filetype:json OR filetype:xml) intitle:"index of"
"%[1]s" site:googleapis.com intext:"service account" filetype:json
"%[1]s" site:digitaloceanspaces.com intext:"%[1]s-dev"
"%[1]s" site:r2.cloudflarestorage.com intitle:"index of" (filetype:json OR filetype:txt)
"%[1]s" site:wasabisys.com intext:"access_key"
"%[1]s" site:linodeobjects.com intext:"secret"
"%[1]s" site:aliyuncs.com intext:oss
"%[1]s" site:supabase.co intext:"service_role"
"%[1]s" site:firebaseio.com intext:"apiKey"
"%[1]s" site:box.com/s intext:"internal"
"%[1]s" site:dropbox.com/s intext:"confidential"

Generate these dorks now, keeping them varied, creative, and non-repetitive.%[3]s`, target, quantity, ignoreContext)

	default:
		// Unknown focus - treat as keyword/category search
		focusedInstructions = fmt.Sprintf(`%s

FOCUS: %s

Generate creative dorks related to "%s" for site:%s. Be intelligent about what patterns, file types, URL structures, and content would be relevant for discovering assets or vulnerabilities related to this focus area.

Use combinations of:
- Relevant inurl: patterns
- Related filetype: extensions
- Associated intitle: and intext: content
- Appropriate URL parameters%s

Generate EXACTLY %d diverse dorks focused on %s. Output only the dorks, nothing else.`, baseRules, focus, focus, target, ignoreContext, quantity, focus)
	}

	return focusedInstructions
}

// appendDorksToIgnoreFile appends new dorks to the ignore file
func appendDorksToIgnoreFile(filename string, dorks []string) error {
	// Read existing dorks
	existing := make(map[string]struct{})
	if fileExists(filename) {
		lines, err := readLines(filename)
		if err != nil {
			return err
		}
		for _, line := range lines {
			existing[strings.TrimSpace(line)] = struct{}{}
		}
	}

	// Open file for appending
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	defer writer.Flush()

	// Append only new dorks
	count := 0
	for _, dork := range dorks {
		dork = strings.TrimSpace(dork)
		if _, exists := existing[dork]; !exists {
			writer.WriteString(dork + "\n")
			count++
		}
	}

	return nil
}

// formatMarkdownToText converts markdown to colored terminal output
func formatMarkdownToText(markdown string) string {
	// ANSI color codes
	const (
		reset   = "\033[0m"
		bold    = "\033[1m"
		cyan    = "\033[36m"
		yellow  = "\033[33m"
		green   = "\033[32m"
		blue    = "\033[34m"
		magenta = "\033[35m"
	)

	lines := strings.Split(markdown, "\n")
	var formatted strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines
		if trimmed == "" {
			formatted.WriteString("\n")
			continue
		}

		// H3 headers (###)
		if strings.HasPrefix(trimmed, "### ") {
			text := strings.TrimPrefix(trimmed, "### ")
			formatted.WriteString(fmt.Sprintf("%s%s%s%s\n", bold, cyan, text, reset))
			continue
		}

		// H2 headers (##)
		if strings.HasPrefix(trimmed, "## ") {
			text := strings.TrimPrefix(trimmed, "## ")
			formatted.WriteString(fmt.Sprintf("%s%s%s%s\n", bold, yellow, text, reset))
			continue
		}

		// H1 headers (#)
		if strings.HasPrefix(trimmed, "# ") {
			text := strings.TrimPrefix(trimmed, "# ")
			formatted.WriteString(fmt.Sprintf("%s%s%s%s\n", bold, magenta, text, reset))
			continue
		}

		// Bold text (**text**)
		processedLine := trimmed
		boldRegex := regexp.MustCompile(`\*\*([^*]+)\*\*`)
		processedLine = boldRegex.ReplaceAllString(processedLine, bold+"$1"+reset)

		// Bullet points with *
		if strings.HasPrefix(processedLine, "*   ") || strings.HasPrefix(processedLine, "* ") {
			processedLine = strings.TrimPrefix(processedLine, "*   ")
			processedLine = strings.TrimPrefix(processedLine, "* ")
			formatted.WriteString(fmt.Sprintf("  %s•%s %s\n", green, reset, processedLine))
			continue
		}

		// Bullet points with -
		if strings.HasPrefix(processedLine, "-   ") || strings.HasPrefix(processedLine, "- ") {
			processedLine = strings.TrimPrefix(processedLine, "-   ")
			processedLine = strings.TrimPrefix(processedLine, "- ")
			formatted.WriteString(fmt.Sprintf("  %s•%s %s\n", green, reset, processedLine))
			continue
		}

		// Numbered lists
		numberedRegex := regexp.MustCompile(`^(\d+)\.\s+(.+)$`)
		if matches := numberedRegex.FindStringSubmatch(processedLine); len(matches) > 0 {
			formatted.WriteString(fmt.Sprintf("  %s%s.%s %s\n", blue, matches[1], reset, matches[2]))
			continue
		}

		// Code blocks (```)
		if strings.HasPrefix(trimmed, "```") {
			continue // Skip code block markers
		}

		// Regular text
		formatted.WriteString(fmt.Sprintf("%s\n", processedLine))
	}

	return formatted.String()
}
