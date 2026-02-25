package interactive

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"banshee/internal/app/console"

	"golang.org/x/term"
)

// saveSensitiveDocument saves a sensitive document to the tracking file
// File location: ~/.config/banshee/sensitive-pdfs.txt
func saveSensitiveDocument(url, summary, details string) error {
	// Get home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Join(home, ".config", "banshee")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Open tracking file in append mode
	trackingFile := filepath.Join(configDir, "sensitive-pdfs.txt")
	f, err := os.OpenFile(trackingFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open tracking file: %v", err)
	}
	defer f.Close()

	// Format: timestamp | URL | summary | details
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] %s\n  Summary: %s\n  Details: %s\n\n", timestamp, url, summary, details)

	// Write to file
	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write to tracking file: %v", err)
	}

	// Sync to ensure data is persisted to disk
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync tracking file: %v", err)
	}

	return nil
}

// saveSuccessfulURL saves a successful URL with finding context to successful.txt
// This enables AI to learn from successful patterns across different targets
// File location: ~/.config/banshee/successful.txt
// Format: URL (Finding type: description)
func saveSuccessfulURL(url, findingType, description string) error {
	// Get home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Join(home, ".config", "banshee")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Open successful.txt in append mode
	successfulFile := filepath.Join(configDir, "successful.txt")
	f, err := os.OpenFile(successfulFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open successful.txt: %v", err)
	}
	defer f.Close()

	// Format: URL (Finding type: description)
	// Example: https://example.com:8443/login.php (AWS keys: Found AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)
	var entry string
	if description != "" {
		entry = fmt.Sprintf("%s (%s: %s)\n", url, findingType, description)
	} else {
		entry = fmt.Sprintf("%s (%s)\n", url, findingType)
	}

	// Write to file
	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write to successful.txt: %v", err)
	}

	// Sync to ensure data is persisted to disk (critical for AI learning)
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync successful.txt: %v", err)
	}

	return nil
}

// getRandomBeautifulColor returns a random beautiful ANSI color code
func getRandomBeautifulColor() string {
	beautifulColors := []string{
		"\033[38;5;87m",  // Bright cyan
		"\033[38;5;213m", // Light magenta
		"\033[38;5;120m", // Light green
		"\033[38;5;228m", // Soft yellow
		"\033[38;5;75m",  // Sky blue
		"\033[38;5;208m", // Orange
		"\033[38;5;147m", // Light purple
		"\033[38;5;117m", // Light blue
		"\033[38;5;219m", // Pink
		"\033[38;5;156m", // Mint green
		"\033[38;5;222m", // Peach
		"\033[38;5;141m", // Lavender
	}
	// No need for rand.Seed - global generator is auto-seeded in Go 1.20+
	return beautifulColors[rand.Intn(len(beautifulColors))]
}

// disableInput disables terminal echo and canonical mode to prevent user input
func disableInput() (*term.State, error) {
	// Save the current terminal state
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	return oldState, nil
}

// enableInput restores terminal to normal input mode
func enableInput(oldState *term.State) error {
	if oldState == nil {
		return nil
	}
	return term.Restore(int(os.Stdin.Fd()), oldState)
}

// renderMarkdown renders full markdown to terminal with ANSI codes
func renderMarkdown(text string) string {
	// Store code blocks to protect them from other transformations
	codeBlocks := make(map[string]string)
	codeBlockCounter := 0

	// Code blocks: ```language\ncode``` (must be processed first)
	codeBlockRegex := regexp.MustCompile("(?s)```([\\w]*)\\n?(.+?)```")
	text = codeBlockRegex.ReplaceAllStringFunc(text, func(match string) string {
		parts := codeBlockRegex.FindStringSubmatch(match)
		if len(parts) >= 3 {
			language := parts[1]
			code := strings.TrimSpace(parts[2])

			// Format code block with subtle styling
			var formatted string
			if language != "" {
				formatted = fmt.Sprintf("\n%s┌─ %s ─%s\n%s%s%s\n%s└───%s\n",
					console.ColorGray, language, console.ColorReset,
					console.ColorCyan, code, console.ColorReset,
					console.ColorGray, console.ColorReset)
			} else {
				formatted = fmt.Sprintf("\n%s%s%s\n", console.ColorCyan, code, console.ColorReset)
			}

			placeholder := fmt.Sprintf("{{CODEBLOCK_%d}}", codeBlockCounter)
			codeBlocks[placeholder] = formatted
			codeBlockCounter++
			return placeholder
		}
		return match
	})

	// Inline code: `code`
	inlineCodeRegex := regexp.MustCompile("`([^`]+?)`")
	text = inlineCodeRegex.ReplaceAllStringFunc(text, func(match string) string {
		code := strings.Trim(match, "`")
		return fmt.Sprintf("%s%s%s", console.ColorCyan, code, console.ColorReset)
	})

	// Links: [text](url) - simplified to just show link text
	linkRegex := regexp.MustCompile(`\[([^\]]+)\]\(([^\)]+)\)`)
	text = linkRegex.ReplaceAllString(text, "$1")

	// Headers: # Header (multiple levels)
	headerRegex := regexp.MustCompile(`(?m)^(#{1,6})\s+(.+)$`)
	text = headerRegex.ReplaceAllStringFunc(text, func(match string) string {
		parts := headerRegex.FindStringSubmatch(match)
		if len(parts) >= 3 {
			level := len(parts[1])
			headerText := parts[2]
			if level == 1 {
				// Level 1: Bold with underline
				underlineLen := visibleLength(headerText)
				return fmt.Sprintf("\n%s%s%s\n%s%s%s", console.ColorBoldWhite, headerText, console.ColorReset, console.ColorGray, strings.Repeat("─", underlineLen), console.ColorReset)
			} else if level == 2 {
				// Level 2: Bold
				return fmt.Sprintf("\n%s%s%s", console.ColorBoldWhite, headerText, console.ColorReset)
			} else {
				// Level 3+: Just bold, no extra spacing
				return fmt.Sprintf("%s%s%s", console.ColorBoldWhite, headerText, console.ColorReset)
			}
		}
		return match
	})

	// Bold text: **text** or __text__
	boldRegex := regexp.MustCompile(`\*\*(.+?)\*\*|__(.+?)__`)
	text = boldRegex.ReplaceAllString(text, "\033[1m$1$2\033[0m")

	// Italic text: *text* or _text_ (but not in URLs or already processed)
	italicRegexStar := regexp.MustCompile(`\*([^*\n]+?)\*`)
	text = italicRegexStar.ReplaceAllString(text, "\033[3m$1\033[0m")

	italicRegexUnderscore := regexp.MustCompile(`_([^_\n]+?)_`)
	text = italicRegexUnderscore.ReplaceAllString(text, "\033[3m$1\033[0m")

	// Numbered lists: 1. item
	numberedListRegex := regexp.MustCompile(`(?m)^\s*(\d+)\.\s+(.+)$`)
	text = numberedListRegex.ReplaceAllString(text, "  $1. $2")

	// Bullet points: - item or * item or • item
	bulletRegex := regexp.MustCompile(`(?m)^[\s]*[-\*•]\s+(.+)$`)
	text = bulletRegex.ReplaceAllString(text, "  • $1")

	// Horizontal rules: --- or ***
	hrRegex := regexp.MustCompile(`(?m)^(\*\*\*|---|___)\s*$`)
	text = hrRegex.ReplaceAllString(text, strings.Repeat("─", 75))

	// Blockquotes: > text
	blockquoteRegex := regexp.MustCompile(`(?m)^>\s+(.+)$`)
	text = blockquoteRegex.ReplaceAllString(text, "  │ $1")

	// Restore code blocks
	for placeholder, code := range codeBlocks {
		text = strings.ReplaceAll(text, placeholder, code)
	}

	return text
}

// launchInteractiveMode launches an interactive TUI for querying and learning about Banshee
// displayCybersecurityNews fetches and displays the latest cybersecurity news using AI
func (c *Config) displayCybersecurityNews() {
	// Check if gemini-cli is available
	if err := checkGeminiCLI(); err != nil {
		console.Logv(c.Verbose, "[NEWS] gemini-cli not available: %v", err)
		return // Silently skip if gemini-cli is not available
	}

	fmt.Printf("%s\n╭─ Latest Cybersecurity News%s\n", console.ColorGray, console.ColorReset)

	// Rotate through varied questions to improve freshness
	questions := []string{
		"Top 3 CVEs disclosed in the past 6 days.",
		"The most interesting 5 cybersecurity news items in the past 7 days.",
		"Top 3 exploited-in-the-wild vulnerabilities this week.",
		"5 notable breaches or ransomware events in the last 7 days.",
		"3 urgent patch advisories security teams should act on this week.",
	}
	rand.Seed(time.Now().UnixNano())
	question := questions[rand.Intn(len(questions))]

	// Create AI prompt for getting latest cybersecurity news
	systemPrompt := `You are a cybersecurity news analyst with access to the latest cybersecurity news. Provide a concise summary of the most recent and important cybersecurity news.

CRITICAL OUTPUT RULES:
1. Output ONLY 3-4 bullet points
2. Each bullet point should be one line (max 80 characters)
3. Focus on: Critical vulnerabilities, Major breaches, Zero-days, Important security updates
4. NO explanations, NO extra text, NO formatting beyond bullet points
5. Start each line with a dash (-)
6. If you don't have access to real-time news, provide recent high-impact security topics

	Example format:
	- Microsoft patches critical RCE in Exchange Server (CVE-2024-XXXX)
	- Ransomware group hits major healthcare provider, 10M records stolen
	- Chrome zero-day exploited in the wild, update to v120 immediately
	- New critical vulnerability in Log4j successor discovered

	Generate EXACTLY 3-4 concise, high-impact cybersecurity news items.`

	userPrompt := fmt.Sprintf("%s\nQuestion: %s\nOutput 3-4 one-line bullets.", "What are the latest and most critical cybersecurity news, vulnerabilities, or security incidents from the last 7 days?", question)

	// Execute AI generation with spinner
	var output string
	var err error
	done := make(chan struct{})

	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

			output, err = c.callGeminiCLI(ctx, systemPrompt, userPrompt)
			if err != nil {
				console.Logv(c.Verbose, "[NEWS] Primary fetch failed, retrying with simplified prompt: %v", err)
				simplePrompt := "Give me 4 concise bullet points of the latest cybersecurity news (breaches, CVEs, zero-days) from the last 7 days. One line each, no markdown."
				output, err = c.callGeminiCLI(ctx, "You are a cybersecurity news summarizer. Output 4 dash-led bullets, one per line.", simplePrompt)
				if err != nil {
					// Final fallback: static topical reminders to avoid empty output
					console.Logv(c.Verbose, "[NEWS] Error fetching news: %v", err)
					fallback := []string{
						"Chrome/Edge emergency updates ship often—apply latest zero-day fixes quickly.",
						"Ransomware targeting healthcare/municipal networks—patch VPN/edge appliances.",
						"Microsoft Patch Tuesday: prioritize recent Exchange/Office/Windows critical RCEs.",
						"Monitor OpenSSL/Apache/Nginx point releases for fresh CVE drops this week.",
					}
					output = strings.Join(fallback, "\n")
					err = nil
				}
			}
		}()

	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	// Prime first spinner frame immediately
	initialSpinner := console.ColorizeSpinner(spinner[spinIdx%len(spinner)])
	fmt.Printf("%s│%s  %s Fetching latest news...%s", console.ColorGray, console.ColorReset, initialSpinner, console.ColorReset)
	spinIdx++

loop:
	for {
		select {
		case <-done:
			fmt.Print("\r\033[K")
			break loop
		case <-ticker.C:
			spinnerChar := console.ColorizeSpinner(spinner[spinIdx%len(spinner)])
			fmt.Printf("\r%s│%s  %s Fetching latest news...%s", console.ColorGray, console.ColorReset, spinnerChar, console.ColorReset)
			spinIdx++
		}
	}

	if err != nil {
		fmt.Printf("%s│%s  %s-%s Unable to fetch news (AI service unavailable; ensure gemini-cli works)\n", console.ColorGray, console.ColorReset, console.ColorGray, console.ColorReset)
		fmt.Printf("%s╰───────────────────────────────────────────────────────────────────────────%s\n\n", console.ColorGray, console.ColorReset)
		return
	}

	news := strings.TrimSpace(output)
	if news == "" {
		fmt.Printf("%s│%s  %s-%s No recent news available\n", console.ColorGray, console.ColorReset, console.ColorGray, console.ColorReset)
		fmt.Printf("%s╰───────────────────────────────────────────────────────────────────────────%s\n\n", console.ColorGray, console.ColorReset)
		return
	}

	// Parse and display news items
	lines := strings.Split(news, "\n")
	newsCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Remove leading dash/bullet if present
		line = strings.TrimPrefix(line, "-")
		line = strings.TrimPrefix(line, "•")
		line = strings.TrimSpace(line)
		if line != "" {
			fmt.Printf("%s│%s  %s-%s %s\n", console.ColorGray, console.ColorReset, console.ColorCyan, console.ColorReset, line)
			newsCount++
			if newsCount >= 4 {
				break
			}
		}
	}

	if newsCount == 0 {
		fmt.Printf("%s│%s  %s-%s No recent news available\n", console.ColorGray, console.ColorReset, console.ColorGray, console.ColorReset)
	}

	fmt.Printf("%s╰───────────────────────────────────────────────────────────────────────────%s\n\n", console.ColorGray, console.ColorReset)
}

// printInteractiveBanner renders a clean, borderless interactive banner with centered tagline
func printInteractiveBanner() {
	lines := []string{
		"  ██████╗  █████╗ ███╗   ██╗███████╗██╗  ██╗███████╗███████╗     █████╗ ██╗",
		"  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝    ██╔══██╗██║",
		"  ██████╔╝███████║██╔██╗ ██║███████╗███████║█████╗  █████╗      ███████║██║",
		"  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══██║██╔══╝  ██╔══╝      ██╔══██║██║",
		"  ██████╔╝██║  ██║██║ ╚████║███████║██║  ██║███████╗███████╗    ██║  ██║██║",
		"  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝╚═╝",
	}

	tagline := "INTERACTIVE MODE - AI-Powered OSINT"

	maxWidth := len([]rune(tagline))
	for _, l := range lines {
		if w := len([]rune(l)); w > maxWidth {
			maxWidth = w
		}
	}

	center := func(text string) string {
		pad := maxWidth - len([]rune(text))
		if pad <= 0 {
			return text
		}
		left := pad / 2
		right := pad - left
		return strings.Repeat(" ", left) + text + strings.Repeat(" ", right)
	}

	fmt.Println()
	for _, l := range lines {
		fmt.Printf("%s%s%s\n", console.ColorRed, center(l), console.ColorReset)
	}
	fmt.Printf("\n%s%s%s\n\n", console.ColorBoldWhite, center(tagline), console.ColorReset)
}

func (c *Config) launchInteractiveMode() error {
	// Get current time for greeting
	hour := time.Now().Hour()
	var greeting string
	switch {
	case hour >= 5 && hour < 12:
		greeting = "Good morning"
	case hour >= 12 && hour < 17:
		greeting = "Good afternoon"
	case hour >= 17 && hour < 21:
		greeting = "Good evening"
	default:
		greeting = "Good night"
	}

	// Get username
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows fallback
	}
	if username == "" {
		username = "operator"
	}

	// Get IP address (prefer external, fallback to local)
	ip := getPublicIP()
	if ip == "" {
		ip = getLocalIP()
	}
	if ip == "" {
		ip = "unknown"
	}

	// Get current time
	currentTime := time.Now().Format("15:04:05")

	// Matrix-style prompts (randomly selected)
	matrixPrompts := []string{
		"What would you like to find in the matrix?",
		"Which rabbit hole shall we explore today?",
		"What secrets are you hunting?",
		"Ready to dive into the digital abyss?",
		"What vulnerabilities shall we uncover?",
		"Time to exploit the search engines?",
		"What intel are you seeking, operator?",
		"Which target shall we dork today?",
		"Ready to unleash the AI recon beast?",
		"What would you like to extract from the web?",
	}
	randomPrompt := matrixPrompts[time.Now().UnixNano()%int64(len(matrixPrompts))]

	// Clear screen and display banner
	fmt.Print("\033[H\033[2J") // Clear screen
	fmt.Println()
	printInteractiveBanner()

	// Info bar with creative stats
	sessionID := fmt.Sprintf("SID-%d", time.Now().Unix()%10000)
	systemStatus := "READY"

	fmt.Printf("%s%s, %s%s %s| IP: %s%s%s | Time: %s%s%s | Session: %s%s%s | Status: %s%s%s\n",
		console.ColorYellow, greeting, console.ColorBoldWhite, username, console.ColorReset,
		console.ColorCyan, ip, console.ColorReset,
		console.ColorGreen, currentTime, console.ColorReset,
		console.ColorMagenta, sessionID, console.ColorReset,
		console.ColorGreen, systemStatus, console.ColorReset)

	// Fetch and display latest cybersecurity news
	c.displayCybersecurityNews()

	// Instructions - Generate random quick commands
	quickCommands := c.generateRandomQuickCommands()

	fmt.Printf("%s╭─ Quick Commands%s\n", console.ColorGray, console.ColorReset)
	for _, cmd := range quickCommands {
		fmt.Printf("%s│%s  %s\n", console.ColorGray, console.ColorReset, cmd)
	}
	fmt.Printf("%s│%s\n", console.ColorGray, console.ColorReset)
	fmt.Printf("%s│%s  %sTalk to me:%s Find assets, search for leaks, generate dorks, ask questions, etc.\n", console.ColorGray, console.ColorReset, console.ColorYellow, console.ColorReset)
	fmt.Printf("%s│%s  %sExamples:%s\n", console.ColorGray, console.ColorReset, console.ColorYellow, console.ColorReset)
	fmt.Printf("%s│%s    • find leaked credentials for example.com\n", console.ColorGray, console.ColorReset)
	fmt.Printf("%s│%s    • search for sensitive files on dell.com\n", console.ColorGray, console.ColorReset)
	fmt.Printf("%s│%s    • how to find admin panels with google dorks?\n", console.ColorGray, console.ColorReset)
	fmt.Printf("%s╰───────────────────────────────────────────────────────────────────────────%s\n", console.ColorGray, console.ColorReset)
	fmt.Println()

	// Main interactive loop
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s%s%s %s❯%s ", console.ColorMagenta, randomPrompt, console.ColorReset, console.ColorGreen, console.ColorReset)
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println()
				return nil
			}
			return fmt.Errorf("failed to read input: %v", err)
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Handle commands
		switch {
		case input == "/exit" || input == "/quit" || input == "exit" || input == "quit":
			fmt.Printf("\n%s[✓]%s Exiting interactive mode. Happy hunting!\n\n", console.ColorGreen, console.ColorReset)
			return nil

		case input == "/execute":
			c.handleExecuteCommand(reader)

		case input == "/help":
			c.showInteractiveHelp()

		case strings.HasPrefix(input, "/monitor"):
			payload := strings.TrimSpace(strings.TrimPrefix(input, "/monitor"))
			if payload == "" {
				fmt.Printf("\n%s[*]%s Usage: /monitor \"intent\" example.com\n\n", console.ColorCyan, console.ColorReset)
				continue
			}
			c.handleNaturalLanguage("monitor " + payload)

		case input == "/ask" || strings.HasPrefix(input, "/ask "):
			// Handle /ask command for AI questions
			query := strings.TrimSpace(strings.TrimPrefix(input, "/ask"))
			if query == "" {
				fmt.Printf("\n%s[*]%s Ask me anything about Google dorking, Banshee, or OSINT!\n", console.ColorCyan, console.ColorReset)
				fmt.Printf("%s[i]%s Examples:\n", console.ColorCyan, console.ColorReset)

				// Get random examples
				examples := c.getRandomAskExamples()
				for _, example := range examples {
					fmt.Printf("  • %s\n", example)
				}
				fmt.Println()
				continue
			}
			c.askAI(query)

		case strings.HasPrefix(input, "/research "), strings.HasPrefix(input, "/dork "), strings.HasPrefix(input, "/smart "),
			strings.HasPrefix(input, "/intel "), strings.HasPrefix(input, "/leaks "), strings.HasPrefix(input, "/analyze "):
			fmt.Printf("%s[!]%s This command is handled via /execute or chat. Ask \"how to use <mode> mode\" for examples.\n\n", console.ColorRed, console.ColorReset)

		default:
			lowerInput := strings.ToLower(input)
			if strings.Contains(lowerInput, "how") && strings.Contains(lowerInput, "mode") {
				if _, err := exec.LookPath("gemini-cli"); err == nil {
					c.askAI(input)
				} else if c.handleModeQuestion(input) {
					break
				}
				break
			}
			// Treat all free-form input as an AI question/assistant prompt
			c.askAI(input)
		}

		fmt.Println() // Add spacing between interactions
	}
}

// showInteractiveHelp displays help information in the interactive mode
func (c *Config) showInteractiveHelp() {
	fmt.Println()
	fmt.Printf("%s╔═══════════════════════════════════════════════════════════════════════════╗%s\n", console.ColorCyan, console.ColorReset)
	fmt.Printf("%s║                         INTERACTIVE MODE - HELP                           ║%s\n", console.ColorCyan, console.ColorReset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════════════════╝%s\n", console.ColorCyan, console.ColorReset)
	fmt.Println()

	fmt.Printf("%s▸ QUICK COMMANDS:%s\n\n", console.ColorBoldWhite, console.ColorReset)

	fmt.Printf("  %s/execute%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Interactive mode - Execute ANY Banshee feature\n")
	fmt.Printf("    Prompts: \"What would you like to do?\"\n")
	fmt.Printf("    Examples:\n")
	fmt.Printf("      • Find sensitive files on example.com\n")
	fmt.Printf("      • Search for leaked credentials for example.com\n")
	fmt.Printf("      • Generate random XSS dorks for example.com\n\n")

	fmt.Printf("  %s/help%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Display this detailed help message\n\n")

	fmt.Printf("  %s/ask [question]%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Ask AI about Google dorking, Banshee features, or OSINT techniques\n")
	fmt.Printf("    Examples:\n")
	fmt.Printf("      %s/ask How to find admin panels with Google dorks?%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("      %s/ask What are the best operators for finding APIs?%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("      %s/ask Explain smart mode vs research mode%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/research <domain>%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Launch OSINT research mode on a target domain\n")
	fmt.Printf("    Executes: echo <domain> | banshee --research -v\n")
	fmt.Printf("    Example: %s/research example.com%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/dork <query>%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Execute a custom Google dork\n")
	fmt.Printf("    Executes: echo <domain> | banshee -q \"your dork\"\n")
	fmt.Printf("    Example: %s/dork site:example.com filetype:pdf%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/smart <domain>%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Use smart mode for context-aware dorking with AI optimization\n")
	fmt.Printf("    Executes: echo <domain> | banshee --smart -ai \"prompt\" -v\n")
	fmt.Printf("    Example: %s/smart example.com%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/leaks <domain|file>%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Search paste sites for leaked credentials and sensitive data\n")
	fmt.Printf("    Executes: banshee -check-leaks <target> -v\n")
	fmt.Printf("    Examples:\n")
	fmt.Printf("      %s/leaks example.com%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("      %s/leaks /path/to/domains.txt%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/analyze <domain>%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Analyze documents for sensitive information (credentials, PII, API keys)\n")
	fmt.Printf("    Executes: echo <domain> | banshee --analyze-docs -v\n")
	fmt.Printf("    Example: %s/analyze example.com%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/monitor <intent> <domain>%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    Monitor targets on a schedule with AI-generated dorks\n")
	fmt.Printf("    Executes: echo <domain> | banshee --monitor \"intent\" -learn -smart -quantity 5\n")
	fmt.Printf("    Example: %s/monitor \"sensitive pdf\" example.com%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/intel <domain>%s\n", console.ColorGreen, console.ColorReset)
	fmt.Printf("    View learned intelligence for a target (requires --learn mode)\n")
	fmt.Printf("    Shows: successful dorks, patterns, tech stack, endpoints\n")
	fmt.Printf("    Example: %s/intel example.com%s\n\n", console.ColorYellow, console.ColorReset)

	fmt.Printf("  %s/exit%s or %s/quit%s\n", console.ColorGreen, console.ColorReset, console.ColorGreen, console.ColorReset)
	fmt.Printf("    Exit interactive mode\n\n")

	fmt.Printf("%s▸ NATURAL LANGUAGE COMMANDS:%s\n\n", console.ColorBoldWhite, console.ColorReset)
	fmt.Printf("  You can talk to Banshee naturally! Examples:\n\n")

	fmt.Printf("  %s\"find sensitive files on dell.com\"%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    → Searches for sensitive files using smart mode\n\n")

	fmt.Printf("  %s\"search for leaked credentials for example.com\"%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    → Checks paste sites for leaked data\n\n")

	fmt.Printf("  %s\"analyze documents on example.com\"%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    → Scans PDFs/DOCX for sensitive information\n\n")

	fmt.Printf("  %s\"monitor for new pdfs on example.com\"%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    → Starts monitor mode for recent documents\n\n")

	fmt.Printf("  %s\"run OSINT research on example.com\"%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    → Launches full reconnaissance mode\n\n")

	fmt.Printf("  %s\"generate random XSS dorks for example.com\"%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    → Creates random XSS-focused Google dorks\n\n")

	fmt.Printf("  %s\"find API endpoints on example.com\"%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    → Uses smart mode to discover API endpoints\n\n")

	fmt.Printf("%s▸ AI ASSISTANT:%s\n\n", console.ColorBoldWhite, console.ColorReset)
	fmt.Printf("  Ask me anything about:\n")
	fmt.Printf("    • Google dorking techniques and operators\n")
	fmt.Printf("    • How to use Banshee flags and features\n")
	fmt.Printf("    • OSINT research strategies\n")
	fmt.Printf("    • Smart mode and AI enhancements\n")
	fmt.Printf("    • Document analysis and leak detection\n")
	fmt.Printf("    • Paste site monitoring and credential searches\n\n")

	fmt.Printf("  %sQuestion Examples:%s\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("    \"How to use smart mode and explain what it does?\"\n")
	fmt.Printf("    \"What are the best Google dork operators for finding APIs?\"\n")
	fmt.Printf("    \"How do I search for exposed configuration files?\"\n")
	fmt.Printf("    \"Explain the difference between --research and --smart\"\n")
	fmt.Printf("    \"How to check for leaked credentials on paste sites?\"\n\n")

	fmt.Printf("%s▸ ASSET SEARCH CAPABILITIES:%s\n\n", console.ColorBoldWhite, console.ColorReset)
	fmt.Printf("  Banshee can help you find ANY type of asset on ANY domain:\n")
	fmt.Printf("    • Sensitive files (PDFs, XLSX, DOCX, config files)\n")
	fmt.Printf("    • API endpoints and documentation\n")
	fmt.Printf("    • Subdomains and infrastructure\n")
	fmt.Printf("    • Leaked credentials on paste sites\n")
	fmt.Printf("    • Exposed databases and backups\n")
	fmt.Printf("    • Admin panels and login pages\n")
	fmt.Printf("    • Cloud storage buckets (S3, Azure, GCP)\n")
	fmt.Printf("    • Source code and git repositories\n\n")

	fmt.Printf("%s▸ TIPS:%s\n\n", console.ColorBoldWhite, console.ColorReset)
	fmt.Printf("  • Pipe multiple domains via stdin: cat domains.txt | banshee --smart\n")
	fmt.Printf("  • Use --learn to build intelligence profiles over time\n")
	fmt.Printf("  • Combine --smart with --research for maximum effectiveness\n")
	fmt.Printf("  • Leak checking searches 15+ paste sites without domain filtering\n")
	fmt.Printf("  • Natural language processing makes commands intuitive and easy\n\n")
}

// askAI sends a query to the AI for assistance with tool usage or Google dorking
func (c *Config) askAI(query string) {
	// Disable terminal input while AI is thinking
	oldState, err := disableInput()
	if err != nil {
		// If we can't disable input, just continue (non-fatal)
		fmt.Printf("\r\n%s[AI]%s Thinking...\r\n\r\n", console.ColorMagenta, console.ColorReset)
	} else {
		fmt.Printf("\r\n%s[AI]%s Thinking...\r\n\r\n", console.ColorMagenta, console.ColorReset)
	}

	// Get the actual help output for accurate responses
	helpOutput := getBansheeHelp()

	// Get the Banshee config for additional context
	configOutput := getBansheeConfig()

	// Prepare context-aware prompt for the AI
	contextPrompt := fmt.Sprintf(`You are Banshee AI, an expert assistant for the Banshee OSINT tool - an advanced Google dorking and reconnaissance platform.

IMPORTANT: Before answering ANY question about Banshee usage, flags, or features, you MUST refer to the ACTUAL help output and config below. DO NOT make assumptions about flag usage or syntax.

=== BANSHEE HELP OUTPUT (AUTHORITATIVE REFERENCE) ===
%s
=== END HELP OUTPUT ===

=== BANSHEE CONFIG FILE (USER'S DEFAULT SETTINGS) ===
%s
=== END CONFIG ===

User question: %s

Instructions:
1. FIRST: Study the help output above for the EXACT flag syntax and usage
2. SECOND: Review the config file to understand the user's default settings and tool structure
3. THIRD: Provide accurate examples using the CORRECT syntax from the help output
4. DO NOT invent flag usage or syntax that doesn't match the help output
5. When suggesting commands, use ADVANCED flags like: -learn, -adaptive, -deep, -smart, -correlation, --analyze-docs, --no-followup, -quantity, -research, -research-depth, etc.
6. If the user asks "how to find X", provide POWERFUL commands with multiple advanced flags combined
7. Prefer echo piping style for AI prompt mode: echo domain.com | ./banshee -v -ai "prompt" -learn -adaptive -deep -smart
8. For modes that generate their own queries (e.g., --monitor, --random, -q/--query), DO NOT add -ai; use the mode's flags instead

Provide a helpful, concise response about:
- Google dorking techniques, operators, and strategies
- Banshee tool usage, flags, and features (USE HELP OUTPUT FOR ACCURACY)
- OSINT research methodologies
- Wayback Machine foresee mode (--foresee flag) - AI studies architecture to forecast vulnerabilities and generate creative dorks
- Smart mode features (context-aware dork chaining, AI optimization, follow-up generation)
- Document analysis and sensitive data detection
- Leak checking on paste sites
- Continuous learning mode and intelligence gathering
- Advanced AI features: correlation, pattern detection, WAF bypass, tech detection
- Any security/penetration testing concepts related to the query

Keep your response practical, actionable, and under 15 lines. Use technical terminology but remain accessible.
ALWAYS provide ADVANCED command examples with multiple flags, not basic ones.`, helpOutput, configOutput, query)

	// Check if gemini-cli is available
	if _, err := exec.LookPath("gemini-cli"); err != nil {
		// Re-enable input before returning
		if oldState != nil {
			enableInput(oldState)
		}

		fmt.Printf("%s[!]%s AI assistant requires gemini-cli to be installed and configured.\n", console.ColorRed, console.ColorReset)
		fmt.Printf("%s[i]%s Install: https://github.com/reorx/gemini-cli\n", console.ColorCyan, console.ColorReset)
		fmt.Printf("%s[i]%s Configure API key: ~/.config/banshee/gemini-api-key.txt\n", console.ColorCyan, console.ColorReset)

		// Provide basic fallback responses for common queries
		c.provideFallbackResponse(query)
		return
	}

	// Call gemini-cli for AI response
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var args []string

	if c.AiModel != "" {

		args = []string{"--model", c.AiModel}

	} else {

		args = []string{}

	}

	cmd := exec.CommandContext(ctx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(contextPrompt)
	cmd.Env = os.Environ()

	output, err := cmd.Output()

	// Re-enable input BEFORE displaying the response
	if oldState != nil {
		enableInput(oldState)
	}

	if err != nil {
		fmt.Printf("%s[!]%s AI query failed: %v\n", console.ColorRed, console.ColorReset, err)
		fmt.Printf("%s[i]%s Make sure gemini-cli is properly configured\n", console.ColorCyan, console.ColorReset)
		c.provideFallbackResponse(query)
		return
	}

	response := strings.TrimSpace(string(output))
	if response == "" {
		fmt.Printf("%s[!]%s Empty AI response\n", console.ColorRed, console.ColorReset)
		c.provideFallbackResponse(query)
		return
	}

	// Render markdown in response
	response = renderMarkdown(response)

	// Get random beautiful color for the response box
	boxColor := getRandomBeautifulColor()

	// Display AI response with formatting
	fmt.Printf("%s╭─ AI Response ─────────────────────────────────────────────────────────────\n%s", boxColor, console.ColorReset)

	// Display the response with proper wrapping and box formatting
	displayInBox(response, 75)

	fmt.Printf("%s╰───────────────────────────────────────────────────────────────────────────%s\n", boxColor, console.ColorReset)
}

// provideFallbackResponse provides basic responses when AI is unavailable
func (c *Config) provideFallbackResponse(query string) {
	queryLower := strings.ToLower(query)

	// Get random beautiful color for the response box
	boxColor := getRandomBeautifulColor()

	fmt.Printf("%s╭─ Quick Answer ────────────────────────────────────────────────────────────\n", boxColor)

	switch {
	case strings.Contains(queryLower, "smart mode") || strings.Contains(queryLower, "--smart"):
		fmt.Printf("│ Smart mode (--smart) enables context-aware dork chaining with AI\n")
		fmt.Printf("│ optimization. It analyzes results, generates follow-up dorks, and\n")
		fmt.Printf("│ suggests improvements. Use with --suggestions to see optimizations.\n")
		fmt.Printf("│\n")
		fmt.Printf("│ Example: echo example.com | banshee --smart --verbose\n")

	case strings.Contains(queryLower, "research") || strings.Contains(queryLower, "--research"):
		fmt.Printf("│ Research mode (--research) performs OSINT on target companies,\n")
		fmt.Printf("│ generating specialized dorks based on industry, tech stack, and\n")
		fmt.Printf("│ patterns. Use --research-depth (1-4) to control thoroughness.\n")
		fmt.Printf("│\n")
		fmt.Printf("│ Example: echo example.com | banshee --research --research-depth 3\n")

	case strings.Contains(queryLower, "dork") && (strings.Contains(queryLower, "operator") || strings.Contains(queryLower, "find")):
		fmt.Printf("│ Common Google dork operators:\n")
		fmt.Printf("│ • site: - Search specific domain (site:example.com)\n")
		fmt.Printf("│ • filetype: - Find specific files (filetype:pdf)\n")
		fmt.Printf("│ • inurl: - URL contains term (inurl:admin)\n")
		fmt.Printf("│ • intitle: - Page title contains (intitle:\"index of\")\n")
		fmt.Printf("│ • intext: - Page content contains (intext:password)\n")

	case strings.Contains(queryLower, "analyze") || strings.Contains(queryLower, "document"):
		fmt.Printf("│ Document analysis (--analyze-docs) uses AI to scan PDFs, DOCX, PPTX\n")
		fmt.Printf("│ for sensitive information: credentials, API keys, PII, internal IPs.\n")
		fmt.Printf("│ Use --filter-docs to skip non-sensitive docs (manuals, guides).\n")
		fmt.Printf("│\n")
		fmt.Printf("│ Example: echo example.com | banshee --analyze-docs --filter-docs -v\n")

	case strings.Contains(queryLower, "multiple") || strings.Contains(queryLower, "batch") || strings.Contains(queryLower, "mass"):
		fmt.Printf("│ ALL Banshee flags support multiple domain scanning:\n")
		fmt.Printf("│ • Pipe domains via stdin: cat domains.txt | banshee --research\n")
		fmt.Printf("│\n")
		fmt.Printf("│ Works with --smart, --research, --tech-detect, and all other modes.\n")

	case strings.Contains(queryLower, "wayback") || strings.Contains(queryLower, "foresee") || strings.Contains(queryLower, "--foresee"):
		fmt.Printf("│ Wayback Machine foresee mode (--foresee) uses AI to study target\n")
		fmt.Printf("│ architecture from Wayback historical data. AI analyzes URL patterns,\n")
		fmt.Printf("│ tech stack, naming conventions to understand WHERE vulnerabilities\n")
		fmt.Printf("│ might exist. Generates CREATIVE dorks that infer similar patterns\n")
		fmt.Printf("│ (not copy exact URLs) to forecast target architecture.\n")
		fmt.Printf("│\n")
		fmt.Printf("│ Compatible with: -x, -smart, -learn, -deep, -include-dates, -a, --research, --tech-detect, --multi-lang\n")
		fmt.Printf("│ NOT compatible with: -q (use --ai prompt instead), --check-leaks (searches pastebin sites)\n")
		fmt.Printf("│\n")
		fmt.Printf("│ Example: echo example.com | banshee --foresee --ai \"find XSS\" -v\n")
		fmt.Printf("│ Example: echo example.com | banshee --foresee -x www,pdf --smart\n")

	default:
		fmt.Printf("│ For detailed help, use: banshee -h\n")
		fmt.Printf("│ Or try asking more specific questions like:\n")
		fmt.Printf("│  • \"How to use smart mode?\"\n")
		fmt.Printf("│  • \"What are Google dork operators?\"\n")
		fmt.Printf("│  • \"How to analyze documents for sensitive data?\"\n")
	}

	fmt.Printf("╰───────────────────────────────────────────────────────────────────────────%s\n", console.ColorReset)
}

// stripANSI removes ANSI escape codes from a string for length calculation
func stripANSI(s string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

// visibleLength returns the visible length of a string (excluding ANSI codes)
func visibleLength(s string) int {
	return len(stripANSI(s))
}

// wrapLine wraps a single line of text to fit within the specified width
func wrapLine(text string, width int) []string {
	var lines []string
	words := strings.Fields(text)

	if len(words) == 0 {
		return []string{""}
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		// Calculate visible length (excluding ANSI codes)
		visLen := visibleLength(currentLine) + 1 + visibleLength(word)

		if visLen <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

// displayInBox displays text in a box with proper wrapping
func displayInBox(text string, width int) {
	// Split by newlines to preserve paragraph structure
	lines := strings.Split(text, "\n")

	for _, line := range lines {
		// Trim leading/trailing whitespace from each line
		line = strings.TrimSpace(line)

		// Empty line - just print the box border
		if line == "" {
			fmt.Printf("│\n")
			continue
		}

		// Check if this is a code block border (don't wrap)
		if strings.Contains(line, "┌─") || strings.Contains(line, "└─") {
			fmt.Printf("│ %s\n", line)
			continue
		}

		// Calculate visible length (excluding ANSI codes)
		visLen := visibleLength(line)

		// If line fits within width, print as-is
		if visLen <= width {
			fmt.Printf("│ %s\n", line)
		} else {
			// Line is too long, wrap it
			wrappedLines := wrapLine(line, width)
			for _, wrappedLine := range wrappedLines {
				fmt.Printf("│ %s\n", wrappedLine)
			}
		}
	}
}

// generateRandomQuickCommands generates a random set of quick commands to display
func (c *Config) generateRandomQuickCommands() []string {
	// All possible quick commands with randomized examples
	allCommands := [][]string{
		{fmt.Sprintf("%s/execute%s    - Execute ANY Banshee feature (interactive prompt)", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/help%s       - Show all available commands with examples", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/ask%s        - Ask AI about Google dorking, Banshee, or OSINT techniques", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/research%s   - OSINT research: echo <domain> | banshee --research -v", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/dork%s       - Custom dorks: banshee -q <query>", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/smart%s      - Smart mode with AI: echo <domain> | banshee --smart -v", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/leaks%s      - Check paste sites: banshee -check-leaks <domain> -v", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/analyze%s    - Find & analyze docs: echo <domain> | banshee -ai \"find sensitive docs\" --analyze-docs", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/intel%s      - View learned intelligence for a target domain", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/subdomain%s  - Discover subdomains: echo <domain> | banshee -s -v", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/tech%s       - Detect technology stack: echo <domain> | banshee --tech-detect -v", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/random%s     - Generate random dorks: echo <domain> | banshee -random <type> -v", console.ColorGreen, console.ColorReset)},
		{fmt.Sprintf("%s/exit%s       - Exit interactive mode", console.ColorGreen, console.ColorReset)},
	}

	// No need to seed - global generator is auto-seeded in Go 1.20+

	// Always include /execute, /help, /ask, and /exit
	selected := []string{
		allCommands[0][0], // /execute
		allCommands[1][0], // /help
		allCommands[2][0], // /ask
	}

	// Randomly select 5 more commands from the rest
	remaining := allCommands[3 : len(allCommands)-1] // Exclude /execute, /help, /ask, and /exit for now
	rand.Shuffle(len(remaining), func(i, j int) {
		remaining[i], remaining[j] = remaining[j], remaining[i]
	})

	for i := 0; i < 5 && i < len(remaining); i++ {
		selected = append(selected, remaining[i][0])
	}

	// Always add /exit at the end
	selected = append(selected, allCommands[len(allCommands)-1][0])

	return selected
}

// getRandomAskExamples returns a random selection of example questions for /ask
func (c *Config) getRandomAskExamples() []string {
	// Comprehensive list of example questions
	allExamples := []string{
		"How to find admin panels with Google dorks?",
		"What are the best dork operators for finding APIs?",
		"Explain the difference between --research and --smart mode",
		"How to search for exposed configuration files?",
		"What's the best way to find database backups?",
		"How to discover subdomains effectively?",
		"What are inurl and intext operators used for?",
		"How can I find exposed API keys?",
		"What's the difference between site: and related: operators?",
		"How to find exposed .env files?",
		"What are the most common sensitive file extensions?",
		"How to search for SQL dumps?",
		"What's the best approach for finding admin login pages?",
		"How to use filetype: operator effectively?",
		"What are some dorks for finding Jenkins instances?",
		"How to find exposed Docker registries?",
		"What's the difference between --analyze-docs and regular scanning?",
		"How to find exposed Git repositories?",
		"What are some dorks for finding cloud storage buckets?",
		"How to search for exposed phpinfo pages?",
		"What's the best way to find directory listings?",
		"How to discover exposed Elasticsearch instances?",
		"What are cache: and info: operators?",
		"How to find exposed Grafana dashboards?",
		"What's the technique for finding vulnerable WordPress sites?",
	}

	// No need to seed - global generator is auto-seeded in Go 1.20+

	// Shuffle the examples
	rand.Shuffle(len(allExamples), func(i, j int) {
		allExamples[i], allExamples[j] = allExamples[j], allExamples[i]
	})

	// Return 4-6 random examples
	numExamples := 4 + rand.Intn(3) // Random number between 4 and 6
	if numExamples > len(allExamples) {
		numExamples = len(allExamples)
	}

	return allExamples[:numExamples]
}

// generateDynamicExamples generates creative Banshee command examples using AI
func (c *Config) generateDynamicExamples() []string {
	// Default examples in case AI is unavailable
	defaultExamples := []string{
		"Find sensitive files on example.com",
		"Search for leaked credentials on paste sites for example.com",
		"Analyze documents for sensitive data on example.com",
		"Generate random XSS dorks for example.com",
		"Run OSINT research on example.com",
		"Find API endpoints on example.com using smart mode",
	}

	// Check if gemini-cli is available
	if _, err := exec.LookPath("gemini-cli"); err != nil {
		return defaultExamples
	}

	// Prepare prompt for AI to generate creative examples
	prompt := `Generate 6 creative and diverse example commands for Banshee OSINT tool.
Each example should showcase different Banshee capabilities.
Use REAL domains like tesla.com, microsoft.com, dell.com, netflix.com, amazon.com, etc. (vary them).
Format: Just list the examples, one per line, as user-friendly descriptions (not command syntax).
Examples should cover: document analysis, leak checking, smart mode, research mode, random dorks, subdomain enumeration, etc.
Be creative and vary the domains and attack vectors.
Output ONLY the 6 examples, nothing else.`

	// Call gemini-cli with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var args []string

	if c.AiModel != "" {

		args = []string{"--model", c.AiModel}

	} else {

		args = []string{}

	}

	cmd := exec.CommandContext(ctx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Env = os.Environ()

	output, err := cmd.Output()
	if err != nil {
		return defaultExamples
	}

	response := strings.TrimSpace(string(output))
	if response == "" {
		return defaultExamples
	}

	// Parse the response into examples
	examples := strings.Split(response, "\n")
	var cleanExamples []string
	for _, example := range examples {
		example = strings.TrimSpace(example)
		// Remove numbering if present (1., 2., etc.)
		example = regexp.MustCompile(`^\d+[\.\)]\s*`).ReplaceAllString(example, "")
		// Remove bullet points if present
		example = strings.TrimPrefix(example, "• ")
		example = strings.TrimPrefix(example, "- ")
		example = strings.TrimPrefix(example, "* ")
		if example != "" && !strings.HasPrefix(example, "#") {
			cleanExamples = append(cleanExamples, example)
		}
	}

	// Return AI examples if we got enough, otherwise use defaults
	if len(cleanExamples) >= 4 {
		return cleanExamples[:6] // Return first 6
	}
	return defaultExamples
}

// handleExecuteCommand provides an interactive prompt for executing any Banshee feature
func (c *Config) handleExecuteCommand(reader *bufio.Reader) {
	// Get random beautiful color for this box
	boxColor := getRandomBeautifulColor()

	fmt.Println()
	fmt.Printf("%s╭─ Execute Mode\n", boxColor)
	fmt.Printf("│  What would you like to do?\n")
	fmt.Printf("│\n")

	// Generate dynamic examples using AI (with loading message)
	fmt.Printf("│  %sLoading examples...%s\n", console.ColorCyan, console.ColorReset)

	// Disable terminal input while loading examples
	oldState, err := disableInput()

	// Discard any buffered input before loading examples
	reader.Reset(os.Stdin)

	examples := c.generateDynamicExamples()

	// Re-enable input before prompting user
	if err == nil && oldState != nil {
		enableInput(oldState)
	}

	// Clear the loading message and redraw
	fmt.Print("\033[F\033[K") // Move up and clear line

	fmt.Printf("│  %sExamples:%s\n", console.ColorYellow, console.ColorReset)
	for _, example := range examples {
		fmt.Printf("│    • %s\n", example)
	}
	fmt.Printf("│\n")
	fmt.Printf("│  Type '%sback%s' to return to main menu\n", console.ColorYellow, console.ColorReset)
	fmt.Printf("╰───────────────────────────────────────────────────────────────────────────%s\n", console.ColorReset)

	// Reset reader again to discard any input typed during loading
	reader.Reset(os.Stdin)

	// Small delay to ensure terminal is ready
	time.Sleep(100 * time.Millisecond)

	fmt.Printf("\n%s❯%s ", console.ColorGreen, console.ColorReset)

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("%s[!]%s Failed to read input: %v\n", console.ColorRed, console.ColorReset, err)
		return
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return
	}

	// Handle back command
	if input == "back" || input == "/back" {
		fmt.Printf("%s[*]%s Returning to main menu...\n\n", console.ColorCyan, console.ColorReset)
		return
	}

	// Process the natural language command
	if !c.handleNaturalLanguage(input) {
		// If natural language processing fails, try AI interpretation
		fmt.Printf("\n%s[*]%s Let me help you build the right command...\n", console.ColorYellow, console.ColorReset)
		c.askAI(input)
	}
}

// shellEscape escapes a string for safe use in shell commands
func shellEscape(s string) string {
	// Use single quotes and escape any single quotes in the string
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// getBansheePath returns the path to the current banshee executable
func getBansheePath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "./banshee"
	}
	return exePath
}

// executeCommand executes a banshee command with the given arguments
func (c *Config) executeCommand(args string) {
	// Parse the arguments
	cmdArgs := strings.Fields(args)
	if len(cmdArgs) == 0 {
		return
	}

	// Execute the command in a subprocess
	cmd := exec.Command(getBansheePath(), cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
	}
	fmt.Println()
}

// executeCommandWithInput executes a banshee command and feeds data to stdin
func (c *Config) executeCommandWithInput(args string, stdinData string) {
	cmdArgs := strings.Fields(args)
	if len(cmdArgs) == 0 {
		return
	}

	cmd := exec.Command(getBansheePath(), cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(stdinData)

	if err := cmd.Run(); err != nil {
		fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
	}
	fmt.Println()
}

// handleModeQuestion answers "how to use <mode> mode" inline without AI
func (c *Config) handleModeQuestion(input string) bool {
	lower := strings.ToLower(strings.TrimSpace(input))
	if !strings.Contains(lower, "how") || !strings.Contains(lower, "mode") {
		return false
	}

	type modeHelp struct {
		keys    []string
		title   string
		summary string
		example string
	}

	modes := []modeHelp{
		{
			keys:    []string{"smart"},
			title:   "SMART mode",
			summary: "Context-aware dork chaining with follow-ups, correlation, and optimization.",
			example: `echo "example.com" | banshee -v --smart -ai "find exposed APIs" -learn -adaptive -deep --correlation --no-followup`,
		},
		{
			keys:    []string{"research"},
			title:   "RESEARCH mode",
			summary: "Performs OSINT research to craft better AI dorks before scanning.",
			example: `echo "example.com" | banshee -v --research --research-depth 2 -ai "discover attack surface" -learn`,
		},
		{
			keys:    []string{"ai"},
			title:   "AI mode",
			summary: "Generates custom dorks from your prompt; combine with learn/tech-detect.",
			example: `echo "example.com" | banshee -v -ai "find exposed dashboards" -learn -adaptive -deep --tech-detect`,
		},
		{
			keys:    []string{"random"},
			title:   "RANDOM mode",
			summary: "Generates random dorks by category (sqli, xss, api, etc.).",
			example: `echo "example.com" | banshee -v --random api --quantity 15 -learn -adaptive`,
		},
		{
			keys:    []string{"monitor", "watch"},
			title:   "MONITOR mode",
			summary: "Continuously monitors targets with intent-based dorks on a schedule (do not use -ai/-random).",
			example: `cat domains.txt | banshee --monitor "sensitive pdf" -learn -smart -quantity 5 -adaptive -deep --no-followup --monitor-time 60`,
		},
		{
			keys:    []string{"learn"},
			title:   "LEARN mode",
			summary: "Continuously stores intelligence to improve future runs.",
			example: `echo "example.com" | banshee -v -ai "find login portals" --smart --learn`,
		},
		{
			keys:    []string{"subdomain", "subdomains", "-s"},
			title:   "SUBDOMAIN mode",
			summary: "AI-powered subdomain discovery with optional deep recursion.",
			example: `echo "example.com" | banshee -v -s -ai "discover subdomains" --learn --deep`,
		},
		{
			keys:    []string{"analyze", "docs", "document"},
			title:   "DOCUMENT ANALYSIS",
			summary: "Find PDFs/DOCX/etc and scan contents for sensitive data.",
			example: `echo "example.com" | banshee -v -ai "find sensitive documents" --smart --analyze-docs --no-followup`,
		},
		{
			keys:    []string{"leak", "paste"},
			title:   "LEAK CHECKING",
			summary: "Search paste sites for leaked credentials or tokens.",
			example: `banshee -v -check-leaks example.com --keywords "api,token,password"`,
		},
	}

	for _, m := range modes {
		for _, k := range m.keys {
			if strings.Contains(lower, k) {
				fmt.Printf("\n%s[%s]%s %s\n", console.ColorCyan, strings.ToUpper(m.title), console.ColorReset, m.summary)
				fmt.Printf("%sExample:%s %s\n\n", console.ColorYellow, console.ColorReset, m.example)
				return true
			}
		}
	}
	return false
}

// handleNaturalLanguage processes natural language commands and executes appropriate Banshee commands
func (c *Config) handleNaturalLanguage(input string) bool {
	inputLower := strings.ToLower(input)

	// Pre-compile all regexes for efficiency
	domainRegex := regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	ipRegex := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	filePathRegex := regexp.MustCompile(`(/[^\s]+|[a-zA-Z0-9_\-./]+\.[a-zA-Z0-9]+)`)
	outputFileRegex := regexp.MustCompile(`(?:save to|output to|write to)\s+([a-zA-Z0-9_\-./]+\.[a-zA-Z0-9]+)`)

	// Extract domain/target from input
	var target string

	// Try domain pattern first
	if match := domainRegex.FindString(input); match != "" {
		target = match
	} else if match := ipRegex.FindString(input); match != "" {
		// Try IP pattern
		target = match
	}

	// File path detection
	if target == "" && strings.Contains(input, "/") && (strings.Contains(input, ".txt") || strings.Contains(input, ".") || strings.Contains(inputLower, "file")) {
		// Extract file path
		if match := filePathRegex.FindString(input); match != "" {
			target = match
		}
	}

	// Detect output file request
	outputFile := ""
	if strings.Contains(inputLower, "save to") || strings.Contains(inputLower, "output to") || strings.Contains(inputLower, "write to") {
		// Extract output filename
		if match := outputFileRegex.FindStringSubmatch(inputLower); len(match) > 1 {
			outputFile = match[1]
		}
	}

	// Detect proxy configuration (e.g., "send to burp 127.0.0.1:8080", "use proxy localhost:8080")
	proxy := ""
	proxyRegex := regexp.MustCompile(`(?:proxy|burp|through|via)\s+(?:(?:https?|socks5)://)?([a-zA-Z0-9.-]+):(\d+)`)
	if match := proxyRegex.FindStringSubmatch(inputLower); len(match) > 2 {
		host := match[1]
		port := match[2]
		// Default to http:// if no protocol specified
		if strings.Contains(inputLower, "socks") {
			proxy = fmt.Sprintf("socks5://%s:%s", host, port)
		} else {
			proxy = fmt.Sprintf("http://%s:%s", host, port)
		}
	}

	// Extract quantity if specified (e.g., "generate 20 dorks", "find 50 results", "20 dorks")
	quantity := 0
	quantityRegex := regexp.MustCompile(`(?:generate|find|use|create)?\s*(\d+)\s+(?:dork|result|item|amount)`)
	if match := quantityRegex.FindStringSubmatch(inputLower); len(match) > 1 {
		if num, err := strconv.Atoi(match[1]); err == nil {
			quantity = num
		}
	}

	// View intelligence/statistics
	if strings.Contains(inputLower, "statistic") || strings.Contains(inputLower, "intelligence") ||
		strings.Contains(inputLower, "view intel") || strings.Contains(inputLower, "show stats") ||
		strings.Contains(inputLower, "show intel") || strings.Contains(inputLower, "view stats") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: show statistics of example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}
		cmd := fmt.Sprintf("--view-intel %s", target)
		fmt.Printf("\n%s[*]%s Viewing intelligence for: %s%s%s\n\n", console.ColorYellow, console.ColorReset, console.ColorCyan, target, console.ColorReset)
		fmt.Printf("%s[i]%s Did you mean: %sbanshee --view-intel %s%s\n\n", console.ColorCyan, console.ColorReset, console.ColorGreen, target, console.ColorReset)
		c.executeCommand(cmd)
		return true
	}

	// Monitor mode
	if strings.Contains(inputLower, "monitor") || strings.Contains(inputLower, "watch") || strings.Contains(inputLower, "tracking") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain or file path\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: monitor for new pdfs on example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}

		intent := inputLower
		if target != "" {
			intent = strings.ReplaceAll(intent, strings.ToLower(target), "")
		}
		intent = regexp.MustCompile(`(?i)\b(monitor|watch|tracking|track|for|on|in|of|please)\b`).ReplaceAllString(intent, " ")
		intent = strings.TrimSpace(intent)
		intent = strings.Trim(intent, "\"'")
		if intent == "" {
			intent = "all"
		}

		qty := quantity
		if qty <= 0 {
			qty = c.AiQuantity
		}
		if qty <= 0 {
			qty = 5
		}

		cmd := fmt.Sprintf("--monitor %s -learn -smart -quantity %d -adaptive -deep --no-followup", shellEscape(intent), qty)
		if proxy != "" {
			cmd += fmt.Sprintf(" -proxy %s", shellEscape(proxy))
		}
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", shellEscape(outputFile))
		}

		fmt.Printf("\n%s[*]%s Starting monitor mode: %s%s%s\n\n", console.ColorYellow, console.ColorReset, console.ColorCyan, intent, console.ColorReset)
		fmt.Printf("%s[i]%s Executing: banshee %s\n\n", console.ColorCyan, console.ColorReset, cmd)

		if fileExists(target) {
			lines, err := readLines(target)
			if err != nil {
				fmt.Printf("%s[!]%s Failed to read targets file: %v\n", console.ColorRed, console.ColorReset, err)
				return true
			}
			c.executeCommandWithInput(cmd, strings.Join(lines, "\n"))
			return true
		}

		c.executeCommandWithInput(cmd, target+"\n")
		return true
	}

	// Leak/paste site checking
	if strings.Contains(inputLower, "leak") || strings.Contains(inputLower, "paste") || strings.Contains(inputLower, "credential") || strings.Contains(inputLower, "pastebin") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain or file path\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: find leaked credentials for example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}
		cmd := fmt.Sprintf("-check-leaks %s -v", target)
		if proxy != "" {
			cmd += fmt.Sprintf(" -proxy %s", shellEscape(proxy))
			fmt.Printf("%s[i]%s Using Proxy: %s\n", console.ColorCyan, console.ColorReset, proxy)
		}
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", outputFile)
		}
		fmt.Printf("\n%s[*]%s Searching paste sites for leaks: %s%s%s\n\n", console.ColorYellow, console.ColorReset, console.ColorCyan, target, console.ColorReset)
		fmt.Printf("%s[i]%s Executing: banshee %s\n\n", console.ColorCyan, console.ColorReset, cmd)
		c.executeCommand(cmd)
		return true
	}

	// Document analysis
	if (strings.Contains(inputLower, "analyze") || strings.Contains(inputLower, "document") || strings.Contains(inputLower, "sensitive") || strings.Contains(inputLower, "pdf") || strings.Contains(inputLower, "docx")) && !strings.Contains(inputLower, "how") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: analyze documents on example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}

		// Build advanced command with AI and smart features
		searchPrompt := "find sensitive documents and files"
		cmd := fmt.Sprintf("echo %s | %s -v -ai %s -learn -quantity 5 -adaptive -deep -smart --no-followup --analyze-docs",
			shellEscape(target), shellEscape(getBansheePath()), shellEscape(searchPrompt))
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", shellEscape(outputFile))
		}

		fmt.Printf("\n%s[*]%s Analyzing documents for: %s%s%s\n\n", console.ColorYellow, console.ColorReset, console.ColorCyan, target, console.ColorReset)
		fmt.Printf("%s[i]%s Executing: echo %s | banshee -v -ai \"%s\" -learn -quantity 5 -adaptive -deep -smart --no-followup --analyze-docs\n\n",
			console.ColorCyan, console.ColorReset, target, searchPrompt)

		// Execute via shell to handle piping
		shellCmd := exec.Command("sh", "-c", cmd)
		shellCmd.Stdout = os.Stdout
		shellCmd.Stderr = os.Stderr
		shellCmd.Stdin = os.Stdin
		if err := shellCmd.Run(); err != nil {
			fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
		}
		fmt.Println()
		return true
	}

	// Smart mode searches
	if strings.Contains(inputLower, "smart") || (strings.Contains(inputLower, "find") && (strings.Contains(inputLower, "api") || strings.Contains(inputLower, "endpoint"))) {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: find API endpoints on example.com using smart mode\n", console.ColorCyan, console.ColorReset)
			fmt.Printf("%s[i]%s With quantity: generate 15 dorks and find API endpoints on example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}

		// Extract what to search for
		searchFor := "API endpoints and sensitive files"
		if strings.Contains(inputLower, "admin") {
			searchFor = "admin panels and login pages"
		} else if strings.Contains(inputLower, "config") {
			searchFor = "configuration files and sensitive data"
		} else if strings.Contains(inputLower, "backup") {
			searchFor = "backup files and archives"
		} else if strings.Contains(inputLower, "document") || strings.Contains(inputLower, "pdf") {
			searchFor = "sensitive documents and files"
		}

		// Use specified quantity or default
		if quantity == 0 {
			quantity = 8
		}

		// Build advanced command with full smart mode features
		cmd := fmt.Sprintf("echo %s | %s -v -ai %s -learn -quantity %d -adaptive -deep -smart -correlation --max-followup 5",
			shellEscape(target), shellEscape(getBansheePath()), shellEscape(searchFor), quantity)
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", shellEscape(outputFile))
		}

		fmt.Printf("\n%s[*]%s Running smart mode search for %s on: %s%s%s\n\n", console.ColorYellow, console.ColorReset, searchFor, console.ColorCyan, target, console.ColorReset)
		fmt.Printf("%s[i]%s Executing: echo %s | banshee -v -ai \"%s\" -learn -quantity %d -adaptive -deep -smart -correlation --max-followup 5\n\n",
			console.ColorCyan, console.ColorReset, target, searchFor, quantity)

		// Execute via shell to handle piping
		shellCmd := exec.Command("sh", "-c", cmd)
		shellCmd.Stdout = os.Stdout
		shellCmd.Stderr = os.Stderr
		shellCmd.Stdin = os.Stdin
		if err := shellCmd.Run(); err != nil {
			fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
		}
		fmt.Println()
		return true
	}

	// Research mode
	if strings.Contains(inputLower, "research") || strings.Contains(inputLower, "osint") || strings.Contains(inputLower, "reconnaissance") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: run OSINT research on example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}

		// Determine research depth
		depth := "2"
		if strings.Contains(inputLower, "deep") || strings.Contains(inputLower, "comprehensive") {
			depth = "3"
		} else if strings.Contains(inputLower, "basic") {
			depth = "1"
		}

		// Use specified quantity or default
		if quantity == 0 {
			quantity = 12
		}

		// Build advanced research command with AI and learning
		cmd := fmt.Sprintf("echo %s | %s -v -random any -research -research-depth %s -learn -quantity %d -adaptive -deep -smart",
			shellEscape(target), shellEscape(getBansheePath()), depth, quantity)
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", shellEscape(outputFile))
		}

		fmt.Printf("\n%s[*]%s Running OSINT research (depth %s) on: %s%s%s\n\n", console.ColorYellow, console.ColorReset, depth, console.ColorCyan, target, console.ColorReset)
		fmt.Printf("%s[i]%s Executing: echo %s | banshee -v -random any -research -research-depth %s -learn -quantity %d -adaptive -deep -smart\n\n",
			console.ColorCyan, console.ColorReset, target, depth, quantity)

		// Execute via shell to handle piping
		shellCmd := exec.Command("sh", "-c", cmd)
		shellCmd.Stdout = os.Stdout
		shellCmd.Stderr = os.Stderr
		shellCmd.Stdin = os.Stdin
		if err := shellCmd.Run(); err != nil {
			fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
		}
		fmt.Println()
		return true
	}

	// Random dorks
	if strings.Contains(inputLower, "random") || (strings.Contains(inputLower, "generate") && strings.Contains(inputLower, "dork")) {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: generate random XSS dorks for example.com\n", console.ColorCyan, console.ColorReset)
			fmt.Printf("%s[i]%s Or with quantity: generate 20 dorks for example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}

		// Detect dork type
		dorkType := "any"
		if strings.Contains(inputLower, "xss") {
			dorkType = "xss"
		} else if strings.Contains(inputLower, "sqli") || strings.Contains(inputLower, "sql") {
			dorkType = "sqli"
		} else if strings.Contains(inputLower, "lfi") {
			dorkType = "lfi"
		} else if strings.Contains(inputLower, "rce") {
			dorkType = "rce"
		} else if strings.Contains(inputLower, "api") {
			dorkType = "api"
		} else if strings.Contains(inputLower, "cloud") {
			dorkType = "cloud"
		}

		// Use specified quantity or default
		if quantity == 0 {
			quantity = 10
		}

		// Build advanced random dork command with learning
		cmd := fmt.Sprintf("echo %s | %s -v -random %s -learn -quantity %d -adaptive -deep -smart --no-followup",
			shellEscape(target), shellEscape(getBansheePath()), dorkType, quantity)
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", shellEscape(outputFile))
		}

		fmt.Printf("\n%s[*]%s Generating %d random %s dorks for: %s%s%s\n\n", console.ColorYellow, console.ColorReset, quantity, dorkType, console.ColorCyan, target, console.ColorReset)
		fmt.Printf("%s[i]%s Executing: echo %s | banshee -v -random %s -learn -quantity %d -adaptive -deep -smart --no-followup\n\n",
			console.ColorCyan, console.ColorReset, target, dorkType, quantity)

		// Execute via shell to handle piping
		shellCmd := exec.Command("sh", "-c", cmd)
		shellCmd.Stdout = os.Stdout
		shellCmd.Stderr = os.Stderr
		shellCmd.Stdin = os.Stdin
		if err := shellCmd.Run(); err != nil {
			fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
		}
		fmt.Println()
		return true
	}

	// Generic file/asset search
	if strings.Contains(inputLower, "find") || strings.Contains(inputLower, "search") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: find sensitive files on example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}

		// Extract what to search for
		searchFor := "sensitive files and exposed data"
		if strings.Contains(inputLower, "file") {
			searchFor = "sensitive files and documents"
		} else if strings.Contains(inputLower, "asset") {
			searchFor = "assets and resources"
		} else if strings.Contains(inputLower, "subdomain") {
			searchFor = "subdomains"
		} else if strings.Contains(inputLower, "admin") {
			searchFor = "admin panels and login pages"
		} else if strings.Contains(inputLower, "backup") {
			searchFor = "backup files and archives"
		}

		fmt.Printf("\n%s[*]%s Searching for %s on: %s%s%s\n\n", console.ColorYellow, console.ColorReset, searchFor, console.ColorCyan, target, console.ColorReset)

		// Use smart mode with advanced features for better results
		if strings.Contains(inputLower, "subdomain") {
			// Enhanced subdomain enumeration
			cmd := fmt.Sprintf("echo %s | ./banshee -v -s -learn -adaptive -deep", target)
			if outputFile != "" {
				cmd += fmt.Sprintf(" -o %s", outputFile)
			}
			fmt.Printf("%s[i]%s Executing: %s\n\n", console.ColorCyan, console.ColorReset, cmd)

			shellCmd := exec.Command("sh", "-c", cmd)
			shellCmd.Stdout = os.Stdout
			shellCmd.Stderr = os.Stderr
			shellCmd.Stdin = os.Stdin
			if err := shellCmd.Run(); err != nil {
				fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
			}
			fmt.Println()
		} else {
			// Use specified quantity or default
			searchQuantity := quantity
			if searchQuantity == 0 {
				searchQuantity = 8
			}

			// Enhanced smart mode search
			cmd := fmt.Sprintf("echo %s | ./banshee -v -ai \"%s\" -learn -quantity %d -adaptive -deep -smart -correlation --max-followup 5", target, searchFor, searchQuantity)
			if outputFile != "" {
				cmd += fmt.Sprintf(" -o %s", outputFile)
			}
			fmt.Printf("%s[i]%s Executing: %s\n\n", console.ColorCyan, console.ColorReset, cmd)

			shellCmd := exec.Command("sh", "-c", cmd)
			shellCmd.Stdout = os.Stdout
			shellCmd.Stderr = os.Stderr
			shellCmd.Stdin = os.Stdin
			if err := shellCmd.Run(); err != nil {
				fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
			}
			fmt.Println()
		}
		return true
	}

	// Technology detection
	if strings.Contains(inputLower, "tech") || strings.Contains(inputLower, "technology") || strings.Contains(inputLower, "stack") || strings.Contains(inputLower, "detect tech") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: detect technology stack on example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}
		cmd := "--tech-detect -v"
		if proxy != "" {
			cmd += fmt.Sprintf(" -proxy %s", proxy)
		}
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", outputFile)
		}
		displayCmd := fmt.Sprintf("echo %s | banshee --tech-detect -v", target)
		if proxy != "" {
			displayCmd += fmt.Sprintf(" -proxy %s", proxy)
		}
		fmt.Printf("\n%s[*]%s Detecting technology stack for: %s%s%s\n\n", console.ColorYellow, console.ColorReset, console.ColorCyan, target, console.ColorReset)
		if proxy != "" {
			fmt.Printf("%s[i]%s Using Proxy: %s\n", console.ColorCyan, console.ColorReset, proxy)
		}
		fmt.Printf("%s[i]%s Did you mean: %s%s%s\n\n", console.ColorCyan, console.ColorReset, console.ColorGreen, displayCmd, console.ColorReset)
		c.executeCommandWithInput(cmd, target+"\n")
		return true
	}

	// Subdomain enumeration (enhanced)
	if strings.Contains(inputLower, "subdomain") || strings.Contains(inputLower, "enumerate subdomain") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: find subdomains of example.com\n", console.ColorCyan, console.ColorReset)
			fmt.Printf("%s[i]%s With Proxy: find subdomains for example.com and send to burp 127.0.0.1:8080\n", console.ColorCyan, console.ColorReset)
			return true
		}
		cmd := fmt.Sprintf("echo %s | %s -v -s -learn -adaptive -deep", shellEscape(target), shellEscape(getBansheePath()))
		if proxy != "" {
			cmd += fmt.Sprintf(" -proxy %s", shellEscape(proxy))
			fmt.Printf("%s[i]%s Using Proxy: %s (results will be sent through this proxy)\n", console.ColorCyan, console.ColorReset, proxy)
		}
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", shellEscape(outputFile))
		}
		fmt.Printf("\n%s[*]%s Enumerating subdomains for: %s%s%s\n\n", console.ColorYellow, console.ColorReset, console.ColorCyan, target, console.ColorReset)

		displayCmd := fmt.Sprintf("echo %s | banshee -v -s -learn", target)
		if proxy != "" {
			displayCmd += fmt.Sprintf(" -proxy %s", proxy)
		}
		fmt.Printf("%s[i]%s Did you mean: %s%s%s\n\n", console.ColorCyan, console.ColorReset, console.ColorGreen, displayCmd, console.ColorReset)

		shellCmd := exec.Command("sh", "-c", cmd)
		shellCmd.Stdout = os.Stdout
		shellCmd.Stderr = os.Stderr
		shellCmd.Stdin = os.Stdin
		if err := shellCmd.Run(); err != nil {
			fmt.Printf("\n%s[!]%s Command failed: %v\n", console.ColorRed, console.ColorReset, err)
		}
		fmt.Println()
		return true
	}

	// WAF bypass mode
	if strings.Contains(inputLower, "waf") || strings.Contains(inputLower, "bypass") || strings.Contains(inputLower, "firewall") {
		if target == "" {
			fmt.Printf("%s[!]%s Please specify a domain\n", console.ColorRed, console.ColorReset)
			fmt.Printf("%s[i]%s Example: test WAF bypass on example.com\n", console.ColorCyan, console.ColorReset)
			return true
		}
		cmd := "--waf-bypass -v"
		if proxy != "" {
			cmd += fmt.Sprintf(" -proxy %s", proxy)
		}
		if outputFile != "" {
			cmd += fmt.Sprintf(" -o %s", outputFile)
		}
		displayCmd := fmt.Sprintf("echo %s | banshee --waf-bypass -v", target)
		if proxy != "" {
			displayCmd += fmt.Sprintf(" -proxy %s", proxy)
		}
		fmt.Printf("\n%s[*]%s Testing WAF bypass techniques for: %s%s%s\n\n", console.ColorYellow, console.ColorReset, console.ColorCyan, target, console.ColorReset)
		if proxy != "" {
			fmt.Printf("%s[i]%s Using Proxy: %s\n", console.ColorCyan, console.ColorReset, proxy)
		}
		fmt.Printf("%s[i]%s Did you mean: %s%s%s\n\n", console.ColorCyan, console.ColorReset, console.ColorGreen, displayCmd, console.ColorReset)
		c.executeCommandWithInput(cmd, target+"\n")
		return true
	}

	// CVE database update
	if strings.Contains(inputLower, "update") && (strings.Contains(inputLower, "cve") || strings.Contains(inputLower, "database") || strings.Contains(inputLower, "vulnerability")) {
		fmt.Printf("\n%s[*]%s Updating CVE database...\n\n", console.ColorYellow, console.ColorReset)
		fmt.Printf("%s[i]%s Did you mean: %sbanshee --update-cve-db%s\n\n", console.ColorCyan, console.ColorReset, console.ColorGreen, console.ColorReset)
		c.executeCommand("--update-cve-db")
		return true
	}

	// Custom query
	if strings.Contains(inputLower, "custom query") || strings.Contains(inputLower, "custom dork") {
		fmt.Printf("%s[!]%s Please specify your custom query\n", console.ColorRed, console.ColorReset)
		fmt.Printf("%s[i]%s Example: banshee -q \"site:example.com inurl:admin\"\n", console.ColorCyan, console.ColorReset)
		return true
	}

	return false
}

// getBansheeHelp gets the help output from banshee to provide accurate information to AI
func getBansheeHelp() string {
	candidates := []string{
		getBansheePath(),
		"banshee",
		"./banshee",
	}
	flags := [][]string{{"--help"}, {"-h"}}

	for _, bin := range candidates {
		if strings.TrimSpace(bin) == "" {
			continue
		}
		for _, args := range flags {
			cmd := exec.Command(bin, args...)
			output, _ := cmd.CombinedOutput()
			if len(output) > 0 {
				return stripANSI(string(output))
			}
		}
	}

	return ""
}

// getBansheeConfig reads the Banshee config file to provide AI with configuration context
func getBansheeConfig() string {
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "banshee", ".config")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "Config file not available"
	}

	return string(data)
}

// getPublicIP attempts to get the public IP address
func getPublicIP() string {
	// Try multiple services for reliability
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" && net.ParseIP(ip) != nil {
			return ip
		}
	}

	return ""
}

// getLocalIP gets the local IP address
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}

	return ""
}
