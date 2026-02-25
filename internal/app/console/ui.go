package console

import (
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
)

const (
	Version = "1.37.1"

	// ANSI color codes (optimized for dark backgrounds).
	ColorReset     = "\033[0m"
	ColorRed       = "\033[38;5;204m"
	ColorBlue      = "\033[38;5;117m"
	ColorOrange    = "\033[38;5;215m"
	ColorGreen     = "\033[38;5;114m"
	ColorCyan      = "\033[38;5;122m"
	ColorTeal      = "\033[38;5;44m"
	ColorYellow    = "\033[38;5;222m"
	ColorMagenta   = "\033[38;5;176m"
	ColorBoldWhite = "\033[1;97m"
	ColorGray      = "\033[38;5;248m"
	ColorPurple    = "\033[38;5;183m"
)

var GlobalNoColors bool

func ShowBanner() {
	// ASCII banner;
	fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀")
	fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀")
	fmt.Println("⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⠋⠉⢹⣯⠉⠉⠛⠲⢤⣀⠀⠀⠀⠀⠀⠀")
	fmt.Println("⠀⠀⠀⠀⢀⡴⠋⠀⣣⠤⠒⠒⣺⣿⡒⠒⠢⢤⡃⠉⠳⣄⠀⠀⠀⠀")
	fmt.Println("⢀⡀⠀⣠⠋⠀⡰⠊⠀⠀⢀⣼⠏⠈⢿⣄⠀⠀⠈⠲⡀⠈⢧⡀⠀⣀")
	fmt.Println("⠀⠈⢳⠧⢤⣞⠀⠀⠀⢀⣾⠏⠀⠀⠈⢿⣆⠀⠀⠀⢘⣦⠤⢷⠋⠀")
	fmt.Println("⠀⠀⡾⠤⡼⠈⠛⢦⣤⣾⡏⣠⠶⠲⢦⡈⣿⣦⣤⠞⠋⢹⡤⠼⡇⠀")
	fmt.Println("⠀⠀⡇⠀⠆⠀⠀⢾⣿⣿⢸⡁⣾⣿⠆⣻⢸⣿⢾⠄⠀⠀⠆⠀⡇⠀")
	fmt.Println("⠀⠀⣧⠐⢲⠀⣠⡼⠟⣿⡆⠳⢬⣥⠴⢃⣿⡟⠻⣤⡀⢸⠒⢠⡇⠀")
	fmt.Println("⠀⢀⣸⡤⠞⢏⠁⠀⠀⠘⢿⡄⠀⠀⠀⣼⠟⠀⠀⠀⢙⠟⠦⣼⣀⠀")
	fmt.Println("⠐⠉⠀⠹⡄⠈⠣⡀⠀⠀⠈⢿⣄⢀⣾⠏⠀⠀⠀⡠⠋⢀⡼⠁⠈⠑")
	fmt.Println("⠀⠀⠀⠀⠙⢦⣀⠈⡗⠢⠤⢈⣻⣿⣃⠠⠤⠲⡍⢀⣠⠞⠀⠀⠀⠀")
	fmt.Println("⠀⠀⠀⠀⠀⠀⠈⠛⠦⣄⣀⡀⢸⣏⠀⣀⣀⡤⠞⠋⠀⠀⠀⠀⠀⠀")
	fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⡏⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀")
	fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀")
	fmt.Printf(" Banshee v%s\n - Made by Vulnpire\n\n", Version)
}

// BannerColors represents a color scheme for the banner
type BannerColors struct {
	border   string
	title    string
	subtitle string
	Version  string
	powered  string
	heading  string
	option   string
	value    string
	emoji    string
}

// getBannerColors returns a random color scheme that harmonizes with help menu
// All color schemes use eye-friendly, complementary colors
func getBannerColors() BannerColors {
	schemes := []BannerColors{
		// Ocean Breeze: Cyan/Blue/Green (calming, professional)
		{
			border:   ColorCyan,
			title:    ColorBoldWhite,
			subtitle: ColorBlue,
			Version:  ColorGreen,
			powered:  ColorPurple,
			heading:  ColorBoldWhite,
			option:   ColorCyan,
			value:    ColorGreen,
			emoji:    ColorBlue,
		},
		// Sunset Glow: Purple/Pink/Orange (warm, elegant)
		{
			border:   ColorPurple,
			title:    ColorBoldWhite,
			subtitle: ColorMagenta,
			Version:  ColorOrange,
			powered:  ColorYellow,
			heading:  ColorBoldWhite,
			option:   ColorMagenta,
			value:    ColorOrange,
			emoji:    ColorPurple,
		},
		// Forest Dream: Green/Yellow/Cyan (natural, fresh)
		{
			border:   ColorGreen,
			title:    ColorBoldWhite,
			subtitle: ColorCyan,
			Version:  ColorYellow,
			powered:  ColorBlue,
			heading:  ColorBoldWhite,
			option:   ColorGreen,
			value:    ColorYellow,
			emoji:    ColorCyan,
		},
		// Peach Harmony: Yellow/Orange/Magenta (vibrant, friendly)
		{
			border:   ColorYellow,
			title:    ColorBoldWhite,
			subtitle: ColorOrange,
			Version:  ColorMagenta,
			powered:  ColorPurple,
			heading:  ColorBoldWhite,
			option:   ColorYellow,
			value:    ColorOrange,
			emoji:    ColorMagenta,
		},
		// Lavender Sky: Purple/Blue/Cyan (soothing, modern)
		{
			border:   ColorPurple,
			title:    ColorBoldWhite,
			subtitle: ColorBlue,
			Version:  ColorCyan,
			powered:  ColorGreen,
			heading:  ColorBoldWhite,
			option:   ColorBlue,
			value:    ColorCyan,
			emoji:    ColorPurple,
		},
		// Azure Mist: Blue/Cyan/Green (cool, refreshing)
		{
			border:   ColorBlue,
			title:    ColorBoldWhite,
			subtitle: ColorCyan,
			Version:  ColorGreen,
			powered:  ColorYellow,
			heading:  ColorBoldWhite,
			option:   ColorBlue,
			value:    ColorGreen,
			emoji:    ColorCyan,
		},
	}

	// Use global random generator (auto-seeded in Go 1.20+)
	// No need for rand.Seed as it's deprecated and the global generator is automatically seeded
	return schemes[rand.Intn(len(schemes))]
}

// centerText centers text within a given width, accounting for text length only (not color codes)
func centerText(text string, width int) string {
	textLen := len(text)
	if textLen >= width {
		return text
	}
	padding := (width - textLen) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-textLen-padding)
}

func PrintUsage() {
	// Get random color scheme
	colors := getBannerColors()

	// Banner width (excluding borders)
	bannerWidth := 80

	// Prepare text lines (without color codes for accurate length calculation)
	line1 := "Banshee AI - Advanced OSINT & Dorking Tool"
	line2 := fmt.Sprintf("Version %s - Powered by AI", Version)

	// Print banner with proper centering
	fmt.Printf("\n%s╔════════════════════════════════════════════════════════════════════════════════╗%s\n", colors.border, ColorReset)

	// Line 1: Banshee AI - Advanced OSINT & Dorking Tool
	// Calculate padding based on actual visible text length
	leftPadding1 := (bannerWidth - len(line1)) / 2
	rightPadding1 := bannerWidth - len(line1) - leftPadding1
	fmt.Printf("%s║%s%s%sBanshee AI%s - %sAdvanced OSINT & Dorking Tool%s%s%s║%s\n",
		colors.border, ColorReset,
		strings.Repeat(" ", leftPadding1),
		colors.title, ColorReset,
		colors.subtitle, ColorReset,
		strings.Repeat(" ", rightPadding1),
		colors.border, ColorReset)

	// Line 2: Version - Powered by AI
	// Calculate padding based on actual visible text length
	leftPadding2 := (bannerWidth - len(line2)) / 2
	rightPadding2 := bannerWidth - len(line2) - leftPadding2
	fmt.Printf("%s║%s%sVersion %s%s%s - %sPowered by AI%s%s%s║%s\n",
		colors.border, ColorReset,
		strings.Repeat(" ", leftPadding2),
		colors.Version, Version, ColorReset,
		colors.powered, ColorReset,
		strings.Repeat(" ", rightPadding2),
		colors.border, ColorReset)

	fmt.Printf("%s╚════════════════════════════════════════════════════════════════════════════════╝%s\n\n", colors.border, ColorReset)

	fmt.Printf("%s# USAGE%s\n", colors.heading, ColorReset)
	fmt.Printf("  banshee [%sFLAGS%s] [%sOPTIONS%s]\n\n", colors.option, ColorReset, colors.value, ColorReset)

	fmt.Printf("%s# CORE OPTIONS%s\n", colors.heading, ColorReset)
	fmt.Printf("  %s-h, --help%s                    Display this help message\n", colors.option, ColorReset)
	fmt.Printf("  %s(stdin)%s                     Pipe targets via stdin (cat domains.txt | banshee ...)\n", colors.option, ColorReset)
	fmt.Printf("                               • -q works without stdin for universal search\n")
	fmt.Printf("  %s-p, --pages%s %s<NUM>%s             Number of search result pages [default: 1]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-d, --delay%s %s<SEC>%s             Delay in seconds between requests [default: 1.5]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--workers%s %s<NUM>%s              Number of parallel workers for processing [default: 5]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • Speeds up document analysis & response processing\n")
	fmt.Printf("                               • Recommended: 3-10 workers (based on system resources)\n")
	fmt.Printf("  %s-v, --verbose%s                 Enable verbose output (detailed logging)\n", colors.option, ColorReset)
	fmt.Printf("  %s-o, --output%s %s<FILE>%s           Export results to file (URLs only)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • Always writes unique URLs; skips doc/inline-code/response analysis for URLs already in the file\n\n")

	fmt.Printf("%s# SEARCH OPTIONS%s\n", colors.heading, ColorReset)
	fmt.Printf("  %s-e, --extensions%s %s<EXT>%s       Comma-separated file extensions (pdf,doc,xls)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-w, --word%s %s<WORD>%s            Dictionary/paths/files to search\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-q, --query%s %s<QUERY>%s          Custom dork query or file with queries\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-c, --contents%s %s<TEXT>%s        Search for specific content in files\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-x, --exclusions%s %s<EXC>%s       Exclude targets (www,admin,test)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--oos-file%s %s<FILE>%s           Out-of-scope file (supports wildcards, one per line)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • Default: %s~/.config/banshee/oos.txt%s\n", colors.value, ColorReset)
	fmt.Printf("                               • Compatible with bug bounty scope files\n")
	fmt.Printf("                               • Wildcards: %s*.example.com%s, %scsd-*.domain.com%s\n", colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-a, --recursive%s              Aggressive crawling (includes subdomains)\n", colors.option, ColorReset)
	fmt.Printf("  %s-s, --subdomains%s             Enumerate subdomains\n", colors.option, ColorReset)
	fmt.Printf("  %s--find-apex%s                Resolve apex domains via tenant lookup (expands stdin targets)\n", colors.option, ColorReset)
	fmt.Printf("  %s-engine%s %s<ENGINE>%s            Search Engine: %sboth%s (default), %sgoogle%s, %sbrave%s\n\n", colors.option, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset)

	fmt.Printf("%s# PROXY & NETWORK%s\n", colors.heading, ColorReset)
	fmt.Printf("  %s-r, --proxy%s %s<PROXY>%s         Proxy URL: %shttp://127.0.0.1:8080%s or %ssocks5://user:pass@host:1080%s\n", colors.option, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-insecure%s                    Skip TLS certificate verification (for Burp Suite)\n\n", colors.option, ColorReset)

	fmt.Printf("%s# AI-POWERED FEATURES%s %s✨%s\n", colors.heading, ColorReset, colors.emoji, ColorReset)
	fmt.Printf("  %s-ai%s %s<PROMPT>%s                AI-powered dork generation (requires gemini-cli)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • Can be prompt string or file path (one prompt per line)\n")
	fmt.Printf("                               • Example: %s-ai \"find exposed admin panels\"%s\n", colors.value, ColorReset)
	fmt.Printf("  %s-random%s %s<TYPE>%s              Generate random dorks:\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • %sany%s: Diverse dorks across all categories\n", colors.value, ColorReset)
	fmt.Printf("                               • %ssqli%s, %sxss%s, %sredirect%s, %slfi%s, %srce%s, %sidor%s, %sapi%s, %scloud%s\n", colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-quantity%s %s<NUM>%s             Number of AI/random dorks to generate [1-50, default: 10]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-simplify%s                   Simplify AI prompts (removes filler words)\n", colors.option, ColorReset)
	fmt.Printf("  %s--model%s %s<MODEL>%s             AI model to use (gemini-3-pro-preview, gemini-3-flash-preview)\n\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--multi-lang%s               Generate a portion of dorks in detected target language (uses config: multi-lang-multiplier)\n", colors.option, ColorReset)
	fmt.Printf("  %s--multi-lang-multiplier%s %s<0-100>%s  Percentage of dorks in target language when --multi-lang is enabled (default 25)\n\n", colors.option, ColorReset, colors.value, ColorReset)

	fmt.Printf("%s# MONITOR MODE%s %s🛰️%s\n", colors.heading, ColorReset, colors.emoji, ColorReset)
	fmt.Printf("  %s--monitor%s %s<INTENT>%s         Continuous monitoring with AI-generated dorks\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • Examples: \"sensitive pdf\", \"sqli,xss,redirect\", \"monitor for new docs\"\n")
	fmt.Printf("                               • Intent-driven: \"documents\", \"dashboards\", \"all\" (multi-intent supported)\n")
	fmt.Printf("                               • Not compatible with -ai, -random, -q, or --include-dates\n")
	fmt.Printf("  %s--monitor-time%s %s<MIN>%s        Minutes between monitor cycles [default: 60]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--filter-mon%s                 Dedupe URLs across cycles + filter non-sensitive docs (doc intents)\n", colors.option, ColorReset)
	fmt.Printf("  %s--analyze-mon%s                Analyze monitor results (documents + responses; skips inline code)\n\n", colors.option, ColorReset)

	fmt.Printf("%s# OSINT & RESEARCH%s %s🔍%s\n", colors.heading, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-research%s                   OSINT research mode (reconnaissance + specialized dorks)\n", colors.option, ColorReset)
	fmt.Printf("                               • Must be used with %s-ai%s or %s-random%s\n", colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-research-depth%s %s<1-4>%s      Research depth level [default: 1]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • %s1%s: Basic info, CVEs, tech stack\n", colors.value, ColorReset)
	fmt.Printf("                               • %s2%s: Detailed security posture, infrastructure\n", colors.value, ColorReset)
	fmt.Printf("                               • %s3%s: Comprehensive OSINT, historical analysis\n", colors.value, ColorReset)
	fmt.Printf("                               • %s4%s: Linguistic intelligence (emails, departments)\n", colors.value, ColorReset)
	fmt.Printf("  %s-learn%s                      Continuous learning mode (saves intelligence)\n", colors.option, ColorReset)
	fmt.Printf("                               • Tracks successful/failed dorks per target\n")
	fmt.Printf("                               • Generates progressively better dorks\n")
	fmt.Printf("                               • Intelligence: %s~/.config/banshee/.intel%s\n\n", colors.value, ColorReset)

	fmt.Printf("%s# SMART MODE & AI ENHANCEMENTS%s %s⚡%s\n", colors.heading, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-smart%s                      Context-aware dork chaining and optimization\n", colors.option, ColorReset)
	fmt.Printf("                               • Generates contextual follow-up dorks from discoveries\n")
	fmt.Printf("                               • Post-scan optimization suggestions\n")
	fmt.Printf("  %s--suggestions%s                Show dork optimization suggestions (requires %s--smart%s)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--no-followup%s                Skip follow-up dork generation (requires %s--smart%s)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--max-followup%s %s<NUM>%s        Max follow-up dorks per subdomain [default: 5]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-correlation%s                 Multi-layer correlation analysis (requires %s--smart%s)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-max-correlation%s %s<NUM>%s     Max correlation dorks [default: 10]\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-waf-bypass%s                  Adversarial dork generation with obfuscation\n", colors.option, ColorReset)
	fmt.Printf("  %s-save%s                        Smart pagination (stops on diminishing returns)\n", colors.option, ColorReset)
	fmt.Printf("  %s-include-dates%s               Strategic date operators for targeting\n", colors.option, ColorReset)
	fmt.Printf("  %s-tech-detect%s                 Auto-detect tech stack and generate specialized dorks\n", colors.option, ColorReset)
	fmt.Printf("  %s-adaptive%s                    Adaptive rate limiting based on response patterns\n", colors.option, ColorReset)
	fmt.Printf("  %s-deep%s                        Recursive subdomain discovery (up to 3 levels)\n", colors.option, ColorReset)
	fmt.Printf("  %s-scoring%s                     AI-based result classification and vulnerability scoring\n", colors.option, ColorReset)
	fmt.Printf("  %s-budget%s                      Smart query budget optimization\n\n", colors.option, ColorReset)

	fmt.Printf("%s# SECURITY ANALYSIS%s %s🛡️%s\n", colors.heading, ColorReset, colors.emoji, ColorReset)
	fmt.Printf("  %s--analyze-docs%s               Analyze documents (PDF, DOCX, XLSX) for sensitive info\n", colors.option, ColorReset)
	fmt.Printf("  %s--filter-docs%s                Filter non-sensitive documents (requires %s--analyze-docs%s)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--dedupe%s                     Intelligent deduplication with semantic analysis\n", colors.option, ColorReset)
	fmt.Printf("  %s--analyze-responses%s          AI-powered response analysis (requires %s--dedupe%s)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • Detects: credentials, API keys, PII, dashboards\n")
	fmt.Printf("  %s--analyze-response-only%s      Analyze URL(s) from STDIN without dorking\n", colors.option, ColorReset)
	fmt.Printf("                               • Example: %secho \"https://site.com\" | banshee --analyze-response-only%s\n", colors.value, ColorReset)
	fmt.Printf("  %s--analyze-code-only%s          Analyze CODE from STDIN for vulnerabilities (no dorking)\n", colors.option, ColorReset)
	fmt.Printf("                               • Analyzes JavaScript/code for security issues\n")
	fmt.Printf("                               • Example: %scat script.js | banshee --analyze-code-only%s\n", colors.value, ColorReset)
	fmt.Printf("  %s--inline-code-analysis%s       Extract & analyze inline JavaScript from HTML\n", colors.option, ColorReset)
	fmt.Printf("                               • Detects: DOM-XSS, dangerous sinks, open redirects\n")
	fmt.Printf("                               • Requires AI mode (%s-ai%s, %s-random%s, %s-smart%s, or %s-learn%s)\n", colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s-check-leaks%s                 Check paste sites for leaked credentials\n", colors.option, ColorReset)
	fmt.Printf("  %s-keywords%s %s<KEYWORDS>%s       Keywords for leak checking (comma-separated or file)\n\n", colors.option, ColorReset, colors.value, ColorReset)

	fmt.Printf("%s# WAYBACK MACHINE - AI FORESEE MODE (ARCHITECTURE INTELLIGENCE)%s %s🔮 🤖%s\n", colors.heading, ColorReset, colors.emoji, ColorReset)
	fmt.Printf("  %s--foresee%s                     Enable AI foresee mode: study target architecture and generate creative dorks\n", colors.option, ColorReset)
	fmt.Printf("                               • Discovers historical URLs from Internet Archive (Wayback Machine)\n")
	fmt.Printf("                               • AI studies architecture: URL patterns, tech stack, naming conventions\n")
	fmt.Printf("                               • AI understands WHERE vulnerabilities might exist based on structure\n")
	fmt.Printf("                               • Generates CREATIVE dorks that infer similar patterns (not copy exact URLs)\n")
	fmt.Printf("                               • Forecasts target architecture to find related vulnerabilities\n")
	fmt.Printf("                               • Caches: 24h URLs, 7d intelligence\n")
	fmt.Printf("  %s--wmc%s %s<CODES>%s                Filter by status codes (requires %s--foresee%s)\n", colors.option, ColorReset, colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("                               • Format: %s200%s or %s200,301,404%s | Default: all\n", colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--no-wayback-cache%s           Bypass cache, fetch fresh data (requires %s--foresee%s)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--auto-cleanup-cache%s        Auto-remove cache >30 days (requires %s--foresee%s)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--clear-wayback-cache%s       Clear ALL Wayback cache and exit\n", colors.option, ColorReset)
	fmt.Printf("  %sExamples:%s\n", colors.option, ColorReset)
	fmt.Printf("    %secho domain.com | banshee --foresee --ai \"find XSS\" -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %secho domain.com | banshee --foresee --wmc 200 --no-wayback-cache%s\n", colors.value, ColorReset)
	fmt.Printf("    %secho domain.com | banshee --foresee --ai \"find admin\" --smart --dedupe%s\n", colors.value, ColorReset)
	fmt.Printf("    %sbanshee --clear-wayback-cache%s  # Cleanup command\n\n", colors.value, ColorReset)

	fmt.Printf("%s# CVE DATABASE & MANAGEMENT%s %s🔓%s\n", colors.heading, ColorReset, colors.emoji, ColorReset)
	fmt.Printf("  %s--update-cve-db%s              Update CVE database with exploitable vulnerabilities\n", colors.option, ColorReset)
	fmt.Printf("  %s--cve-year%s %s<YEAR>%s           Filter CVEs by year (e.g., 2024, 2025)\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--severity%s %s<LEVEL>%s          Filter by severity: %scritical%s, %shigh%s, %smedium%s, %slow%s\n", colors.option, ColorReset, colors.value, ColorReset, colors.emoji, ColorReset, ColorOrange, ColorReset, colors.value, ColorReset, colors.option, ColorReset)
	fmt.Printf("  %s--ai-dork-generation%s         Generate AI-powered CVE dorks (requires gemini-cli)\n", colors.option, ColorReset)
	fmt.Printf("  %s--nvd-api-key%s %s<KEY>%s         NVD API key (or save to %s~/.config/banshee/nvd-api-key.txt%s)\n", colors.option, ColorReset, colors.value, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--view-intel%s %s<DOMAIN>%s       View saved intelligence for a domain\n", colors.option, ColorReset, colors.value, ColorReset)
	fmt.Printf("  %s--export-intel%s %s<DOMAIN>%s     Export intelligence to JSON\n\n", colors.option, ColorReset, colors.value, ColorReset)

	fmt.Printf("%s# INTERACTIVE MODE%s %s💬%s\n", colors.heading, ColorReset, colors.emoji, ColorReset)
	fmt.Printf("  %s--interactive%s                Launch interactive TUI with AI assistant\n", colors.option, ColorReset)
	fmt.Printf("                               • Commands: %s/help%s, %s/research%s, %s/dork%s, %s/smart%s, %s/intel%s, %s/exit%s\n\n", colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset, colors.value, ColorReset)

	fmt.Printf("%s# STDIN SUPPORT%s %s📥%s\n", colors.heading, ColorReset, colors.value, ColorReset)
	fmt.Printf("  Pipe domains/URLs via stdin:\n")
	fmt.Printf("    • %secho \"example.com\" | banshee -ai \"find admin\" -v%s\n", colors.value, ColorReset)
	fmt.Printf("    • %scat domains.txt | banshee -random any -quantity 10%s\n", colors.value, ColorReset)
	fmt.Printf("    • %scat domains.txt | banshee --monitor \"sensitive pdf\" -learn -smart -quantity 5%s\n\n", colors.value, ColorReset)
	fmt.Printf("    • %ssubfinder -d example.com | banshee -e pdf,doc%s\n\n", colors.value, ColorReset)

	fmt.Printf("%s# EXAMPLES%s\n", colors.heading, ColorReset)
	fmt.Printf("  %secho \"example.com\" | banshee -e pdf,doc,bak%s\n", colors.value, ColorReset)
	fmt.Printf("  %scat domains.txt | banshee -w login.html,search,redirect,?id= -x admin.example.com%s\n", colors.value, ColorReset)
	fmt.Printf("  %secho \"example.com\" | banshee -ai \"find sensitive docs\" --analyze-docs -v%s\n", colors.value, ColorReset)
	fmt.Printf("  %scat domains.txt | banshee --monitor \"documents\" -learn -smart -quantity 5 -adaptive -deep --no-followup -p 5 -x www%s\n", colors.value, ColorReset)
	fmt.Printf("  %ssubfinder -d example.com | banshee -s -p 10 -d 5 -o banshee-subdomains.txt%s\n", colors.value, ColorReset)
	fmt.Printf("  %sbanshee -q \"intitle:index of\" -p 2%s\n\n", colors.value, ColorReset)

	fmt.Printf("%s# Out-of-Scope Filtering (Bug Bounty Compatible):%s\n", colors.heading, ColorReset)
	fmt.Printf("  Use default OOS file:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -e pdf,doc -v%s\n", colors.value, ColorReset)
	fmt.Printf("    # Automatically filters URLs matching patterns in ~/.config/banshee/oos.txt\n\n")
	fmt.Printf("  Use custom OOS file:\n")
	fmt.Printf("    %scat targets.txt | banshee -random any --oos-file ./bug-bounty-oos.txt -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  OOS file format (supports wildcards):\n")
	fmt.Printf("    %s# Comment lines start with #%s\n", colors.value, ColorReset)
	fmt.Printf("    %s*.out-of-scope.com          # Wildcard subdomain%s\n", colors.value, ColorReset)
	fmt.Printf("    %scsd-*.contentsquare.com     # Wildcard pattern%s\n", colors.value, ColorReset)
	fmt.Printf("    %ssubdomain.example.com        # Exact match%s\n", colors.value, ColorReset)
	fmt.Printf("    %sexample.com/public/*         # Path wildcard%s\n\n", colors.value, ColorReset)

	fmt.Printf("%s# Smart Mode & AI Enhancement Examples:%s\n", colors.heading, ColorReset)
	fmt.Printf("  Basic smart mode (contextual follow-up dorks):\n")
	fmt.Printf("    %secho dell.com | banshee -ai \"find admin dashboards\" -smart -v%s\n", colors.value, ColorReset)
	fmt.Printf("    # Discovers i.dell.com → generates: site:i.dell.com find admin dashboards\n\n")
	fmt.Printf("  With optimization suggestions:\n")
	fmt.Printf("    %secho dell.com | banshee -ai \"find admin\" -smart --suggestions -v%s\n", colors.value, ColorReset)
	fmt.Printf("    # Shows [MUTATE], [MERGE], [SPECIALIZE], [NEW] dork improvements\n\n")
	fmt.Printf("  Skip follow-up dorks:\n")
	fmt.Printf("    %secho dell.com | banshee -ai \"find admin\" -smart --no-followup -v%s\n", colors.value, ColorReset)
	fmt.Printf("    # Only executes original dorks, no follow-ups\n\n")
	fmt.Printf("  Limit follow-up dorks:\n")
	fmt.Printf("    %secho dell.com | banshee -ai \"find admin\" -smart --max-followup 10 -v%s\n", colors.value, ColorReset)
	fmt.Printf("    # Generates max 10 follow-up dorks instead of default 5\n\n")
	fmt.Printf("  Smart mode with correlation:\n")
	fmt.Printf("    %secho dell.com | banshee -ai \"find APIs\" -smart -correlation -v%s\n", colors.value, ColorReset)
	fmt.Printf("    # Cross-correlates discoveries for deeper intelligence\n\n")
	fmt.Printf("  All smart features combined:\n")
	fmt.Printf("    %secho dell.com | banshee -ai \"find admin\" -smart --suggestions --max-followup 3 -correlation -v%s\n\n", colors.value, ColorReset)

	fmt.Printf("%s# Random Dork Generation:%s\n", colors.heading, ColorReset)
	fmt.Printf("  Generate 10 diverse random dorks:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random any -quantity 10 -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Generate SQLi-focused dorks:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random sqli -quantity 5 -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  With ignore file to avoid duplicates:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random any -quantity 15 -ignore-file used-dorks.txt -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Flush mode - ignore previous dorks:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random any -quantity 20 -flush -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Multiple domains:\n")
	fmt.Printf("    %scat domains.txt | banshee -random any -quantity 20 -ignore-file used.txt -o results.txt%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Cloud asset enumeration (S3, Azure, GCP):\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random cloud -quantity 15 -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %secho \"dell.com\" | banshee -random cloud -research -research-depth 2 -v%s\n\n", colors.value, ColorReset)

	fmt.Printf("%s# Universal Search (No Target Domain Filter):%s\n", colors.heading, ColorReset)
	fmt.Printf("  Search without domain restriction (shows ALL results):\n")
	fmt.Printf("    %sbanshee -q 'site:s3.amazonaws.com \"dell\"' -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %sbanshee -q '\"company-backup\" (site:storage.googleapis.com OR site:digitaloceanspaces.com)' -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %sbanshee -q 'site:blob.core.windows.net filetype:xlsx' -o results.txt%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Find cloud assets for any company:\n")
	fmt.Printf("    %sbanshee -q 'site:s3.amazonaws.com inurl:backup' -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %sbanshee -q 'site:storage.googleapis.com \"confidential\"' -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Note: When using -q without piping targets via stdin, ALL matching results are returned (no domain filtering).\n")
	fmt.Printf("        This is useful for cloud enumeration and broad searches.\n\n")

	fmt.Printf("%s# OSINT Research Mode:%s\n", colors.heading, ColorReset)
	fmt.Printf("  Basic research with AI dorks:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -ai \"find vulnerabilities\" -research -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Moderate depth research with random dorks:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random any -research -research-depth 2 -quantity 15 -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Comprehensive research (depth 3):\n")
	fmt.Printf("    %secho \"example.com\" | banshee -ai \"security assessment\" -research -research-depth 3 -quantity 20 -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Research mode with specific vulnerability focus:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random sqli -research -research-depth 2 -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Multiple targets with research mode:\n")
	fmt.Printf("    %scat domains.txt | banshee -random any -research -research-depth 1 -o results.txt -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Note: Research mode performs OSINT on the target company to identify:\n")
	fmt.Printf("    - Known vulnerabilities and CVEs\n")
	fmt.Printf("    - Past security incidents\n")
	fmt.Printf("    - Technology stack and infrastructure\n")
	fmt.Printf("    - Common exposed assets\n")
	fmt.Printf("    - Industry-specific weaknesses\n")
	fmt.Printf("  Then generates highly targeted dorks based on this intelligence.\n\n")

	fmt.Printf("%s# Continuous Learning Mode (-learn):%s\n", colors.heading, ColorReset)
	fmt.Printf("  Enable learning for better dork generation over time:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random any -learn -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %secho \"example.com\" | banshee -ai \"find admin panels\" -learn -quantity 15 -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  AI-powered subdomain enumeration with learning:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -subdomains -learn -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %secho \"example.com\" | banshee -s -learn -quantity 20 -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Research mode with continuous learning:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random sqli -research -learn -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Multiple scans - intelligence improves each time:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -random any -learn -v%s    # First scan - builds intelligence\n", colors.value, ColorReset)
	fmt.Printf("    %secho \"example.com\" | banshee -random any -learn -v%s    # Second scan - uses learned patterns\n", colors.value, ColorReset)
	fmt.Printf("    %secho \"example.com\" | banshee -random any -learn -v%s    # Third scan - even better targeting\n\n", colors.value, ColorReset)
	fmt.Printf("  How it works:\n")
	fmt.Printf("    1. Stores successful/failed dorks in ~/.config/banshee/.intel/<target-hash>.json\n")
	fmt.Printf("    2. Successful dorks also saved to ~/.config/banshee/successful.txt (for --smart mode)\n")
	fmt.Printf("    3. Tracks discovered: subdomains, paths, file types, API endpoints, cloud assets\n")
	fmt.Printf("    4. Analyzes which dork patterns/types work best for this target\n")
	fmt.Printf("    5. Generates NEW dorks using successful patterns as a guide\n")
	fmt.Printf("    6. Each scan produces BETTER, more targeted dorks (not reused ones)\n")
	fmt.Printf("    7. Saves AI quota by focusing on what actually works for this target\n\n")
	fmt.Printf("  Storage Locations:\n")
	fmt.Printf("    • Target Intelligence: ~/.config/banshee/.intel/<target-hash>.json\n")
	fmt.Printf("    • Successful dorks: ~/.config/banshee/successful.txt (analyzed by --smart mode)\n")
	fmt.Printf("    • Wayback cache: ~/.config/banshee/.wayback_cache/<domain_hash>.json\n")
	fmt.Printf("    • Response cache: ~/.config/banshee/.response_cache/<url_hash>.json\n\n")
	fmt.Printf("  What it discovers and learns from:\n")
	fmt.Printf("    - Successful dork patterns (inurl, filetype, intitle, etc.)\n")
	fmt.Printf("    - Discovered subdomains and naming patterns\n")
	fmt.Printf("    - Common paths and directory structures\n")
	fmt.Printf("    - File extensions that exist on the target\n")
	fmt.Printf("    - API endpoints and cloud assets\n")
	fmt.Printf("    - Best dork categories (admin, api, config, etc.)\n")
	fmt.Printf("    - Statistical trends (average results per dork type)\n\n")
	fmt.Printf("  Benefits:\n")
	fmt.Printf("    ✓ Generates progressively BETTER dorks with each scan\n")
	fmt.Printf("    ✓ Learns what works specifically for this target\n")
	fmt.Printf("    ✓ Reduces wasted AI API calls (smarter from the start)\n")
	fmt.Printf("    ✓ Builds target-specific intelligence over time\n")
	fmt.Printf("    ✓ Works with ALL AI features (-ai, -random, -subdomains)\n")
	fmt.Printf("    ✓ No duplicate dorks - always generates fresh, improved variations\n\n")

	fmt.Printf("%s# Document Analysis Examples:%s\n", colors.heading, ColorReset)
	fmt.Printf("  Basic document analysis (verbose mode shows all documents):\n")
	fmt.Printf("    %secho \"example.com\" | banshee -e pdf,docx,xlsx --analyze-docs -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Filter out non-sensitive documents (user guides, manuals, etc.):\n")
	fmt.Printf("    %secho \"example.com\" | banshee -e pdf,docx --analyze-docs --filter-docs -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Search for specific document types with AI-powered analysis:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -ai \"find technical documents\" --analyze-docs -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Non-verbose mode (only shows sensitive documents):\n")
	fmt.Printf("    %secho \"example.com\" | banshee -e pdf,docx,xlsx --analyze-docs%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Combine with SMART mode for comprehensive analysis:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -ai \"find documents\" -smart --analyze-docs --filter-docs -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  How it works:\n")
	fmt.Printf("    - Downloads found documents (PDF, DOCX, PPTX, XLSX, XLS, CSV, TXT)\n")
	fmt.Printf("    - Extracts text content (uses pdftotext for PDFs, ZIP/XML parsing for XLSX)\n")
	fmt.Printf("    - Analyzes with AI for sensitive information: credentials, PII, API keys, etc.\n")
	fmt.Printf("    - Verbose mode: Shows summary for ALL documents found\n")
	fmt.Printf("    - Non-Verbose: Only reports documents containing sensitive information\n")
	fmt.Printf("    - Filter mode: Skips non-sensitive documents (user guides, manuals, datasheets)\n\n")

	fmt.Printf("%s# Leak Checking (Paste Site Monitoring):%s\n", colors.heading, ColorReset)
	fmt.Printf("  Stdin input (newline-separated):\n")
	fmt.Printf("    %secho \"example.com\" | banshee -check-leaks -v%s\n", colors.value, ColorReset)
	fmt.Printf("    %scat domains.txt | banshee -check-leaks -keywords \"api,password\" -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  With comma-separated Keywords:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -check-leaks -keywords \"api,token,password,secret\" -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  With keywords from file:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -check-leaks -keywords keywords.txt -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  AI-powered leak detection:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -check-leaks -ai \"find credentials and API keys\" -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Combine keywords with AI:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -check-leaks -keywords \"aws,azure,gcp\" -ai \"cloud credentials\" -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  With specific search Engine:\n")
	fmt.Printf("    %secho \"example.com\" | banshee -check-leaks -engine brave -v%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Note: Leak checking searches 15+ paste sites including:\n")
	fmt.Printf("    - pastebin.com, ghostbin.com, paste.ee\n")
	fmt.Printf("    - gist.github.com, gitlab.com/-/snippets\n")
	fmt.Printf("    - hastebin.com, rentry.co, controlc.com\n")
	fmt.Printf("    - dpaste.com, privatebin.net, and more\n")
	fmt.Printf("  The -check-leaks feature searches for exposed credentials WITHOUT filtering\n")
	fmt.Printf("  to the target domain (it searches paste sites, not the target).\n\n")

	fmt.Printf("%s# CVE Database Management (Update & Filter Exploitable CVEs):%s\n", colors.heading, ColorReset)
	fmt.Printf("  Update CVE database with all exploitable CVEs:\n")
	fmt.Printf("    %sbanshee --update-cve-db%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Get only 2024 critical exploits:\n")
	fmt.Printf("    %sbanshee --update-cve-db --cve-year 2024 --severity critical%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Get 2024 critical AND high severity:\n")
	fmt.Printf("    %sbanshee --update-cve-db --cve-year 2024 --severity critical,high%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Bulk download with higher results per page (faster):\n")
	fmt.Printf("    %sbanshee --update-cve-db --cve-year 2024 --cve-results-per-page 500%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Maximum results per page (2000 max):\n")
	fmt.Printf("    %sbanshee --update-cve-db --severity critical,high --cve-results-per-page 2000%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Use API key from file (recommended):\n")
	fmt.Printf("    %secho \"YOUR_NVD_API_KEY\" > ~/.config/banshee/nvd-api-key.txt%s\n", colors.value, ColorReset)
	fmt.Printf("    %sbanshee --update-cve-db%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Or provide API key via flag:\n")
	fmt.Printf("    %sbanshee --update-cve-db --nvd-api-key YOUR_KEY%s\n\n", colors.value, ColorReset)
	fmt.Printf("  AI-Powered Dork Generation (RECOMMENDED for Defcon quality):\n")
	fmt.Printf("    %sbanshee --update-cve-db --cve-year 2025 --severity critical --ai-dork-generation%s\n\n", colors.value, ColorReset)
	fmt.Printf("    This uses gemini-cli to generate specialized, attack-focused dorks for each CVE.\n")
	fmt.Printf("    Instead of generic dorks like 'intext:\"CVE-2025-1234\"', you get targeted dorks\n")
	fmt.Printf("    based on the CVE's specific attack vector, vulnerable endpoints, and technology\n")
	fmt.Printf("    fingerprints. Install gemini-cli: https://github.com/reugn/gemini-cli\n\n")
	fmt.Printf("    Example AI-generated dorks (vs traditional):\n")
	fmt.Printf("    Traditional: intext:\"Spring\" \"CVE-2025-2320\"\n")
	fmt.Printf("    AI-powered:  inurl:/actuator/env intitle:\"Whitelabel Error Page\" \"Spring Framework\"\n")
	fmt.Printf("                 site:*.com inurl:/api/v1 \"Spring Boot\" filetype:json\n")
	fmt.Printf("                 intitle:\"Error\" \"SpringBootApplication\" inurl:/error\n\n")
	fmt.Printf("  View intelligence for a Target:\n")
	fmt.Printf("    %sbanshee --view-intel example.com%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Export intelligence to JSON:\n")
	fmt.Printf("    %sbanshee --export-intel example.com -o example-intel.json%s\n\n", colors.value, ColorReset)
	fmt.Printf("  Note: CVE updates only include EXPLOITABLE vulnerabilities:\n")
	fmt.Printf("    ✓ RCE, SQLi, XSS, Path Traversal, Auth Bypass, File Upload\n")
	fmt.Printf("    ✓ SSRF, Command Injection, Privilege Escalation, Info Disclosure\n")
	fmt.Printf("    ✗ DoS-only CVEs are skipped (not useful for Google dorking)\n")
	fmt.Printf("  Get your free NVD API key: https://nvd.nist.gov/developers/request-an-api-key\n\n")

}

func ShowErrorAndExit() {
	LogErr("[!] Error, missing or invalid argument.")
	LogErr("[!] Pipe domain(s) via stdin (cat domains.txt | banshee <flags>) or use -q for targetless search.")
	PrintUsage()
	os.Exit(1)
}

// Global spinner counter for color alternation
var spinnerColorToggle bool

func Logv(v bool, f string, a ...any) {
	if v {
		colorized := ColorizeVerboseOutput(f)
		fmt.Fprintf(os.Stderr, colorized+"\n", a...)
	}
}

func LogErr(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
}

// ColorizeVerboseOutput adds colors to [tags] in verbose output
func ColorizeVerboseOutput(msg string) string {
	if GlobalNoColors {
		return msg // Return uncolorized if colors disabled
	}

	// Pattern to match [TAG]
	re := regexp.MustCompile(`\[([^\]]+)\]`)

	return re.ReplaceAllStringFunc(msg, func(match string) string {
		tag := strings.Trim(match, "[]")
		var color string

		switch tag {
		case "Google":
			color = ColorBlue // Blue only for Google
		case "Brave":
			color = ColorOrange
	case "LEARN":
		color = ColorGreen
	case "AI", "SMART":
		color = ColorCyan
	case "OSINT":
		color = ColorTeal
	case "stdin", "Target":
		color = ColorYellow
	case "SCORING", "BUDGET", "OPTIMIZE":
		color = ColorMagenta
	case "MULTI-LANG":
		color = ColorPurple
	case "Summary":
		color = ColorBoldWhite
	default:
		color = ColorCyan // Default for other tags
	}

		return color + match + ColorReset
	})
}

// ColorizeSpinner colorizes spinner characters (alternating red/blue)
func ColorizeSpinner(spinner string) string {
	if GlobalNoColors {
		return spinner
	}

	var color string
	if spinnerColorToggle {
		color = ColorRed
	} else {
		color = ColorBlue
	}
	spinnerColorToggle = !spinnerColorToggle

	return color + spinner + ColorReset
}
