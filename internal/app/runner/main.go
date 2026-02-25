package runner

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"banshee/internal/app/ai"
	"banshee/internal/app/analysis"
	"banshee/internal/app/console"
	"banshee/internal/app/core"
	"banshee/internal/app/cve"
	"banshee/internal/app/intel"
	"banshee/internal/app/interactive"
	"banshee/internal/app/monitor"
	"banshee/internal/app/pipeline"
	"banshee/internal/app/search"
	"banshee/internal/app/tech"
	"banshee/internal/app/tenant"
	"banshee/internal/app/utils"
)

func Run() {
	// Load config file first (will set defaults)
	fileConfig := loadConfigFile()

	// Initialize config files (gemini-api-key.txt, successful.txt)
	initializeConfigFiles()

	// Initialize AI cache manager
	home, err := os.UserHomeDir()
	var aiCache *utils.AICacheManager
	if err == nil {
		configDir := filepath.Join(home, ".config", "banshee")
		aiCache = utils.NewAICacheManager(configDir)
	}

multiLangMultiplier := fileConfig.MultiLangMultiplier
if multiLangMultiplier < 0 || multiLangMultiplier > 100 {
	multiLangMultiplier = 25
}

	cfg := &Config{
		ExhaustedKeys:      make(map[string]struct{}),
		ExhaustedBraveKeys: make(map[string]struct{}),
		BraveKeyLastUsed:   make(map[string]time.Time),
		SuccessfulURLCache: make(map[string]*SuccessfulURLInfo),
		AiCacheManager:     aiCache,
		DynamicDelay:       0.25,

		// Apply config file defaults
		Engine:                fileConfig.Engine,
		Verbose:               fileConfig.Verbose,
		IncludeSubdomains:     fileConfig.Recursive,
		Insecure:              fileConfig.Insecure,
		Pages:                 fileConfig.Pages,
		Delay:                 fileConfig.Delay,
		Workers:               fileConfig.Workers,
		AiQuantity:            fileConfig.Quantity,
		Simplify:              fileConfig.Simplify,
		ResearchMode:          fileConfig.Research,
		ResearchDepth:         fileConfig.ResearchDepth,
		LearnMode:             fileConfig.Learn,
		SmartMode:             fileConfig.Smart,
		SmartTimeout:          fileConfig.SmartTimeout,
		ShowSuggestions:       fileConfig.Suggestions,
		NoFollowUp:            fileConfig.NoFollowUp,
		MaxFollowUp:           fileConfig.MaxFollowUp,
		CorrelationMode:       fileConfig.Correlation,
		MaxCorrelation:        fileConfig.MaxCorrelation,
		PatternDetection:      fileConfig.PatternDetection,
		WafBypass:             fileConfig.WAFBypass,
		SaveMode:              fileConfig.Save,
		IncludeDates:          fileConfig.IncludeDates,
		TechDetect:            fileConfig.TechDetect,
		AdaptiveMode:          fileConfig.Adaptive,
		DeepMode:              fileConfig.Deep,
		ScoringMode:           fileConfig.Scoring,
		BudgetMode:            fileConfig.Budget,
		FlushMode:             fileConfig.Flush,
		SuccessfulURLPatterns: fileConfig.SuccessfulURLPatterns,
		AiModel:               fileConfig.Model,
		OosFile:               fileConfig.OOSFile,
		MultiLangMultiplier:   multiLangMultiplier,
		MonitorMinutes:        fileConfig.MonitorTime,
	}

	analysis.DorkRun = func(ctx context.Context, cfg *core.Config, ext string) []string {
		return pipeline.DorkRun(cfg, ctx, ext)
	}
	ai.DorkRun = func(ctx context.Context, cfg *core.Config, ext string) []string {
		return pipeline.DorkRun(cfg, ctx, ext)
	}

	// Flags
	help := flag.Bool("h", false, "Display help")
	flag.BoolVar(help, "help", *help, "Display help")

	flag.BoolVar(&cfg.SubdomainMode, "s", false, "Lists subdomains of the specified domain")
	flag.BoolVar(&cfg.SubdomainMode, "subdomains", false, "Lists subdomains of the specified domain")
	flag.BoolVar(&cfg.FindApex, "find-apex", false, "Resolve apex domains via tenant lookup (expands stdin targets)")

	flag.BoolVar(&cfg.IncludeSubdomains, "a", cfg.IncludeSubdomains, "Aggressive crawling (subdomains included)")
	flag.BoolVar(&cfg.IncludeSubdomains, "recursive", cfg.IncludeSubdomains, "Aggressive crawling (subdomains included)")

	flag.IntVar(&cfg.Pages, "p", cfg.Pages, "Specify the number of pages")
	flag.IntVar(&cfg.Pages, "pages", cfg.Pages, "Specify the number of pages")

	flag.StringVar(&cfg.Dork, "q", "", "Specify a query string")
	flag.StringVar(&cfg.Dork, "query", "", "Specify a query string")

	flag.StringVar(&cfg.Exclusions, "x", "", "Excludes targets in searches (comma-separated or file)")
	flag.StringVar(&cfg.Exclusions, "exclusions", "", "Excludes targets in searches (comma-separated or file)")

	flag.StringVar(&cfg.Contents, "c", "", "Specify relevant content in comma-separated files or file path")
	flag.StringVar(&cfg.Contents, "contents", "", "Specify relevant content in comma-separated files or file path")

	flag.Float64Var(&cfg.Delay, "d", cfg.Delay, "Delay in seconds between requests")
	flag.Float64Var(&cfg.Delay, "delay", cfg.Delay, "Delay in seconds between requests")

	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "Number of parallel workers for processing (default: 5)")

	flag.StringVar(&cfg.Dictionary, "w", "", "Specify a DICTIONARY/paths/files (comma-separated or file)")
	flag.StringVar(&cfg.Dictionary, "word", "", "Specify a DICTIONARY/paths/files (comma-separated or file)")

	flag.StringVar(&cfg.Extension, "e", "", "Specify comma-separated extensions or file")
	flag.StringVar(&cfg.Extension, "extensions", "", "Specify comma-separated extensions or file")

	flag.StringVar(&cfg.OutputPath, "o", "", "Export the results to a file (results only)")
	flag.StringVar(&cfg.OutputPath, "output", "", "Export the results to a file (results only)")

	flag.StringVar(&cfg.Proxy, "r", "", "Specify an [protocol://]host[:port] proxy")
	flag.StringVar(&cfg.Proxy, "proxy", "", "Specify an [protocol://]host[:port] proxy")
	flag.BoolVar(&cfg.Insecure, "insecure", cfg.Insecure, "Skip TLS certificate verification (use with Burp/proxies)")

	flag.BoolVar(&cfg.Verbose, "v", cfg.Verbose, "Enable verbose")
	flag.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "Enable verbose")
	flag.BoolVar(&cfg.NoColors, "no-colors", false, "Disable colorful output (colors enabled by default)")

	flag.StringVar(&cfg.Engine, "engine", cfg.Engine, "Search engine to use: both, google, brave")

	flag.StringVar(&cfg.AiPrompt, "ai", "", "AI prompt for generating custom dorks (requires gemini-cli)")
	flag.IntVar(&cfg.AiQuantity, "quantity", cfg.AiQuantity, "Number of dorks to generate with --ai (default: 10)")
	flag.StringVar(&cfg.MonitorQuery, "monitor", "", "Enable monitor mode with an intent description (e.g., \"sensitive pdf\", \"sqli,xss\")")
	flag.BoolVar(&cfg.FilterMonitor, "filter-mon", false, "Enable monitor-mode filtering: dedupe URLs across cycles and filter non-sensitive docs based on intent")
	flag.IntVar(&cfg.MonitorMinutes, "monitor-time", cfg.MonitorMinutes, "Minutes between monitor cycles (default from config: 60)")
	flag.BoolVar(&cfg.AnalyzeMonitor, "analyze-mon", false, "Analyze monitor results (documents + responses; skips inline code analysis)")
	flag.BoolVar(&cfg.Simplify, "simplify", cfg.Simplify, "Simplify long AI prompts (removes dates/details)")

	randomFocus := flag.String("random", "", "Generate random dorks. Specify type: any, sqli, xss, redirect, exposure, lfi, rce, idor, api")

	flag.StringVar(&cfg.IgnoreFile, "ignore-file", "", "File with previously used dorks to ignore (one per line)")

	flag.BoolVar(&cfg.FlushMode, "flush", cfg.FlushMode, "Flush mode - ignore the ignore file and generate fresh dorks")

	flag.StringVar(&cfg.OosFile, "oos-file", cfg.OosFile, "Path to out-of-scope file (supports wildcards, one entry per line)")

	flag.BoolVar(&cfg.ResearchMode, "research", cfg.ResearchMode, "OSINT research mode - generates dorks based on target company research")
	flag.IntVar(&cfg.ResearchDepth, "research-depth", cfg.ResearchDepth, "Research depth (1-4): 1=basic, 2=moderate, 3=comprehensive, 4=linguistic [default: 1]")

	flag.BoolVar(&cfg.LearnMode, "learn", cfg.LearnMode, "Enable continuous learning - saves intelligence and generates specialized dorks")

	// AI Enhancement Flags
	flag.BoolVar(&cfg.SmartMode, "smart", cfg.SmartMode, "Context-aware dork chaining and optimization - generates follow-up dorks from discoveries and suggests improvements")
	flag.BoolVar(&cfg.ShowSuggestions, "suggestions", cfg.ShowSuggestions, "Show dork optimization suggestions (requires --smart)")
	flag.BoolVar(&cfg.NoFollowUp, "no-followup", cfg.NoFollowUp, "Skip follow-up dork generation (requires --smart)")
	flag.IntVar(&cfg.MaxFollowUp, "max-followup", cfg.MaxFollowUp, "Maximum number of follow-up dorks to generate (default 5, requires --smart)")
	flag.BoolVar(&cfg.CorrelationMode, "correlation", cfg.CorrelationMode, "Enable multi-layer correlation analysis (requires --smart)")
	flag.IntVar(&cfg.MaxCorrelation, "max-correlation", cfg.MaxCorrelation, "Max correlation dorks per subdomain (requires --correlation)")
	flag.BoolVar(&cfg.PatternDetection, "pattern-detection", cfg.PatternDetection, "Detect and exploit naming convention patterns (subdomains, emails)")
	flag.BoolVar(&cfg.SaveMode, "save", cfg.SaveMode, "Smart pagination - stops when no new results (saves API quota)")
	flag.BoolVar(&cfg.IncludeDates, "include-dates", cfg.IncludeDates, "Strategic date operators - targets specific time periods")
	flag.BoolVar(&cfg.TechDetect, "tech-detect", cfg.TechDetect, "Auto-detect tech stack and generate specialized dorks")
	flag.BoolVar(&cfg.AdaptiveMode, "adaptive", cfg.AdaptiveMode, "Adaptive rate limiting - adjusts delays based on responses")
	flag.BoolVar(&cfg.DeepMode, "deep", cfg.DeepMode, "Recursive subdomain discovery - finds sub-subdomains")
	flag.BoolVar(&cfg.ScoringMode, "scoring", cfg.ScoringMode, "AI-based result classification and vulnerability scoring")
	flag.BoolVar(&cfg.BudgetMode, "budget", cfg.BudgetMode, "Smart query budget optimization - predicts dork success before execution")
	flag.BoolVar(&cfg.WafBypass, "waf-bypass", cfg.WafBypass, "Adversarial dork generation with obfuscation and bypass techniques (URL encoding, case variations, trailing slashes)")

	flag.BoolVar(&cfg.CheckLeaks, "check-leaks", false, "Check paste sites for leaked credentials (stdin only)")
	flag.StringVar(&cfg.Keywords, "keywords", "", "Keywords for leak checking (comma-separated or file path): api,token,password,etc.")

	// CVE Database Management
	flag.BoolVar(&cfg.UpdateCVEDB, "update-cve-db", false, "Update CVE database from NVD API with latest vulnerabilities")
	flag.IntVar(&cfg.CveYear, "cve-year", 0, "Filter CVEs by year (e.g., 2024) - only with --update-cve-db")
	flag.StringVar(&cfg.CveSeverity, "severity", "", "Filter CVEs by severity: critical,high,medium,low (comma-separated) - only with --update-cve-db")
	flag.IntVar(&cfg.CveResultsPerPage, "cve-results-per-page", 100, "Results per page from NVD API (max 2000) - only with --update-cve-db")
	flag.BoolVar(&cfg.HasExploit, "has-exploit", false, "Only include CVEs with public exploits (saves AI resources) - only with --update-cve-db")
	flag.BoolVar(&cfg.AiDorkGeneration, "ai-dork-generation", false, "Use AI (gemini-cli) to generate specialized dorks for each CVE - only with --update-cve-db")
	flag.IntVar(&cfg.MaxCVEDork, "max-cve-dork", 10, "Maximum number of dorks to generate per CVE (1-20, default 10) - only with --ai-dork-generation")
	flag.StringVar(&cfg.NvdAPIKey, "nvd-api-key", "", "NVD API key for higher rate limits (get free key at https://nvd.nist.gov/developers/request-an-api-key)")

	// Intelligence Management
	flag.StringVar(&cfg.ViewIntel, "view-intel", "", "View learned intelligence for a specific target")
	flag.StringVar(&cfg.ExportIntel, "export-intel", "", "Export intelligence to JSON for a specific target")

	// Interactive Mode
	flag.BoolVar(&cfg.InteractiveMode, "interactive", false, "Launch interactive TUI - ask questions, get help, and perform research")

	// Document Analysis
	flag.BoolVar(&cfg.AnalyzeDocuments, "analyze-docs", false, "Automatically analyze found documents (PDF, DOCX, PPTX) for sensitive information using AI")
	flag.BoolVar(&cfg.FilterDocs, "filter-docs", false, "Filter out non-sensitive documents (user guides, manuals, datasheets) from analysis (requires --analyze-docs)")
	flag.BoolVar(&cfg.AnalyseOnly, "analyse-only", false, "Skip dorking and only analyze document URLs from stdin (requires --analyze-docs)")

	// Successful URL Pattern Learning
	flag.IntVar(&cfg.SuccessfulURLPatterns, "successful-url-patterns", 3, "Number of patterns to extract from successful URLs (default: 3) - only applies when tech stacks match")

	// Multi-language and fuzzing support
	flag.BoolVar(&cfg.MultiLang, "multi-lang", false, "Enable multi-language dork generation based on target's language (prioritizes foreign language dorks)")
	flag.IntVar(&cfg.MultiLangMultiplier, "multi-lang-multiplier", cfg.MultiLangMultiplier, "Percentage of dorks to generate in target language when --multi-lang is enabled (0-100)")
	flag.BoolVar(&cfg.FuzzMode, "fuzz", false, "Enable advanced fuzzing with dynamic wordlist generation, mutation engine, and recursive enumeration")
	flag.StringVar(&cfg.MatchCodes, "mc", "", "Match specific HTTP status codes (comma-separated): 200,301,403 (like httpx --mc)")

	// AI Provider Configuration
	// Set default model: config file takes precedence, fallback to gemini-2.0-flash-exp if empty
	defaultModel := "gemini-2.0-flash-exp"
	if cfg.AiModel != "" {
		defaultModel = cfg.AiModel
	}
	flag.StringVar(&cfg.AiModel, "model", defaultModel, "AI model to use (e.g., gemini-2.0-flash-exp, gemini-1.5-pro, claude-3-5-sonnet, gpt-4)")

	// Deduplication
	flag.BoolVar(&cfg.DedupeMode, "dedupe", false, "Enable intelligent deduplication: semantic analysis, parameter normalization, fuzzy matching, similarity scoring")

	// Response Analysis
	flag.BoolVar(&cfg.AnalyzeResponses, "analyze-responses", false, "Enable AI-powered response analysis (requires --dedupe and AI)")
	flag.BoolVar(&cfg.AnalyzeResponseOnly, "analyze-response-only", false, "Analyze response of URL(s) from STDIN without dorking (use: echo URL | banshee --analyze-response-only)")
	flag.BoolVar(&cfg.AnalyzeCodeOnly, "analyze-code-only", false, "Analyze code from STDIN for security vulnerabilities without dorking (use: cat script.js | banshee --analyze-code-only)")
	flag.BoolVar(&cfg.InlineCodeAnalysis, "inline-code-analysis", false, "Extract and analyze inline JavaScript from HTML for DOM-XSS, dangerous sinks, etc. (requires AI mode)")

	// Wayback Machine (Foresee Mode - AI-Powered Intelligence Analysis)
	flag.BoolVar(&cfg.ForeseeMode, "foresee", false, "Enable AI foresee mode: studies Wayback intelligence to understand target architecture and generate creative dorks")
	waybackMC := flag.String("wmc", "", "Filter Wayback results by status codes (comma-separated): 200,301,404 (requires --foresee)")
	flag.BoolVar(&cfg.NoWaybackCache, "no-wayback-cache", false, "Bypass Wayback cache and fetch fresh intelligence (requires --foresee)")
	flag.BoolVar(&cfg.ClearWaybackCache, "clear-wayback-cache", false, "Clear all Wayback cache (URLs + intelligence) and exit")
	flag.BoolVar(&cfg.AutoCleanupCache, "auto-cleanup-cache", false, "Auto-cleanup old Wayback cache (>30 days) on startup (requires --foresee)")

	flag.Parse()

	// Track which flags were explicitly set via command line
	explicitFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	// Handle model flag: if not explicitly set via CLI and config has empty model, keep it empty
	// This ensures that when model= in config, we don't pass --model to gemini-cli
	if !explicitFlags["model"] && fileConfig.Model == "" {
		cfg.AiModel = ""
	}

	// Validate CVE-related flags
	if (cfg.CveYear != 0 || cfg.CveSeverity != "" || cfg.CveResultsPerPage != 100 || cfg.HasExploit || cfg.AiDorkGeneration) && !cfg.UpdateCVEDB {
		console.LogErr("[!] Error: --cve-year, --severity, --cve-results-per-page, --has-exploit, and --ai-dork-generation can only be used with --update-cve-db")
		os.Exit(1)
	}

	// Validate max-cve-dork flag (only if explicitly set on command line)
	if explicitFlags["max-cve-dork"] {
		if !cfg.AiDorkGeneration {
			console.LogErr("[!] Error: --max-cve-dork can only be used with --ai-dork-generation")
			os.Exit(1)
		}
		if cfg.MaxCVEDork < 1 || cfg.MaxCVEDork > 20 {
			console.LogErr("[!] Error: --max-cve-dork must be between 1 and 20 (got %d)", cfg.MaxCVEDork)
			os.Exit(1)
		}
	}

	// Validate document analysis flags
	if cfg.FilterDocs && !cfg.AnalyzeDocuments {
		console.LogErr("[!] Error: --filter-docs can only be used with --analyze-docs")
		os.Exit(1)
	}
	if cfg.AnalyseOnly && !cfg.AnalyzeDocuments {
		console.LogErr("[!] Error: --analyse-only can only be used with --analyze-docs")
		os.Exit(1)
	}
	if cfg.AnalyzeDocuments && cfg.DedupeMode {
		console.LogErr("[!] Error: --dedupe cannot be used with --analyze-docs (PDF analysis handles its own filtering)")
		os.Exit(1)
	}

	// Validate response analysis flag
	if cfg.AnalyzeResponses && !cfg.DedupeMode {
		console.LogErr("[!] Error: --analyze-responses requires --dedupe flag")
		os.Exit(1)
	}

	// Validate analyze-response-only flag - URLs will be read from STDIN
	// No validation needed here, will be handled in the handler

	// Validate inline-code-analysis flag
	if cfg.InlineCodeAnalysis {
		// Must be in AI mode (at least one AI-related flag must be set)
		if cfg.AiPrompt == "" && !cfg.RandomMode && !cfg.SmartMode && !cfg.LearnMode {
			console.LogErr("[!] Error: --inline-code-analysis requires AI mode (use -ai, -random, -smart, or -learn)")
			os.Exit(1)
		}
		// Cannot be used with --analyze-docs or --analyze-response-only
		if cfg.AnalyzeDocuments {
			console.LogErr("[!] Error: --inline-code-analysis cannot be used with --analyze-docs")
			os.Exit(1)
		}
		if cfg.AnalyzeResponseOnly {
			console.LogErr("[!] Error: --inline-code-analysis cannot be used with --analyze-response-only")
			os.Exit(1)
		}
	}

	// Handle --clear-wayback-cache first (exit after cleanup)
	if cfg.ClearWaybackCache {
		fmt.Println("[WAYBACK] Clearing all Wayback cache...")
		if err := clearAllWaybackCache(); err != nil {
			console.LogErr("[!] Failed to clear cache: %v", err)
			os.Exit(1)
		}
		fmt.Println("[WAYBACK] Cache cleared successfully")
		os.Exit(0)
	}

	// Handle Wayback Machine flags
	if cfg.NoWaybackCache && !cfg.ForeseeMode {
		console.LogErr("[!] Error: --no-wayback-cache can only be used with --foresee")
		os.Exit(1)
	}

	if cfg.AutoCleanupCache && !cfg.ForeseeMode {
		console.LogErr("[!] Error: --auto-cleanup-cache can only be used with --foresee")
		os.Exit(1)
	}

	if *waybackMC != "" {
		if !cfg.ForeseeMode {
			console.LogErr("[!] Error: --wmc can only be used with --foresee")
			os.Exit(1)
		}
		// Parse comma-separated status codes
		codes := strings.Split(*waybackMC, ",")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" {
				cfg.WaybackStatusCodes = append(cfg.WaybackStatusCodes, code)
			}
		}
	} else if cfg.ForeseeMode {
		// Default: all status codes
		cfg.WaybackStatusCodes = []string{"all"}
	}

	// Feature compatibility validation for --foresee
	if cfg.ForeseeMode {
		// Restrictions that make sense:
		if cfg.Dork != "" {
			console.LogErr("[!] Error: --foresee cannot be used with -q (dork query) - use --ai prompt instead")
			os.Exit(1)
		}
		if cfg.CheckLeaks {
			console.LogErr("[!] Error: --foresee and --check-leaks cannot be used together (check-leaks searches pastebin sites, incompatible with Wayback)")
			os.Exit(1)
		}
		// Cloud enumeration is not compatible with foresee mode
		if strings.EqualFold(cfg.RandomFocus, "cloud") ||
			strings.EqualFold(cfg.RandomFocus, "cloud-assets") ||
			strings.EqualFold(cfg.RandomFocus, "s3") ||
			strings.EqualFold(cfg.RandomFocus, "azure") ||
			strings.EqualFold(cfg.RandomFocus, "gcp") ||
			isCloudPrompt(cfg.AiPrompt) {
			console.LogErr("[!] Error: --foresee cannot be combined with cloud enumeration modes or cloud AI prompts")
			os.Exit(1)
		}
		// All other features (--research, --tech-detect, --multi-lang) are compatible!
	}

	// Auto-cleanup old cache if requested
	if cfg.AutoCleanupCache && cfg.ForeseeMode {
		console.Logv(cfg.Verbose, "[WAYBACK] Auto-cleaning cache (removing entries >30 days old)...")
		removed, err := cleanupWaybackCache(30, 500*1024*1024) // 30 days, 500MB max
		if err != nil {
			console.Logv(cfg.Verbose, "[WAYBACK] Cache cleanup warning: %v", err)
		} else if removed > 0 {
			console.Logv(cfg.Verbose, "[WAYBACK] Removed %d old cache entries", removed)
		}
	}

	// Set global color flag
	console.GlobalNoColors = cfg.NoColors

	// Set default number of workers if not specified
	if cfg.Workers == 0 {
		cfg.Workers = 5
	}

	// Handle -random flag
	if *randomFocus != "" {
		cfg.RandomMode = true

		// Normalize "any" to empty string (diverse mode)
		if strings.ToLower(strings.TrimSpace(*randomFocus)) == "any" {
			cfg.RandomFocus = ""
		} else {
			cfg.RandomFocus = strings.ToLower(strings.TrimSpace(*randomFocus))
		}
	}

	// Monitor mode setup
	cfg.MonitorQuery = strings.TrimSpace(cfg.MonitorQuery)
	if cfg.MonitorQuery != "" {
		cfg.MonitorMode = true
		if cfg.MonitorMinutes <= 0 {
			cfg.MonitorMinutes = 60
		}
	}

	// Set default ignore file location if not specified and in random mode
	if (cfg.RandomMode || cfg.MonitorMode) && cfg.IgnoreFile == "" && !cfg.FlushMode {
		home, err := os.UserHomeDir()
		if err == nil {
			cfg.IgnoreFile = filepath.Join(home, ".config", "banshee", ".ignore.file")

			// Create directory if it doesn't exist
			dir := filepath.Dir(cfg.IgnoreFile)
			if err := os.MkdirAll(dir, 0755); err != nil {
				console.LogErr("[!] Warning: Could not create ignore file directory: %v", err)
				cfg.IgnoreFile = "" // Disable if can't create
			}
		}
	}

	if *help {
		console.ShowBanner()
		console.PrintUsage()
		return
	}

	// Validate mutually exclusive flags
	if cfg.RandomMode {
		if cfg.AiPrompt != "" {
			console.LogErr("[!] Error: -random cannot be used with -ai")
			os.Exit(1)
		}
		if cfg.Dork != "" {
			console.LogErr("[!] Error: -random cannot be used with -q/--query")
			os.Exit(1)
		}
		if cfg.Dictionary != "" {
			console.LogErr("[!] Error: -random cannot be used with -w/--word")
			os.Exit(1)
		}
		if cfg.Extension != "" {
			console.LogErr("[!] Error: -random cannot be used with -e/--extensions")
			os.Exit(1)
		}
		if cfg.Contents != "" {
			console.LogErr("[!] Error: -random cannot be used with -c/--contents")
			os.Exit(1)
		}
	}

	if cfg.MonitorMode {
		if cfg.Dork != "" {
			console.LogErr("[!] Error: --monitor cannot be used with -q/--query (it generates its own dorks)")
			os.Exit(1)
		}
		if cfg.AiPrompt != "" {
			console.LogErr("[!] Error: --monitor cannot be combined with -ai (monitor builds its own AI prompt)")
			os.Exit(1)
		}
		if cfg.RandomMode {
			console.LogErr("[!] Error: --monitor cannot be used with -random")
			os.Exit(1)
		}
		if cfg.DedupeMode {
			console.LogErr("[!] Error: --monitor is not compatible with --dedupe (use --filter-mon instead)")
			os.Exit(1)
		}
		if cfg.FilterDocs {
			console.LogErr("[!] Error: --monitor is not compatible with --filter-docs (use --filter-mon instead)")
			os.Exit(1)
		}
		if cfg.IncludeDates {
			console.LogErr("[!] Error: --monitor cannot be combined with --include-dates (monitor uses its own recency logic)")
			os.Exit(1)
		}
		if cfg.AnalyzeDocuments || cfg.AnalyzeResponses || cfg.InlineCodeAnalysis || cfg.AnalyzeCodeOnly || cfg.AnalyzeResponseOnly {
			console.LogErr("[!] Error: --monitor is not compatible with --analyze-docs/--analyze-responses/--inline-code-analysis/--analyze-code-only (use --analyze-mon)")
			os.Exit(1)
		}
		if cfg.AnalyseOnly {
			console.LogErr("[!] Error: --monitor cannot be combined with --analyse-only")
			os.Exit(1)
		}
		if cfg.CheckLeaks {
			console.LogErr("[!] Error: --monitor cannot be used with --check-leaks")
			os.Exit(1)
		}
	}
	if cfg.AnalyzeMonitor && !cfg.MonitorMode {
		console.LogErr("[!] Error: --analyze-mon can only be used with --monitor")
		os.Exit(1)
	}

	// Validate -s and -ai incompatibility
	if cfg.SubdomainMode && cfg.AiPrompt != "" {
		console.LogErr("[!] Error: -s/--subdomains cannot be used with -ai (use one or the other)")
		console.LogErr("    -ai: Generate dorks based on your prompt")
		console.LogErr("    -s:  Subdomain enumeration mode")
		os.Exit(1)
	}

	// Validate -s and -random incompatibility
	if cfg.SubdomainMode && cfg.RandomMode {
		console.LogErr("[!] Error: -s/--subdomains cannot be used with -random (use one or the other)")
		console.LogErr("    -random: Generate random dorks for vulnerability discovery")
		console.LogErr("    -s:      Subdomain enumeration mode")
		os.Exit(1)
	}

	// Validate research mode flags
	if cfg.ResearchMode {
		// Research mode requires AI features (-ai or -random)
		if cfg.AiPrompt == "" && !cfg.RandomMode {
			console.LogErr("[!] Error: -research requires AI features (-ai or -random)")
			os.Exit(1)
		}
		// Research mode cannot be used with -q/--query
		if cfg.Dork != "" {
			console.LogErr("[!] Error: -research cannot be used with -q/--query")
			os.Exit(1)
		}
		// Research mode cannot be used with wordlist generation
		if cfg.Dictionary != "" {
			console.LogErr("[!] Error: -research cannot be used with -w/--word (wordlist generation)")
			os.Exit(1)
		}
		// Research mode cannot be used with extension generation
		if cfg.Extension != "" {
			console.LogErr("[!] Error: -research cannot be used with -e/--extensions (extension generation)")
			os.Exit(1)
		}
		// Validate research depth
		if cfg.ResearchDepth < 1 || cfg.ResearchDepth > 4 {
			console.LogErr("[!] Error: -research-depth must be between 1 and 4")
			os.Exit(1)
		}
	}

	// Graceful Ctrl+C handling: first signal -> cancel context; second signal -> hard exit
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		count := 0
		for sig := range sigCh {
			count++
			if count == 1 {
				console.LogErr("[!] Caught %s, attempting graceful shutdown... (press Ctrl+C again to force)", sig.String())
				cancel()
			} else {
				console.LogErr("[!] Force exiting.")
				os.Exit(130)
			}
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
		cancel()
	}()

	// HTTP client for API requests (NO PROXY - direct connection to Google/Brave)
	apiClient, err := buildHTTPClient("", false)
	if err != nil {
		console.LogErr("[!] Failed to create HTTP Client: %v", err)
		os.Exit(1)
	}
	cfg.Client = apiClient

	// HTTP client for accessing found URLs (WITH PROXY if specified)
	// This client is used when validating/accessing discovered target URLs
	proxyClient, err := buildHTTPClient(cfg.Proxy, cfg.Insecure)
	if err != nil {
		console.LogErr("[!] Invalid Proxy: %v", err)
		os.Exit(1)
	}
	cfg.ProxyClient = proxyClient

	if cfg.Proxy != "" {
		console.Logv(cfg.Verbose, "[PROXY] Found URLs will be sent through Proxy: %s", cfg.Proxy)
	}

	// Load API keys based on engine selection
	useGoogle := cfg.Engine == "both" || cfg.Engine == "google"
	useBrave := cfg.Engine == "both" || cfg.Engine == "brave"

	if useGoogle {
		if err := search.LoadGoogleAPIKeysDefault(cfg); err != nil {
			console.LogErr("Google keys.txt not found or unreadable: %v", err)
			if !useBrave {
				os.Exit(1)
			}
		}
	}

	if useBrave {
		if err := search.LoadBraveAPIKeysDefault(cfg); err != nil {
			console.LogErr("Brave keys.txt not found or unreadable: %v", err)
			if !useGoogle {
				os.Exit(1)
			}
		}
	}

	// Preprocess helpers...
	if cfg.Exclusions != "" {
		cfg.ExcludeTargets = buildExclusions(cfg.Exclusions, cfg.IncludeSubdomains)
	}
	if cfg.Contents != "" {
		cfg.InFile = buildContentsQuery(cfg.Contents)
	}
	if cfg.Dictionary != "" {
		cfg.InUrl = buildInurlQuery(cfg.Dictionary)
	}

	// Load out-of-scope patterns
	if cfg.OosFile != "" {
		cfg.OosPatterns = loadOOSFile(cfg.OosFile)
		if len(cfg.OosPatterns) > 0 {
			console.Logv(cfg.Verbose, "[OOS] Loaded %d out-of-scope patterns from %s", len(cfg.OosPatterns), cfg.OosFile)
		}
	}

	// Preload output file entries to show what will be skipped during analysis
	if cfg.Verbose && cfg.OutputPath != "" {
		existing := loadExistingOutputs(cfg.OutputPath)
		console.Logv(true, "[OUTPUT] Loaded %d existing URLs from %s (these will be skipped for re-analysis)", len(existing), cfg.OutputPath)
	}

	// Check for stdin input (piped data)
	var stdinDomains []string
	var monitorTargets []string
	if checkStdin() {
		domains, err := readStdin()
		if err != nil {
			console.LogErr("[!] Error reading from stdin: %v", err)
			os.Exit(1)
		}
		stdinDomains = domains
	}

	// Stdin flow (highest priority)
	if len(stdinDomains) > 0 {
		if cfg.MonitorMode {
			monitorTargets = stdinDomains
			if len(stdinDomains) == 1 {
				cfg.Target = stdinDomains[0]
				console.Logv(cfg.Verbose, "[stdin] Monitoring single domain: %s", cfg.Target)
			} else {
				cfg.Target = stdinDomains[0]
				console.Logv(cfg.Verbose, "[stdin] Monitoring %d domains from pipe (using monitor mode)", len(stdinDomains))
			}
		} else {
			// If leak checking is enabled, store stdin for leak checking
			if cfg.CheckLeaks {
				cfg.LeakTarget = strings.Join(stdinDomains, "\n")
				if len(stdinDomains) == 1 {
					console.Logv(cfg.Verbose, "[stdin] Processing single domain: %s", stdinDomains[0])
				} else {
					console.Logv(cfg.Verbose, "[stdin] Processing %d domains from pipe", len(stdinDomains))
				}
				// Continue to leak checking flow below
			} else if len(stdinDomains) == 1 {
				// Single domain from stdin
				cfg.Target = stdinDomains[0]
				console.Logv(cfg.Verbose, "[stdin] Processing single domain: %s", cfg.Target)
				// Continue to single target flow below
			} else {
				// Multiple domains from stdin
				console.Logv(cfg.Verbose, "[stdin] Processing %d domains from pipe", len(stdinDomains))
				if err := pipeline.ProcessDomainsFromList(cfg, ctx, stdinDomains); err != nil {
					if errors.Is(err, context.Canceled) {
						os.Exit(130)
					}
					console.LogErr("%v", err)
					os.Exit(1)
				}
				return
			}
		}
	}

	if cfg.FindApex && cfg.Target != "" && !cfg.MonitorMode && !cfg.AnalyseOnly && !cfg.AnalyzeResponseOnly && !cfg.AnalyzeCodeOnly && !cfg.CheckLeaks && !cfg.UpdateCVEDB && cfg.ViewIntel == "" && cfg.ExportIntel == "" && !cfg.InteractiveMode {
		apexTargets, err := tenant.ResolveApexTargets(cfg, ctx, []string{cfg.Target})
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(130)
			}
			console.LogErr("[!] Failed to resolve apex domains: %v", err)
		} else if len(apexTargets) > 0 {
			if len(apexTargets) > 1 {
				console.Logv(cfg.Verbose, "[APEX] Expanded to %d apex domain(s)", len(apexTargets))
				tenant.LogApexTargets(cfg, apexTargets)
				if err := pipeline.ProcessDomainsFromList(cfg, ctx, apexTargets); err != nil {
					if errors.Is(err, context.Canceled) {
						os.Exit(130)
					}
					console.LogErr("%v", err)
					os.Exit(1)
				}
				return
			}
			if apexTargets[0] != cfg.Target {
				console.Logv(cfg.Verbose, "[APEX] Target resolved to: %s", apexTargets[0])
			}
			cfg.Target = apexTargets[0]
		}
	}

	// Detect target language if multi-lang mode is enabled (AFTER stdin/target is set)
	if cfg.MultiLang && cfg.Target != "" {
		cfg.TargetLanguage = ai.DetectTargetLanguage(cfg, ctx)
		if cfg.TargetLanguage != "en" {
			portion := cfg.MultiLangMultiplier
			if portion < 0 || portion > 100 {
				portion = 25
			}
			console.Logv(cfg.Verbose, "[MULTI-LANG] Will generate %d%% of dorks in target's language to save API quota", portion)
		} else {
			console.Logv(cfg.Verbose, "[MULTI-LANG] Target uses English, no translation needed")
		}
	}

	// Document analysis only mode (--analyse-only)
	if cfg.AnalyseOnly {
		// Read URLs from stdin
		if len(stdinDomains) == 0 {
			console.LogErr("[!] Error: --analyse-only requires URLs from stdin")
			console.LogErr("[!] Usage: echo 'https://example.com/document.pdf' | ./banshee --analyse-docs --analyse-only --filter-docs")
			console.LogErr("[!]        cat urls.txt | ./banshee --analyse-docs --analyse-only")
			os.Exit(1)
		}

		console.Logv(cfg.Verbose, "[ANALYSE-ONLY] Processing %d document URLs from stdin with %d workers", len(stdinDomains), cfg.Workers)

		// Filter out empty URLs
		var validURLs []string
		for _, docURL := range stdinDomains {
			docURL = strings.TrimSpace(docURL)
			if docURL != "" {
				validURLs = append(validURLs, docURL)
			}
		}

		// Analyze documents in parallel using worker pool
		if len(validURLs) > 0 {
			// Convert URLs to interface{} for worker pool
			items := make([]interface{}, len(validURLs))
			for i, url := range validURLs {
				items[i] = url
			}

			// Document analysis processor
			docProcessor := func(ctx context.Context, item interface{}) (interface{}, error) {
				url := item.(string)
				analysis.AnalyzeDocumentForSensitiveInfo(cfg, ctx, url)
				return nil, nil
			}

			processWithWorkerPool(ctx, items, cfg.Workers, docProcessor)
		}

		console.Logv(cfg.Verbose, "[ANALYSE-ONLY] Completed analysis of %d URLs", len(validURLs))
		return
	}

	// Response analysis only mode (--analyze-response-only)
	if cfg.AnalyzeResponseOnly {
		// Read URLs from stdin
		if len(stdinDomains) == 0 {
			console.LogErr("[!] Error: --analyze-response-only requires URLs from stdin")
			console.LogErr("[!] Usage: echo 'https://example.com' | ./banshee --analyze-response-only")
			console.LogErr("[!]        cat urls.txt | ./banshee --analyze-response-only -v")
			os.Exit(1)
		}

		// Analyze each URL
		for _, urlStr := range stdinDomains {
			urlStr = strings.TrimSpace(urlStr)
			if urlStr == "" {
				continue
			}

			// Validate URL format
			if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
				console.LogErr("[!] Skipping invalid URL (must start with http:// or https://): %s", urlStr)
				continue
			}

			cfg.AnalyzeResponseURL = urlStr

			// Fetch and analyze the response
			if err := analysis.AnalyzeResponseOnlyHandler(cfg, ctx); err != nil {
				console.LogErr("[!] Failed to analyze response for %s: %v", urlStr, err)
				continue // Continue with next URL instead of exiting
			}
		}
		return
	}

	// Code analysis only mode (--analyze-code-only)
	if cfg.AnalyzeCodeOnly {
		// Read code from stdin
		if len(stdinDomains) == 0 {
			console.LogErr("[!] Error: --analyze-code-only requires code input from stdin")
			console.LogErr("[!] Usage: cat script.js | ./banshee --analyze-code-only")
			console.LogErr("[!]        echo 'var x = eval(input);' | ./banshee --analyze-code-only -v")
			os.Exit(1)
		}

		// Combine all stdin input as code
		codeToAnalyze := strings.Join(stdinDomains, "\n")

		console.Logv(cfg.Verbose, "[CODE-ANALYSIS] Analyzing %d bytes of code...", len(codeToAnalyze))

		// Analyze the code with AI (using the same function as inline code analysis)
		analysis, err := analysis.AnalyzeInlineJavaScript(cfg, ctx, "stdin", codeToAnalyze)
		if err != nil {
			console.LogErr("[!] Failed to analyze code: %v", err)
			os.Exit(1)
		}

		if analysis == "" {
			fmt.Printf("%s[CODE-ANALYSIS]%s No vulnerabilities found\n", console.ColorGreen, console.ColorReset)
			return
		}

		// Parse and display results
		var result struct {
			Vulnerabilities []struct {
				Type       string `json:"type"`
				Confidence string `json:"confidence"`
				Reasoning  string `json:"reasoning"`
				Payload    string `json:"payload"`
				Snippet    string `json:"snippet"`
				Line       string `json:"line"`
			} `json:"vulnerabilities"`
		}

		if err := json.Unmarshal([]byte(analysis), &result); err != nil {
			console.LogErr("[!] Failed to parse AI response: %v", err)
			console.Logv(cfg.Verbose, "[!] Raw response: %s", analysis)
			os.Exit(1)
		}

		// Display findings
		if len(result.Vulnerabilities) == 0 {
			fmt.Printf("%s[CODE-ANALYSIS]%s No vulnerabilities found\n", console.ColorGreen, console.ColorReset)
			return
		}

		fmt.Printf("\n%s[CODE-ANALYSIS]%s Found %d vulnerabilities:\n\n", console.ColorRed, console.ColorReset, len(result.Vulnerabilities))

		for i, vuln := range result.Vulnerabilities {
			// Determine color based on confidence
			var confidenceColor string
			switch strings.ToLower(vuln.Confidence) {
			case "high":
				confidenceColor = console.ColorGreen
			case "medium", "low":
				confidenceColor = console.ColorYellow
			default:
				confidenceColor = console.ColorYellow
			}

			snippetShort := vuln.Snippet
			if len(snippetShort) > 100 {
				snippetShort = snippetShort[:97] + "..."
			}

			payloadColored := fmt.Sprintf("%s%s%s", console.ColorRed, vuln.Payload, console.ColorReset)

			fmt.Printf("%s[%d]%s %s%s%s (%sconfidence: %s%s)\n",
				console.ColorCyan, i+1, console.ColorReset,
				confidenceColor, vuln.Type, console.ColorReset,
				console.ColorGray, vuln.Confidence, console.ColorReset)
			fmt.Printf("    %sLine:%s %s\n", console.ColorCyan, console.ColorReset, vuln.Line)
			fmt.Printf("    %sSnippet:%s %s\n", console.ColorCyan, console.ColorReset, snippetShort)
			fmt.Printf("    %sPayload:%s %s\n", console.ColorCyan, console.ColorReset, payloadColored)

			if cfg.Verbose && vuln.Reasoning != "" {
				fmt.Printf("    %sReasoning:%s %s\n", console.ColorCyan, console.ColorReset, vuln.Reasoning)
			}
			fmt.Println()
		}

		return
	}

	// Leak checking flow
	if cfg.CheckLeaks {
		// If no stdin input, check for positional argument or file
		if cfg.LeakTarget == "" {
			args := flag.Args()
			if len(args) > 0 {
				cfg.LeakTarget = args[0]
			} else {
				console.LogErr("[!] Error: -check-leaks requires stdin input")
				console.LogErr("[!] Usage: echo domain.com | banshee -check-leaks -v")
				console.LogErr("[!]        cat domains.txt | banshee -check-leaks -v")
				os.Exit(1)
			}
		}

		if err := analysis.CheckPasteSitesForLeaks(cfg, ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(130)
			}
			console.LogErr("%v", err)
			os.Exit(1)
		}
		return
	}

	// ========== CVE DATABASE UPDATE ==========
	// Update CVE database from NVD API if requested
	if cfg.UpdateCVEDB {
		// Try to load NVD API key from file if not provided via flag
		if cfg.NvdAPIKey == "" {
			if home, err := os.UserHomeDir(); err == nil {
				keyPath := filepath.Join(home, ".config", "banshee", "nvd-api-key.txt")
				if keyData, err := os.ReadFile(keyPath); err == nil {
					cfg.NvdAPIKey = strings.TrimSpace(string(keyData))
					if cfg.NvdAPIKey != "" {
						console.Logv(cfg.Verbose, "[+] Loaded NVD API key from %s", keyPath)
					}
				}
			}
		}

		if err := cve.UpdateCVEDatabase(cfg, ctx); err != nil {
			console.LogErr("[!] Failed to update CVE database: %v", err)
			os.Exit(1)
		}
		return
	}

	// ========== INTELLIGENCE VIEWER ==========
	// View intelligence for a specific target
	if cfg.ViewIntel != "" {
		if err := intel.ViewIntelligence(cfg, cfg.ViewIntel); err != nil {
			console.LogErr("[!] %v", err)
			os.Exit(1)
		}
		return
	}

	// ========== INTELLIGENCE EXPORT ==========
	// Export intelligence to JSON
	if cfg.ExportIntel != "" {
		if err := intel.ExportIntelligence(cfg, cfg.ExportIntel); err != nil {
			console.LogErr("[!] %v", err)
			os.Exit(1)
		}
		return
	}

	// ========== INTERACTIVE MODE ==========
	// Launch interactive TUI
	if cfg.InteractiveMode {
		if cfg.MonitorMode {
			console.Logv(true, "[INTERACTIVE] --monitor detected; start monitor via /monitor or /execute inside interactive mode")
			cfg.MonitorMode = false
		}
		if err := interactive.LaunchInteractiveMode(cfg); err != nil {
			console.LogErr("[!] %v", err)
			os.Exit(1)
		}
		return
	}

	// Single target flow (allow empty target if using -q/--query flag)
	if cfg.Target == "" && cfg.Dork == "" && !cfg.MonitorMode {
		console.ShowErrorAndExit()
	}

	// ========== FLAG COMPATIBILITY VALIDATIONS ==========
	// Only validate when target is provided

	// Validate --correlation requires --smart
	if cfg.CorrelationMode && !cfg.SmartMode {
		console.LogErr("[!] Error: --correlation requires --smart")
		console.LogErr("    --smart enables context-aware dork chaining")
		console.LogErr("    --correlation enables multi-layer correlation analysis")
		os.Exit(1)
	}

	// Validate --suggestions requires --smart
	if cfg.ShowSuggestions && !cfg.SmartMode {
		console.LogErr("[!] Error: --suggestions requires --smart")
		console.LogErr("    --smart enables context-aware dork chaining and optimization")
		console.LogErr("    --suggestions then shows the optimization analysis")
		os.Exit(1)
	}

	// Validate --no-followup requires --smart
	if cfg.NoFollowUp && !cfg.SmartMode {
		console.LogErr("[!] Error: --no-followup requires --smart")
		console.LogErr("    --smart enables follow-up dork generation")
		console.LogErr("    --no-followup disables that feature")
		os.Exit(1)
	}

	// Validate --max-followup requires --smart (only if explicitly set on command line)
	if explicitFlags["max-followup"] && !cfg.SmartMode {
		console.LogErr("[!] Error: --max-followup requires --smart")
		console.LogErr("    --smart enables follow-up dork generation")
		console.LogErr("    --max-followup controls how many are generated")
		os.Exit(1)
	}

	// Validate max-correlation is positive (only if correlation mode is enabled)
	if cfg.CorrelationMode && cfg.MaxCorrelation < 1 {
		console.LogErr("[!] Error: --max-correlation must be at least 1")
		os.Exit(1)
	}

	// Validate multi-lang and research are not used together (research already handles language context)
	if cfg.ResearchMode && cfg.MultiLang {
		console.LogErr("[!] Error: --multi-lang cannot be combined with --research")
		console.LogErr("    Research mode already adapts to the target's language; remove --multi-lang")
		os.Exit(1)
	}

	if cfg.MonitorMode {
		if len(monitorTargets) == 0 && cfg.Target != "" {
			monitorTargets = append(monitorTargets, cfg.Target)
		}
		if cfg.FindApex && len(monitorTargets) > 0 {
			apexTargets, err := tenant.ResolveApexTargets(cfg, ctx, monitorTargets)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					os.Exit(130)
				}
				console.LogErr("[!] Failed to resolve apex monitor targets: %v", err)
			} else if len(apexTargets) > 0 {
				monitorTargets = apexTargets
				console.Logv(cfg.Verbose, "[APEX] Monitor targets expanded to %d apex domain(s)", len(monitorTargets))
				tenant.LogApexTargets(cfg, monitorTargets)
			}
		}
		if len(monitorTargets) == 0 {
			console.LogErr("[!] Error: --monitor requires targets (stdin or positional domain)")
			os.Exit(1)
		}
		if cfg.FilterMonitor && cfg.MonitorSeenURLs == nil {
			cfg.MonitorSeenURLs = core.NewSafeSet()
		}
		if err := monitor.RunMonitor(cfg, ctx, monitorTargets); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(130)
			}
			console.LogErr("%v", err)
			os.Exit(1)
		}
		tenant.PrintApexSummary(cfg)
		return
	}

	var ran bool

	// Random mode flow
	if cfg.Target != "" && cfg.RandomMode {
		ran = true

		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "Target: %s\n", cfg.Target)
			if cfg.ResearchMode {
				fmt.Fprintf(os.Stderr, "Research Mode: OSINT depth %d\n", cfg.ResearchDepth)
			}
			if cfg.RandomFocus != "" {
				fmt.Fprintf(os.Stderr, "Random Mode: Generating %d %s-focused dorks\n", cfg.AiQuantity, cfg.RandomFocus)
			} else {
				fmt.Fprintf(os.Stderr, "Random Mode: Generating %d diverse dorks\n", cfg.AiQuantity)
			}
			if cfg.IgnoreFile != "" {
				fmt.Fprintf(os.Stderr, "Ignore File: %s\n", cfg.IgnoreFile)
			}
		}

		var dorks []string
		var err error

		// If research mode is enabled, perform OSINT research first
		if cfg.ResearchMode {
			researchData, researchErr := ai.PerformOSINTResearch(cfg, ctx, cfg.Target)
			if researchErr != nil {
				console.LogErr("[!] Failed to perform OSINT research: %v", researchErr)
				console.LogErr("[!] Falling back to standard random dork generation")
				// Fallback to standard random dorks
				dorks, err = ai.GenerateRandomDorks(cfg, ctx)
			} else {
				// Generate research-based dorks
				dorks, err = ai.GenerateResearchBasedDorks(cfg, ctx, cfg.Target, researchData)
			}
		} else {
			// Standard random dork generation
			dorks, err = ai.GenerateRandomDorks(cfg, ctx)
		}

		if err != nil {
			console.LogErr("[!] Failed to generate dorks: %v", err)
		} else if len(dorks) > 0 {
			// Execute the generated dorks
			pipeline.MultiDorkAttack(cfg, ctx, dorks)
		}
	}

	// ========== CVE HUNTING CHECK ==========
	// Check if user is requesting CVE hunting without --tech-detect flag
	if cfg.Target != "" && cfg.LearnMode && !cfg.TechDetect && cfg.AiPrompt != "" {
		// Use AI-based intent detection to determine if user wants CVE hunting
		if isCVEHuntingIntent(cfg.AiPrompt) {
			console.LogErr("[!] CVE hunting requires technology detection for better results")
			console.LogErr("[!] Recommendation: Add --tech-detect flag for accurate CVE matching")
			console.LogErr("[!] Example: echo %s | banshee --tech-detect -ai \"%s\"", cfg.Target, cfg.AiPrompt)
		}
	}

	// ========== TLD MASS SCANNING ==========
	// If target starts with ".", treat it as TLD mass scanning
	if cfg.Target != "" && strings.HasPrefix(cfg.Target, ".") {
		// Parse comma-separated TLDs
		tlds := strings.Split(cfg.Target, ",")
		for i, tld := range tlds {
			tlds[i] = strings.TrimSpace(tld)
			// Ensure TLD starts with .
			if !strings.HasPrefix(tlds[i], ".") {
				tlds[i] = "." + tlds[i]
			}
		}

		fmt.Printf("\n%s[TLD-SCAN]%s Mass scanning %d TLD(s): %s\n", console.ColorCyan, console.ColorReset, len(tlds), strings.Join(tlds, ", "))

		if !cfg.TechDetect {
			console.LogErr("[!] Error: TLD mass scanning requires --tech-detect flag")
			console.LogErr("    Example: echo %s | banshee --tech-detect", cfg.Target)
			os.Exit(1)
		}

		// Perform TLD mass scanning
		if err := pipeline.PerformTLDMassScanning(cfg, ctx, tlds); err != nil {
			console.LogErr("[!] TLD mass scanning failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// ========== TECHNOLOGY DETECTION & CVE SCANNING ==========
	// Perform comprehensive technology fingerprinting only when explicitly requested
	if cfg.Target != "" && cfg.TechDetect {
		console.Logv(cfg.Verbose, "[TECH-DETECT] Performing Wappalyzer-based technology fingerprinting...")

		techDorks, detectedCVEs := tech.PerformComprehensiveTechDetection(cfg, ctx)

		// Execute tech-based and CVE-based dorks
		if len(techDorks) > 0 {
			console.Logv(cfg.Verbose, "[TECH-DORK] Executing %d technology and CVE-based dorks", len(techDorks))
			pipeline.MultiDorkAttack(cfg, ctx, techDorks)
			ran = true
		}

		// If CVEs were detected, display summary
		if len(detectedCVEs) > 0 {
			console.Logv(cfg.Verbose, "")
			console.Logv(cfg.Verbose, "╔════════════════════════════════════════════════════════════════╗")
			console.Logv(cfg.Verbose, "║           CVE DETECTION SUMMARY                                ║")
			console.Logv(cfg.Verbose, "╚════════════════════════════════════════════════════════════════╝")

			criticalCount := 0
			highCount := 0

			for _, cve := range detectedCVEs {
				severityColor := ""
				switch cve.Severity {
				case "critical":
					severityColor = "\033[1;31m" // Bold red
					criticalCount++
				case "high":
					severityColor = "\033[1;33m" // Bold yellow
					highCount++
				default:
					severityColor = "\033[1;37m" // Bold white
				}

				console.Logv(cfg.Verbose, "%s[%s] %s - %s - CVSS: %.1f%s",
					severityColor, strings.ToUpper(cve.Severity), cve.CVEID, cve.Description, cve.CVSS, "\033[0m")

				if cve.HasPublicExploit {
					console.Logv(cfg.Verbose, "        ⚠️  PUBLIC EXPLOIT AVAILABLE (%s)", cve.ExploitType)
				}
			}

			console.Logv(cfg.Verbose, "")
			console.Logv(cfg.Verbose, "Summary: %d CVEs detected (%d critical, %d high)",
				len(detectedCVEs), criticalCount, highCount)
			console.Logv(cfg.Verbose, "")
		}
	}

	// =========================================================================
	// WAYBACK MACHINE FORESEE MODE - AI-POWERED INTELLIGENCE ANALYSIS
	// =========================================================================
	if cfg.Target != "" && cfg.ForeseeMode {
		ran = true

		// Try to load cached Wayback intelligence (unless --no-wayback-cache is set)
		var waybackIntel *core.WaybackIntelligence

		if !cfg.NoWaybackCache {
			waybackIntel, _ = loadWaybackIntelligence(cfg.Target)
			// Don't print message here - will be printed later in else if block
		} else {
			console.Logv(cfg.Verbose, "[WAYBACK] Bypassing cache (--no-wayback-cache)")
		}

		if waybackIntel == nil {
			// No cache or expired, query Wayback
			urls, err := queryWaybackCDX(ctx, cfg.Target, cfg.WaybackStatusCodes, cfg.Verbose)
			if err != nil {
				console.LogErr("[!] Wayback query failed: %v", err)
			} else if len(urls) > 0 {
				// Apply exclusion filters if specified
				if cfg.Exclusions != "" {
					urls = filterExcludedURLs(urls, cfg.Exclusions, cfg.Verbose)
					if len(urls) == 0 {
						console.Logv(cfg.Verbose, "[WAYBACK] All URLs excluded by -x filters")
					}
				}

				// Extract intelligence from historical URLs
				if len(urls) > 0 {
					waybackIntel = extractWaybackIntelligence(cfg.Target, urls, cfg.Verbose)

					// Save intelligence for future use
					if waybackIntel != nil {
						if err := saveWaybackIntelligence(cfg.Target, waybackIntel); err != nil {
							console.Logv(cfg.Verbose, "[WAYBACK] Warning: Failed to save Intelligence: %v", err)
						}
					}
				}

				// Display intelligence summary
				if waybackIntel != nil {
					console.Logv(cfg.Verbose, "\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s", console.ColorCyan, console.ColorReset)
				console.Logv(cfg.Verbose, "%sWAYBACK INTELLIGENCE SUMMARY%s", console.ColorGreen, console.ColorReset)
				console.Logv(cfg.Verbose, "%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", console.ColorCyan, console.ColorReset)

				if len(waybackIntel.Subdomains) > 0 {
					console.Logv(cfg.Verbose, "%s📁 Subdomains Discovered:%s %d", console.ColorYellow, console.ColorReset, len(waybackIntel.Subdomains))
					for i, sub := range waybackIntel.Subdomains {
						if i < 10 { // Show first 10
							console.Logv(cfg.Verbose, "   • %s", sub)
						}
					}
					if len(waybackIntel.Subdomains) > 10 {
						console.Logv(cfg.Verbose, "   ... and %d more", len(waybackIntel.Subdomains)-10)
					}
					console.Logv(cfg.Verbose, "")
				}

				if len(waybackIntel.Parameters) > 0 {
					console.Logv(cfg.Verbose, "%s🔍 Vulnerable Parameters:%s %d unique", console.ColorYellow, console.ColorReset, len(waybackIntel.Parameters))
					count := 0
					for param := range waybackIntel.Parameters {
						if count < 10 {
							console.Logv(cfg.Verbose, "   • %s", param)
						}
						count++
					}
					if len(waybackIntel.Parameters) > 10 {
						console.Logv(cfg.Verbose, "   ... and %d more", len(waybackIntel.Parameters)-10)
					}
					console.Logv(cfg.Verbose, "")
				}

				if len(waybackIntel.FilePatterns) > 0 {
					console.Logv(cfg.Verbose, "%s📄 Document Types:%s", console.ColorYellow, console.ColorReset)
					for ext, paths := range waybackIntel.FilePatterns {
						if len(paths) > 0 {
							console.Logv(cfg.Verbose, "   • %s (%d files)", ext, len(paths))
						}
					}
					console.Logv(cfg.Verbose, "")
				}

				if len(waybackIntel.TechStack) > 0 {
					console.Logv(cfg.Verbose, "%s⚙️  Technology Stack:%s", console.ColorYellow, console.ColorReset)
					for _, tech := range waybackIntel.TechStack {
						console.Logv(cfg.Verbose, "   • %s", tech)
					}
					console.Logv(cfg.Verbose, "")
				}

				if len(waybackIntel.TemporalPatterns) > 0 {
					console.Logv(cfg.Verbose, "%s📅 Temporal Patterns:%s %d patterns detected", console.ColorYellow, console.ColorReset, len(waybackIntel.TemporalPatterns))
					for i, tp := range waybackIntel.TemporalPatterns {
						if i < 3 {
							console.Logv(cfg.Verbose, "   • %s", tp.Pattern)
							if len(tp.MissingYears) > 0 {
								console.Logv(cfg.Verbose, "     Missing years: %v", tp.MissingYears)
							}
						}
					}
					console.Logv(cfg.Verbose, "")
				}

				if len(waybackIntel.DirectoryPatterns) > 0 {
					console.Logv(cfg.Verbose, "%s📂 Directory Patterns:%s %d patterns", console.ColorYellow, console.ColorReset, len(waybackIntel.DirectoryPatterns))
					for i, dp := range waybackIntel.DirectoryPatterns {
						if i < 3 {
							console.Logv(cfg.Verbose, "   • %s (seen %d times)", dp.Template, dp.Count)
						}
					}
					console.Logv(cfg.Verbose, "")
				}

				console.Logv(cfg.Verbose, "%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", console.ColorCyan, console.ColorReset)
				}
			}
		} else if waybackIntel != nil {
			console.Logv(cfg.Verbose, "[WAYBACK] Using cached intelligence (generated %s)", waybackIntel.ProcessedAt.Format("2006-01-02 15:04"))
		}

		// Generate targeted dorks from Wayback intelligence using AI
		if waybackIntel != nil {
			// Display informative headers like regular AI mode
			console.Logv(cfg.Verbose, "Target: %s", cfg.Target)
			console.Logv(cfg.Verbose, "AI Prompt: %s", cfg.AiPrompt)

			// Show AI model being used
			aiModel := cfg.AiModel
			if aiModel == "" {
				// Read from config file
				homeDir, _ := os.UserHomeDir()
				if homeDir != "" {
					configPath := filepath.Join(homeDir, ".config", "banshee", ".config")
					if data, err := os.ReadFile(configPath); err == nil {
						lines := strings.Split(string(data), "\n")
						for _, line := range lines {
							line = strings.TrimSpace(line)
							if strings.HasPrefix(line, "model=") {
								model := strings.TrimPrefix(line, "model=")
								model = strings.TrimSpace(model)
								if model != "" && model != "default" {
									aiModel = model
									break
								}
							}
						}
					}
				}
				if aiModel == "" {
					aiModel = "gemini-2.0-flash-exp"
				}
			}
			console.Logv(cfg.Verbose, "[AI-MODEL] %s", aiModel)

			// Show learn mode integration
			if cfg.LearnMode && cfg.Intelligence != nil && cfg.Intelligence.TotalScans > 0 {
				console.Logv(cfg.Verbose, "[LEARN] Loaded Intelligence: %d previous scans, %d successful dorks",
					cfg.Intelligence.TotalScans, len(cfg.Intelligence.SuccessfulDorks))
				console.Logv(cfg.Verbose, "[LEARN] Enhanced prompt with historical intelligence")
			}

			// Generate Wayback dorks (intent analysis happens inside this function)
			waybackDorks := generateAIPoweredWaybackDorks(cfg.Target, waybackIntel, cfg.AiPrompt, cfg.AiQuantity, cfg.Verbose, cfg.WafBypass)

			// Collect all dorks (Wayback + potential AI supplemental)
			allDorks := waybackDorks

			// SUPPLEMENT: If Wayback didn't generate enough dorks, add AI-generated dorks
			if len(waybackDorks) < cfg.AiQuantity {
				remaining := cfg.AiQuantity - len(waybackDorks)
				console.Logv(cfg.Verbose, "[WAYBACK-AI] Wayback generated %d/%d dorks, generating %d supplemental AI dorks", len(waybackDorks), cfg.AiQuantity, remaining)

				// Temporarily adjust quantity and verbose for supplemental generation
				originalQuantity := cfg.AiQuantity
				originalVerbose := cfg.Verbose
				cfg.AiQuantity = remaining
				cfg.Verbose = false // Suppress verbose output from generateDorksWithAI

				supplementalDorks, err := ai.GenerateDorksWithAI(cfg, ctx, cfg.AiPrompt)

				cfg.AiQuantity = originalQuantity
				cfg.Verbose = originalVerbose

				if err == nil && len(supplementalDorks) > 0 {
					console.Logv(cfg.Verbose, "[AI] Generated %d supplemental dorks", len(supplementalDorks))
					allDorks = append(allDorks, supplementalDorks...)
				} else if err != nil {
					console.Logv(cfg.Verbose, "[AI] Supplemental dork generation failed: %v", err)
				}
			}

			if len(allDorks) > 0 {
				// Display combined dorks list
				console.Logv(cfg.Verbose, "[WAYBACK-AI] Generated %d dorks:", len(allDorks))
				for i, dork := range allDorks {
					if i < 10 || cfg.Verbose { // Show all in verbose mode, first 10 otherwise
						console.Logv(cfg.Verbose, "  %d. %s", i+1, dork)
					}
				}
				if len(allDorks) > 10 && !cfg.Verbose {
					console.Logv(true, "  ... and %d more (use -v to see all)", len(allDorks)-10)
				}

				// Apply deduplication if enabled
				if cfg.DedupeMode {
					originalCount := len(allDorks)
					allDorks = deduplicateDorks(allDorks)
					if len(allDorks) < originalCount {
						console.Logv(cfg.Verbose, "[WAYBACK-AI] Deduplicated: %d → %d dorks", originalCount, len(allDorks))
					}
				}

				// INCLUDE-DATES: Apply date operators if enabled
				if cfg.IncludeDates {
					timeline := ai.DetectCompanyTimeline(cfg, ctx)
					if timeline != nil {
						console.Logv(cfg.Verbose, "[WAYBACK-DATES] Applying strategic date operators to dorks")
						for i := range allDorks {
							allDorks[i] = addDateOperators(allDorks[i], timeline)
						}
					}
				}

				// Store Wayback intelligence globally for Smart mode integration
				cfg.WaybackIntelligence = waybackIntel

				// Execute all dorks (Wayback + AI supplemental) together in one batch
				pipeline.MultiDorkAttack(cfg, ctx, allDorks)
			}

			// Foresee mode with Wayback is complete - skip normal AI mode
			return
		}
	}

	// AI-powered dork generation flow
	// Skip if foresee mode (Wayback already handled above)
	if cfg.Target != "" && cfg.AiPrompt != "" && !cfg.ForeseeMode {
		ran = true

		// If research mode is enabled with AI mode, perform research-based dork generation
		if cfg.ResearchMode {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "Target: %s\n", cfg.Target)
				fmt.Fprintf(os.Stderr, "Research Mode: OSINT depth %d\n", cfg.ResearchDepth)
				fmt.Fprintf(os.Stderr, "AI Mode: Research-based dork generation\n")
			}

			researchData, err := ai.PerformOSINTResearch(cfg, ctx, cfg.Target)
			if err != nil {
				console.LogErr("[!] Failed to perform OSINT research: %v", err)
				console.LogErr("[!] Falling back to standard AI dork generation")
				// Fallback to standard AI mode
				if fileExists(cfg.AiPrompt) {
					prompts, err := readLines(cfg.AiPrompt)
					if err != nil {
						console.LogErr("[!] Error reading AI prompts file: %v", err)
						os.Exit(1)
					}
					if len(prompts) == 0 {
						console.LogErr("[!] No prompts found in file: %s", cfg.AiPrompt)
						os.Exit(1)
					}
					pipeline.AiDorkAttackMultiplePrompts(cfg, ctx, prompts)
				} else {
					pipeline.AiDorkAttack(cfg, ctx)
				}
			} else {
				// Generate research-based dorks
				dorks, err := ai.GenerateResearchBasedDorks(cfg, ctx, cfg.Target, researchData)
				if err != nil {
					console.LogErr("[!] Failed to generate research-based dorks: %v", err)
				} else if len(dorks) > 0 {
					// Execute the generated dorks
					pipeline.MultiDorkAttack(cfg, ctx, dorks)
				}
			}
		} else {
			// Standard AI mode (no research)
			if fileExists(cfg.AiPrompt) {
				// Read prompts from file
				prompts, err := readLines(cfg.AiPrompt)
				if err != nil {
					console.LogErr("[!] Error reading AI prompts file: %v", err)
					os.Exit(1)
				}

				if len(prompts) == 0 {
					console.LogErr("[!] No prompts found in file: %s", cfg.AiPrompt)
					os.Exit(1)
				}

				console.Logv(cfg.Verbose, "[AI] Loaded %d prompts from file: %s\n", len(prompts), cfg.AiPrompt)

				// Execute each prompt
				pipeline.AiDorkAttackMultiplePrompts(cfg, ctx, prompts)
			} else {
				// Single prompt (direct string)
				pipeline.AiDorkAttack(cfg, ctx)
			}
		}
	}

	if cfg.Target != "" && cfg.Dictionary != "" {
		ran = true
		pipeline.DictionaryAttack(cfg, ctx)
	}
	if cfg.Target != "" && cfg.Extension != "" {
		if cfg.AiPrompt != "" || cfg.RandomMode || cfg.LearnMode || cfg.SmartMode {
			// AI/random/learn/smart flows handle extensions inline; skip standalone extension scan
			console.Logv(cfg.Verbose, "[EXT] Skipping standalone extension scan because AI/SMART mode is active")
		} else {
			ran = true
			pipeline.ExtensionAttack(cfg, ctx)
		}
	}
	if cfg.Target != "" && cfg.SubdomainMode {
		ran = true
		pipeline.SubdomainAttack(cfg, ctx)
	}
	if cfg.Target != "" && cfg.Contents != "" {
		ran = true
		pipeline.ContentsAttack(cfg, ctx)
	}
	if cfg.Dork != "" {
		ran = true

		// Check if dork is a file path
		if fileExists(cfg.Dork) {
			// Read dorks from file
			dorks, err := readLines(cfg.Dork)
			if err != nil {
				console.LogErr("[!] Error reading dorks file: %v", err)
				os.Exit(1)
			}

			if len(dorks) == 0 {
				console.LogErr("[!] No dorks found in file: %s", cfg.Dork)
				os.Exit(1)
			}

			console.Logv(cfg.Verbose, "[Dorks] Loaded %d dorks from file: %s\n", len(dorks), cfg.Dork)

			// Execute each dork
			pipeline.MultiDorkAttack(cfg, ctx, dorks)
		} else {
			// Single dork (direct string)
			res := pipeline.DorkRun(cfg, ctx, "")
			if len(res) == 0 {
				// If cancelled, exit with 130; otherwise, normal notFound behavior
				if ctx.Err() != nil {
					os.Exit(130)
				}
				search.NotFound(cfg)
			} else {
				// Send URLs through proxy if configured
				search.SendURLsThroughProxy(cfg, ctx, res)
				uniqueRes := uniqueStrings(res)
				if cfg.AnalyzeDocuments {
					for _, u := range uniqueRes {
						analysis.AnalyzeDocumentForSensitiveInfo(cfg, ctx, u)
					}
				} else {
					outputOrPrintUnique(uniqueRes, cfg.OutputPath)
				}
				console.Logv(cfg.Verbose, "[Summary] Total unique results: %d", len(uniqueRes))
			}
		}
	}
	tenant.PrintApexSummary(cfg)

	if !ran && cfg.FindApex && cfg.ApexResolved && len(cfg.ApexTargets) > 0 {
		ran = true
	}

	if !ran {
		console.ShowErrorAndExit()
	}
}
