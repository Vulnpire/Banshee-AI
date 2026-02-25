package core

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/utils"
)

const (
	DefaultAPIURL    = "https://www.googleapis.com/customsearch/v1"
	DefaultCX        = "759aed2f7b4be4b83"
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100"
	BraveAPIURL      = "https://api.search.brave.com/res/v1/web/search"

	// Key refresh timing
	googleQuotaResetHour = 0  // Midnight Pacific Time (approximate)
	braveQuotaResetDay   = 1  // 1st of month
	maxWaitMinutes       = 30 // Maximum wait time before retrying
)

type GoogleResponse struct {
	Items []struct {
		Link string `json:"link"`
	} `json:"items"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type BraveResponse struct {
	Web *struct {
		Results []struct {
			URL string `json:"url"`
		} `json:"results"`
	} `json:"web"`
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

// BansheeConfig holds configuration from ~/.config/banshee/.config
type BansheeConfig struct {
	// Search engine settings
	Engine string `config:"engine"`

	// General flags
	Verbose   bool    `config:"verbose"`
	Recursive bool    `config:"recursive"`
	Insecure  bool    `config:"insecure"`
	Pages     int     `config:"pages"`
	Delay     float64 `config:"delay"`
	Workers   int     `config:"workers"`  // Number of parallel workers (default: 5)
	Quantity  int     `config:"quantity"`
	OOSFile   string  `config:"oos-file"` // Path to out-of-scope file

	// AI Enhancement flags
	Model                 string `config:"model"` // AI model to use globally (overridden by CLI --model flag)
	Simplify              bool   `config:"simplify"`
	Research              bool   `config:"research"`
	ResearchDepth         int    `config:"research-depth"`
	Learn                 bool   `config:"learn"`
	Smart                 bool   `config:"smart"`
	SmartTimeout          int    `config:"smart-timeout"` // Timeout in seconds for SMART AI optimization (default: 150)
	Suggestions           bool   `config:"suggestions"`
	NoFollowUp            bool   `config:"no-followup"`
	MaxFollowUp           int    `config:"max-followup"`
	Correlation           bool   `config:"correlation"`
	MaxCorrelation        int    `config:"max-correlation"`
	PatternDetection      bool   `config:"pattern-detection"`
	WAFBypass             bool   `config:"waf-bypass"`
	Save                  bool   `config:"save"`
	IncludeDates          bool   `config:"include-dates"`
	TechDetect            bool   `config:"tech-detect"`
	Adaptive              bool   `config:"adaptive"`
	Deep                  bool   `config:"deep"`
	Scoring               bool   `config:"scoring"`
	Budget                bool   `config:"budget"`
	Flush                 bool   `config:"flush"`
	SuccessfulURLPatterns int    `config:"successful-url-patterns"` // Number of patterns to extract from successful URLs
	MultiLangMultiplier   int    `config:"multi-lang-multiplier"`   // Percentage of dorks to generate in target language
	MonitorTime           int    `config:"monitor-time"`            // Minutes between monitor cycles
}

// SuccessfulURLInfo stores tech detection results for successful URLs
type SuccessfulURLInfo struct {
	URL           string
	TechStack     map[string]interface{} // Technologies detected
	BusinessFocus string                 // Business focus/purpose detected by AI
	ScannedAt     time.Time
}

type Config struct {
	// Inputs and flags
	Target            string
	Pages             int
	Dork              string
	Exclusions        string
	Contents          string
	Delay             float64
	Dictionary        string
	Extension         string
	OutputPath        string
	DomainsFile       string
	Proxy             string
	Insecure          bool // Skip TLS certificate verification (for Burp/proxies)
	IncludeSubdomains bool
	SubdomainMode     bool
	FindApex          bool
	Verbose           bool
	NoColors          bool   // Disable colorful output
	Engine            string // NEW: "both", "google", "brave"

	// Derived
	ExcludeTargets string
	InFile         string
	InUrl          string

	// Keys
	ApiKeys            []string
	ExhaustedKeys      map[string]struct{}
	BraveAPIKeys       []string             // NEW
	ExhaustedBraveKeys map[string]struct{}  // NEW
	BraveKeyLastUsed   map[string]time.Time // NEW: track rate limiting

	// HTTP / runtime
	Client       *http.Client // Client for API requests (no proxy)
	ProxyClient  *http.Client // Client for accessing found URLs (with proxy if set)
	DynamicDelay float64
	RequestStore []string

	// internal flags
	ResultsFound    bool
	RequestCounter  int
	NoResultCounter int

	AiPrompt   string // AI prompt for dork generation
	AiQuantity int    // Number of dorks to generate

	SuppressAIDorkList bool // Suppress AI dork list logging (internal)

	// Monitor mode
	MonitorMode     bool
	MonitorQuery    string
	MonitorMinutes  int
	FilterMonitor   bool
	AnalyzeMonitor  bool
	MonitorDocFocus bool
	MonitorSeenURLs *SafeSet

	Simplify bool // Simplify long prompts

	RandomMode  bool   // Random dork generation mode
	RandomFocus string // Focus area for random dorks (sqli, xss, etc.)
	IgnoreFile  string // File with dorks to ignore

	FlushMode bool // Flush mode - don't use ignore file

	OosFile     string   // Path to out-of-scope file
	OosPatterns []string // Loaded out-of-scope patterns (supports wildcards)

	ResearchMode  bool // OSINT research mode
	ResearchDepth int  // Research depth (1-4)

	CheckLeaks bool   // Check paste sites for leaked credentials
	LeakTarget string // Target domain/file for leak checking
	Keywords   string // Keywords for leak checking (comma-separated)

	LearnMode bool // Enable continuous learning mode

	// AI Enhancement Flags
	SmartMode        bool // Context-aware dork chaining
	SmartTimeout     int  // Timeout in seconds for SMART AI optimization (default: 150)
	ShowSuggestions  bool // Show dork optimization suggestions (requires --smart)
	NoFollowUp       bool // Skip follow-up dork generation (requires --smart)
	MaxFollowUp      int  // Max follow-up dorks to generate (default 5, requires --smart)
	CorrelationMode  bool // Enable multi-layer correlation (requires --smart)
	MaxCorrelation   int  // Max correlation dorks per subdomain (default 10, requires --correlation)
	PatternDetection bool // Detect and exploit naming convention patterns
	SaveMode         bool // Smart pagination with diminishing returns
	IncludeDates     bool // Strategic date operator usage
	TechDetect       bool // Auto-detect tech stack
	AdaptiveMode     bool // Adaptive rate limiting
	DeepMode         bool // Recursive subdomain discovery
	ScoringMode      bool // AI-based result classification and vulnerability scoring
	BudgetMode       bool // Smart query budget optimization (predict before execute)
	WafBypass        bool // Adversarial dork generation (obfuscation, bypass techniques)

	// CVE and Intelligence Management
	UpdateCVEDB           bool   // Update CVE database from NVD API
	CveYear               int    // Filter CVEs by year (only with --update-cve-db)
	CveSeverity           string // Filter CVEs by severity: critical,high,medium,low (only with --update-cve-db)
	CveResultsPerPage     int    // Results per page from NVD API (only with --update-cve-db)
	HasExploit            bool   // Only include CVEs with public exploits (only with --update-cve-db)
	AiDorkGeneration      bool   // Use AI to generate specialized dorks for each CVE (only with --update-cve-db)
	MaxCVEDork            int    // Max number of dorks to generate per CVE (default 10, max 20) (only with --ai-dork-generation)
	NvdAPIKey             string // NVD API key for higher rate limits
	ViewIntel             string // View intelligence for target
	ExportIntel           string // Export intelligence to JSON
	InteractiveMode       bool   // Launch interactive TUI mode
	AnalyzeDocuments      bool   // Automatically analyze found documents (PDF, DOCX, PPTX) for sensitive information
	FilterDocs            bool   // Filter out non-sensitive documents (user guides, manuals, etc.) from analysis (requires --analyze-docs)
	AnalyseOnly           bool   // Skip dorking and only analyze document URLs from stdin (requires --analyze-docs)
	SuccessfulURLPatterns int    // Number of patterns to extract from successful URLs (default: 3)

	// Multi-language and fuzzing support
	MultiLang           bool // Enable multi-language dork generation based on target's language
	MultiLangMultiplier int  // Percentage of dorks to generate in target language
	FuzzMode            bool // Enable advanced fuzzing with dynamic wordlist generation
	MatchCodes          string // Match specific HTTP status codes (comma-separated, like httpx --mc)

	// AI Provider Configuration
	AiModel string // AI model to use (e.g., gemini-2.0-flash-exp, claude-3-5-sonnet, gpt-4)

	// Deduplication
	DedupeMode bool // Enable intelligent deduplication and result clustering

	// Response Analysis
	AnalyzeResponses    bool   // Enable AI-powered response analysis (requires --dedupe and AI)
	AnalyzeResponseOnly bool   // Analyze the response of a specific URL without dorking
	AnalyzeResponseURL  string // URL to analyze for --analyze-response-only
	AnalyzeCodeOnly     bool   // Analyze code from STDIN for security vulnerabilities (no dorking)
	InlineCodeAnalysis  bool   // Extract and analyze inline JavaScript from HTML (requires AI mode)

	// Internal storage for learn mode
	Intelligence       *TargetIntelligence           // Current target intelligence
	SuccessfulURLCache map[string]*SuccessfulURLInfo // Cache of tech detection results for successful URLs

	// AI improvements
	AiCacheManager *utils.AICacheManager // AI response cache manager

	// Concurrency
	Workers int // Number of worker goroutines for parallel processing (default: 5)

	// Wayback Machine Integration
	ForeseeMode          bool                  // Enable AI-powered foresee mode via Wayback Machine intelligence
	WaybackStatusCodes   []string              // Status codes to filter Wayback results (default: all)
	NoWaybackCache       bool                  // Bypass Wayback cache and fetch fresh data
	ClearWaybackCache    bool                  // Clear all Wayback cache and exit
	AutoCleanupCache     bool                  // Auto-cleanup old Wayback cache on every run
	WaybackIntelligence  *WaybackIntelligence  // Stored Wayback intelligence for Smart mode integration

	TargetLanguage string // Detected language of target website

	ApexTargets        []string // Resolved apex domains from --find-apex
	ApexResolved       bool     // Track whether --find-apex resolution ran
	ApexSummaryPrinted bool     // Prevent duplicate summary output
}

// createDefaultConfig creates a default config file with comprehensive documentation
// ensureConfigFields checks if the config file has all required fields and adds missing ones
func ensureConfigFields(configPath string) error {
	// Read existing config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	content := string(data)
	modified := false

	// Define required fields that should be present
	requiredFields := map[string]string{
		"model=":    "# AI model to use for all AI operations\n# Default: empty (uses gemini-2.0-flash-exp as fallback)\n# Examples: gemini-2.0-flash-exp, gemini-1.5-pro, claude-3-5-sonnet, gpt-4\n# NOTE: CLI --model flag will override this setting\n# Leave empty to use the default model\nmodel=\n",
		"oos-file=": "# Path to out-of-scope file (one entry per line, supports wildcards)\n# Default: ~/.config/banshee/oos.txt\n# If file is empty or doesn't exist, this feature is disabled\n# Supports wildcards: *.example.com, subdomain.*.com, example.com/path/*\n# Compatible with bug bounty program scope files\noos-file=~/.config/banshee/oos.txt\n",
		"multi-lang-multiplier=": "# Percentage of dorks to generate in target language when --multi-lang is enabled (0-100)\n# Default: 25\nmulti-lang-multiplier=25\n",
		"monitor-time=": "# Monitor interval in minutes for --monitor mode (controls how often dorking restarts)\n# Default: 60 (1 hour)\nmonitor-time=60\n",
	}

	// Check each required field
	for fieldPrefix, fieldBlock := range requiredFields {
		// Check if field exists (look for the actual assignment, not just the word in comments)
		lines := strings.Split(content, "\n")
		found := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Skip comments
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			// Check if this line starts with the field
			if strings.HasPrefix(trimmed, fieldPrefix) {
				found = true
				break
			}
		}

		if !found {
			// Field is missing, add it after the quantity field (in AI ENHANCEMENT FLAGS section)
			aiSectionMarker := "# AI ENHANCEMENT FLAGS"
			quantityFieldPattern := "quantity="

			// Find the position after quantity field
			aiSectionIdx := strings.Index(content, aiSectionMarker)
			if aiSectionIdx != -1 {
				// Find quantity= after AI section marker
				searchFrom := content[aiSectionIdx:]
				quantityIdx := strings.Index(searchFrom, quantityFieldPattern)
				if quantityIdx != -1 {
					// Find the end of the quantity line
					lineEndIdx := strings.Index(searchFrom[quantityIdx:], "\n")
					if lineEndIdx != -1 {
						insertPos := aiSectionIdx + quantityIdx + lineEndIdx + 1
						// Insert the field block
						content = content[:insertPos] + "\n" + fieldBlock + content[insertPos:]
						modified = true
					}
				}
			}
		}
	}

	// Write back if modified
	if modified {
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			return err
		}
	}

	return nil
}

func createDefaultConfig(configPath string) error {
	configContent := `# Banshee Configuration File
# Location: ~/.config/banshee/.config
#
# This file allows you to set default values for Banshee flags.
# Command-line arguments will override these settings.
#
# Format: key=value
# Boolean values: true/false, yes/no, 1/0, on/off
# Comments start with #

# =============================================================================
# SEARCH ENGINE SETTINGS
# =============================================================================

# Search engine to use: both, google, brave
# Default: both
engine=both

# =============================================================================
# GENERAL FLAGS
# =============================================================================

# Enable verbose output by default
# Default: false
verbose=false

# Enable recursive/aggressive crawling (includes subdomains)
# Default: false
recursive=false

# Skip TLS certificate verification (for Burp Suite and intercepting proxies)
# Default: false
insecure=false

# Number of pages to search per dork
# Default: 10
# Set to 0 to use Banshee's internal logic
pages=10

# Delay in seconds between requests
# Default: 0 (uses adaptive delay when adaptive=true)
# IMPORTANT: Set to 0 if you want adaptive delay adjustments to work
#            Setting a fixed delay (e.g., 2) will disable adaptive mode's dynamic adjustment
# 0 = Use adaptive delay (default 0.25s, adjusts based on response patterns)
# >0 = Fixed delay between all requests (disables adaptive adjustments)
delay=0

# Number of parallel workers for concurrent processing
# Default: 5
# Higher values = faster processing but more resource usage
# Recommended: 3-10 workers depending on system resources
workers=5

# Number of dorks to generate with -ai or -random
# Default: 10
# Valid range: 1-50
quantity=10

# Monitor interval in minutes for --monitor mode
# Default: 60 (reruns dorking every hour)
monitor-time=60

# Path to out-of-scope file (one entry per line, supports wildcards)
# Default: ~/.config/banshee/oos.txt
# If file is empty or doesn't exist, this feature is disabled
# Supports wildcards: *.example.com, subdomain.*.com, example.com/path/*
# Compatible with bug bounty program scope files
oos-file=~/.config/banshee/oos.txt

# =============================================================================
# AI ENHANCEMENT FLAGS
# =============================================================================

# AI model to use for all AI operations
# Default: empty (uses gemini-2.0-flash-exp as fallback)
# Examples: gemini-2.0-flash-exp, gemini-1.5-pro, claude-3-5-sonnet, gpt-4
# NOTE: CLI --model flag will override this setting
# Leave empty to use the default model
model=

# Simplify long AI prompts (removes filler words, may lose context)
# Default: false
# WARNING: May reduce prompt quality for complex queries
simplify=false

# Percentage of dorks to generate in target language when --multi-lang is enabled
# Default: 25
# Range: 0-100 (0 = disable foreign language variants)
multi-lang-multiplier=25

# Enable OSINT research mode
# Default: false
# Requires: -ai or -random flag
# Conducts reconnaissance on target before generating dorks
research=false

# Research depth level (1-4)
# Default: 1
# 1 = Basic company info, known vulnerabilities, tech stack
# 2 = Moderate - detailed security posture, infrastructure
# 3 = Comprehensive - historical analysis and deep profiling
# 4 = Linguistic - organizational intelligence (emails, projects, departments)
research-depth=1

# Enable continuous learning mode
# Default: false
# Saves intelligence to ~/.config/banshee/.intel/<target-hash>.json
# Learns from successful/failed dorks to improve future scans
learn=false

# =============================================================================
# SMART MODE FLAGS
# =============================================================================

# Enable context-aware dork chaining and optimization
# Default: false
# Generates contextual follow-up dorks from discoveries
# Example: Discovers api.example.com → generates: site:api.example.com {original prompt}
smart=false

# Timeout for SMART AI optimization (in seconds)
# Default: 150
# Controls how long to wait for AI analysis during SMART mode optimization
# Increase this if you're seeing timeout errors during complex analyses
smart-timeout=150

# Show dork optimization suggestions
# Default: false
# Requires: smart=true
# Displays [MUTATE], [MERGE], [SPECIALIZE], [NEW] dork improvements
suggestions=false

# Skip follow-up dork generation
# Default: false
# Requires: smart=true
# Useful for quick scans when only initial results are needed
no-followup=false

# Maximum number of follow-up dorks to generate
# Default: 5
# Requires: smart=true
# Controls how many follow-up dorks are generated per discovered subdomain
max-followup=5

# Enable multi-layer correlation analysis
# Default: false
# Requires: smart=true
# Cross-correlates subdomains, paths, file types, and parameters
# Example: subdomain "api" + path "/v1" → site:api.domain.com inurl:v1
correlation=false

# Max correlation dorks per subdomain
# Default: 10
# Requires: correlation=true
# Limits correlation dorks to prevent API quota exhaustion
max-correlation=10

# Pattern detection and exploitation
# Default: false
# Detects naming convention patterns in subdomains/emails
# Example: prod-api-us-east → auto-generates dev-api-*, test-api-*, etc.
# Exploits organizational patterns to find hidden assets
pattern-detection=false

# =============================================================================
# ADVANCED AI FEATURES
# =============================================================================

# Adversarial dork generation with WAF bypass techniques
# Default: false
# Adds URL encoding variations, case mixing, trailing slashes
# Helps bypass WAF/security filters
waf-bypass=false

# Smart pagination - stops when diminishing returns detected
# Default: false
# Saves API quota by detecting when results are no longer unique
# Stops when last 2 pages yield < 5 combined unique results
save=false

# Strategic date operators - targets specific time periods
# Default: false
# Auto-detects company founding year and key events
# Adds after:YYYY before:YYYY to target early infrastructure
include-dates=false

# Auto-detect tech stack and generate specialized dorks
# Default: false
# Detects WordPress → adds wp-admin, wp-json dorks
# Detects Django → adds /admin/, filetype:py dorks
# Detects Laravel → adds .env, /storage dorks
tech-detect=false

# Adaptive rate limiting - adjusts delays based on response patterns
# Default: true
# Fast responses (< 1s) → reduces delay to 0.5s
# Slow responses (> 5s) → increases delay to 10s
# Captcha detected → auto-pauses 30s
adaptive=true

# Recursive subdomain discovery - finds sub-subdomains up to 3 levels
# Default: false
# Level 1: site:*.example.com → api.example.com
# Level 2: site:*.api.example.com → v1.api.example.com
# Level 3: site:*.v1.api.example.com → internal.v1.api.example.com
deep=false

# =============================================================================
# AI-POWERED ANALYSIS (REQUIRES GEMINI API)
# =============================================================================

# AI-based result classification and vulnerability scoring
# Default: false
# WARNING: Requires AI API access (uses gemini-cli)
# Classifies URLs by vulnerability type (SQLi, XSS, sensitive files)
# Assigns severity score (CRITICAL, HIGH, MEDIUM, LOW)
# Identifies asset types (admin panel, API, config file)
scoring=false

# Smart query budget optimization - predicts dork success before execution
# Default: false
# WARNING: Requires AI API access (uses gemini-cli)
# Estimates result probability for each dork
# Calculates cost (API calls) vs. expected value
# Skips low-probability dorks to save API quota
budget=false

# =============================================================================
# RANDOM DORK GENERATION
# =============================================================================

# Flush mode - ignore previously used dorks
# Default: false
# Used with -random to generate fresh dorks (ignores ~/.config/banshee/.ignore.file)
flush=false

# =============================================================================
# SUCCESSFUL URL PATTERN LEARNING
# =============================================================================

# Number of URL patterns to extract from successful URLs
# Default: 3 (set to 0 to disable this feature)
# Analyzes ~/.config/banshee/successful.txt
# Runs tech detection on successful URLs (cached, scanned only once per URL)
# Compares tech stacks: only applies patterns when current target's tech stack matches successful URL
# Limits dork generation to prevent overwhelming results
# Set to 0 to completely disable this feature
successful-url-patterns=3

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================

# Wayback Machine URL cache duration (hours)
# Default: 24 hours
# Location: ~/.config/banshee/.wayback_cache/<domain_hash>.json
# Caches raw Wayback CDX API responses to reduce API load
# Higher values = fewer API calls but potentially outdated historical data
# Set to 0 to disable caching (not recommended, will hit rate limits)
wayback-url-cache-hours=24

# Wayback Intelligence cache duration (days)
# Default: 7 days
# Location: ~/.config/banshee/.intel/<domain>.wayback.json
# Caches processed intelligence (patterns, subdomains, parameters, etc.)
# Higher values = less processing but may miss new patterns
# Set to 0 to always reprocess Wayback data (slower, more API calls)
wayback-intel-cache-days=7

# Worker pool cache size (concurrent jobs)
# Default: 100
# Controls buffer size for parallel processing queue
# Higher values = more memory but better performance for large batches
# Lower values = less memory but may slow down parallel operations
worker-pool-buffer=100

# Response analysis cache duration (hours)
# Default: 48 hours
# Location: ~/.config/banshee/.response_cache/<url_hash>.json
# Caches AI analysis of HTTP responses to avoid reprocessing
# Set to 0 to always reanalyze (slower, more AI API calls)
response-analysis-cache-hours=48

# =============================================================================
# NOTES
# =============================================================================
#
# 1. Command-line flags ALWAYS override config file settings
#    Example: Even if verbose=true here, using -v=false will disable verbose
#
# 2. Some features require AI API access:
#    - scoring (requires gemini-cli)
#    - budget (requires gemini-cli)
#    - smart mode suggestions (requires gemini-cli for optimization)
#
# 3. Recommended configurations:
#
#    FAST SCANS (minimal API usage):
#      pages=5
#      delay=1
#      quantity=5
#      adaptive=true
#      save=true
#
#    COMPREHENSIVE SCANS (thorough results):
#      pages=20
#      delay=2
#      quantity=20
#      smart=true
#      correlation=true
#      deep=true
#      learn=true
#
#    STEALTH SCANS (avoid detection):
#      delay=5
#      adaptive=true
#      waf-bypass=true
#
#    RESEARCH MODE (intelligence gathering):
#      research=true
#      research-depth=3
#      learn=true
#      smart=true
#      correlation=true
#
# 4. Learning mode intelligence storage:
#    - Location: ~/.config/banshee/.intel/<target-hash>.json
#    - Tracks: successful/failed dorks, discovered assets, patterns
#    - Improves: All AI features over time
#
# 5. Ignore file for random dorks:
#    - Location: ~/.config/banshee/.ignore.file
#    - Auto-managed when using -random
#    - Use flush=true to ignore this file
#
# 6. Wayback Machine cache locations:
#    - URL cache: ~/.config/banshee/.wayback_cache/<domain_hash>.json (24h default)
#    - Intelligence: ~/.config/banshee/.intel/<domain>.wayback.json (7d default)
#    - Reduces API calls and improves performance with --foresee flag
#
# =============================================================================
`

	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Write config file
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// LoadConfigFile reads and parses the config file from ~/.config/banshee/.config
func LoadConfigFile() *BansheeConfig {
	config := &BansheeConfig{
		// Set built-in defaults (will be overridden by config file if present)
		Engine:                "both",
		Verbose:               false,
		Recursive:             false,
		Insecure:              false,
		Pages:                 10,
		Delay:                 0, // Must be 0 for adaptive mode to work properly
		Quantity:              10,
		OOSFile:               "~/.config/banshee/oos.txt", // Default out-of-scope file
		Model:                 "",                          // Empty means use default model
		Simplify:              false,
		Research:              false,
		ResearchDepth:         1,
		Learn:                 false,
		Smart:                 false,
		SmartTimeout:          150, // 150 seconds default for SMART AI optimization
		Suggestions:           false,
		NoFollowUp:            false,
		MaxFollowUp:           5,
		Correlation:           false,
		MaxCorrelation:        10,
		PatternDetection:      false,
		WAFBypass:             false,
		Save:                  false,
		IncludeDates:          false,
		TechDetect:            false,
		Adaptive:              true,
		Deep:                  false,
		Scoring:               false,
		Budget:                false,
		Flush:                 false,
		SuccessfulURLPatterns: 3, // Default: 3 patterns from successful URLs
		MonitorTime:           60,
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return config // Return defaults if can't get home dir
	}

	configPath := filepath.Join(home, ".config", "banshee", ".config")

	// If config file doesn't exist, create it with defaults
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := createDefaultConfig(configPath); err != nil {
			// Silently fail - just use in-memory defaults
			return config
		}
		// File created successfully, continue to read it
	} else {
		// Config file exists, ensure it has all required fields
		ensureConfigFields(configPath)
	}

	file, err := os.Open(configPath)
	if err != nil {
		console.LogErr("[!] Warning: Could not read config file %s: %v", configPath, err)
		return config
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			console.LogErr("[!] Warning: Invalid config line %d: %s", lineNum, line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Apply config values
		switch key {
		case "engine":
			config.Engine = value
		case "verbose":
			config.Verbose = parseBool(value)
		case "recursive":
			config.Recursive = parseBool(value)
		case "insecure":
			config.Insecure = parseBool(value)
		case "pages":
			if val, err := parseInt(value); err == nil {
				config.Pages = val
			}
		case "delay":
			if val, err := parseFloat(value); err == nil {
				config.Delay = val
			}
		case "quantity":
			if val, err := parseInt(value); err == nil {
				config.Quantity = val
			}
		case "oos-file":
			config.OOSFile = value
		case "model":
			config.Model = value
		case "simplify":
			config.Simplify = parseBool(value)
		case "research":
			config.Research = parseBool(value)
		case "research-depth":
			if val, err := parseInt(value); err == nil {
				config.ResearchDepth = val
			}
		case "learn":
			config.Learn = parseBool(value)
		case "smart":
			config.Smart = parseBool(value)
		case "smart-timeout":
			if val, err := parseInt(value); err == nil {
				config.SmartTimeout = val
			}
		case "suggestions":
			config.Suggestions = parseBool(value)
		case "no-followup":
			config.NoFollowUp = parseBool(value)
		case "max-followup":
			if val, err := parseInt(value); err == nil {
				config.MaxFollowUp = val
			}
		case "correlation":
			config.Correlation = parseBool(value)
		case "max-correlation":
			if val, err := parseInt(value); err == nil {
				config.MaxCorrelation = val
			}
		case "waf-bypass":
			config.WAFBypass = parseBool(value)
		case "save":
			config.Save = parseBool(value)
		case "include-dates":
			config.IncludeDates = parseBool(value)
		case "tech-detect":
			config.TechDetect = parseBool(value)
		case "adaptive":
			config.Adaptive = parseBool(value)
		case "deep":
			config.Deep = parseBool(value)
		case "scoring":
			config.Scoring = parseBool(value)
		case "budget":
			config.Budget = parseBool(value)
		case "flush":
			config.Flush = parseBool(value)
		case "successful-url-patterns":
			if val, err := parseInt(value); err == nil {
				config.SuccessfulURLPatterns = val
			} else {
				console.LogErr("[!] Warning: Invalid value for successful-url-patterns on line %d: %s", lineNum, value)
			}
		case "multi-lang-multiplier":
			if val, err := parseInt(value); err == nil {
				config.MultiLangMultiplier = val
			} else {
				console.LogErr("[!] Warning: Invalid value for multi-lang-multiplier on line %d: %s", lineNum, value)
			}
		case "monitor-time":
			if val, err := parseInt(value); err == nil {
				config.MonitorTime = val
			} else {
				console.LogErr("[!] Warning: Invalid value for monitor-time on line %d: %s", lineNum, value)
			}
		case "pattern-detection":
			config.PatternDetection = parseBool(value)
		default:
			console.LogErr("[!] Warning: Unknown config option '%s' on line %d", key, lineNum)
		}
	}

	if err := scanner.Err(); err != nil {
		console.LogErr("[!] Warning: Error reading config file: %v", err)
	}

	return config
}

// parseBool parses a boolean value from config
func parseBool(s string) bool {
	s = strings.ToLower(s)
	return s == "true" || s == "1" || s == "yes" || s == "on"
}

// parseInt parses an integer from config
func parseInt(s string) (int, error) {
	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	return val, err
}

// parseFloat parses a float64 from config
func parseFloat(s string) (float64, error) {
	var val float64
	_, err := fmt.Sscanf(s, "%f", &val)
	return val, err
}

// InitializeConfigFiles creates empty config files if they don't exist
// This ensures users have the proper file structure for customization
func InitializeConfigFiles() {
	home, err := os.UserHomeDir()
	if err != nil {
		return // Silently fail if can't get home dir
	}

	configDir := filepath.Join(home, ".config", "banshee")

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return // Silently fail
	}

	// Initialize gemini-api-key.txt if it doesn't exist
	// This file supports Gemini API key rotation (one key per line)
	// Leave empty if using OAuth authentication
	geminiKeyPath := filepath.Join(configDir, "gemini-api-key.txt")
	if _, err := os.Stat(geminiKeyPath); os.IsNotExist(err) {
		content := `# Gemini API Key Configuration
#
# This file supports API key rotation for Gemini AI calls.
# Add one or more API keys, one per line. Banshee will use the first available key.
#
# If you're using OAuth authentication (gemini-cli with OAuth), leave this file empty.
# If you're using API key authentication, add your keys below:
#
# Format:
# YOUR_API_KEY_HERE
# YOUR_BACKUP_KEY_HERE
# YOUR_THIRD_KEY_HERE
#
# Comments start with #
# Empty lines are ignored
`
		os.WriteFile(geminiKeyPath, []byte(content), 0644)
	}

	// Initialize successful.txt if it doesn't exist
	// This file is used by SMART mode to learn from past successful findings
	successfulPath := filepath.Join(configDir, "successful.txt")
	if _, err := os.Stat(successfulPath); os.IsNotExist(err) {
		content := `# Successful/Vulnerable URLs
#
# This file is used by SMART mode (--smart flag) to learn from your past successful findings.
# Add URLs of vulnerable/sensitive/interesting documents and pages you discovered.
#
# SMART mode will:
# - Analyze URL patterns (paths, filenames, parameters, extensions)
# - Identify business focus and tech stack
# - Generate focused dorks based on what worked for this target
#
# Format: One URL per line
# Example:
# https://target.com/admin/config.php
# https://target.com/api/internal/users.json
# https://target.com/financials/2023-Q4-report.pdf
#
# Comments start with #
# Empty lines are ignored
`
		os.WriteFile(successfulPath, []byte(content), 0644)
	}
}
