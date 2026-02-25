package core

import (
	"sync"
	"time"
)

// SafeSet provides concurrency-safe uniqueness tracking.
type SafeSet struct {
	mu sync.Mutex
	m  map[string]struct{}
}

func NewSafeSet() *SafeSet {
	return &SafeSet{m: make(map[string]struct{})}
}

func (s *SafeSet) Add(v string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[v]; ok {
		return false
	}
	s.m[v] = struct{}{}
	return true
}

// Values returns a snapshot of the set's contents.
func (s *SafeSet) Values() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for v := range s.m {
		out = append(out, v)
	}
	return out
}

// TargetIntelligence stores continuous learning data for a target.
type TargetIntelligence struct {
	Target               string                 `json:"target"`
	FirstSeen            time.Time              `json:"first_seen"`
	LastUpdated          time.Time              `json:"last_updated"`
	TotalScans           int                    `json:"total_scans"`
	SuccessfulDorks      []DorkIntelligence     `json:"successful_dorks"`
	FailedDorks          []string               `json:"failed_dorks"`
	DiscoveredSubdomains []string               `json:"discovered_subdomains"`
	DiscoveredPaths      []string               `json:"discovered_paths"`
	DiscoveredFileTypes  []string               `json:"discovered_file_types"`
	TechStack            []string               `json:"tech_stack"`
	CloudAssets          []string               `json:"cloud_assets"`
	Secrets              []SecretPattern        `json:"secrets"`
	APIEndpoints         []string               `json:"api_endpoints"`
	DorkPatterns         map[string]int         `json:"dork_patterns"`
	CommonPaths          map[string]int         `json:"common_paths"`
	SubdomainFirstSeen   map[string]time.Time   `json:"subdomain_first_seen"`
	Statistics           IntelligenceStats      `json:"statistics"`
	SuccessPatterns      []SuccessPattern       `json:"success_patterns"`
	NamingConventions    *NamingConventions     `json:"naming_conventions"`
	IndustryProfile      string                 `json:"industry_profile"`
	DetectedCVEs         []CVEIntelligence      `json:"detected_cves"`
	PatternStatistics    map[string]*PatternStats `json:"pattern_statistics"`
	ResponseFindings     []ResponseFinding      `json:"response_findings"`
	DataFreshness        *IntelligenceFreshness `json:"data_freshness,omitempty"`
	ValidationMetrics    *ValidationMetrics     `json:"validation_metrics,omitempty"`
}

// DorkIntelligence tracks individual dork performance.
type DorkIntelligence struct {
	Dork             string    `json:"dork"`
	ResultCount      int       `json:"result_count"`
	TimesUsed        int       `json:"times_used"`
	LastUsed         time.Time `json:"last_used"`
	Category         string    `json:"category"`
	Pattern          string    `json:"pattern"`
	SuccessRate      float64   `json:"success_rate"`
	IsAIGenerated    bool      `json:"is_ai_generated,omitempty"`
	ValidationStatus string    `json:"validation_status,omitempty"`
	QualityScore     float64   `json:"quality_score,omitempty"`
	EffectivenessROI float64   `json:"effectiveness_roi,omitempty"`
	FirstSeen        time.Time `json:"first_seen,omitempty"`
}

// SecretPattern tracks found secret patterns.
type SecretPattern struct {
	Type    string    `json:"type"`
	Pattern string    `json:"pattern"`
	Found   int       `json:"found"`
	LastSeen time.Time `json:"last_seen"`
}

// IntelligenceStats stores statistical information.
type IntelligenceStats struct {
	TotalResults          int       `json:"total_results"`
	TotalSubdomains       int       `json:"total_subdomains"`
	TotalEndpoints        int       `json:"total_endpoints"`
	TotalSecrets          int       `json:"total_secrets"`
	MostProductiveHour    int       `json:"most_productive_hour"`
	AverageResultsPerDork float64   `json:"average_results_per_dork"`
	BestDorkCategory      string    `json:"best_dork_category"`
}

// SuccessPattern tracks patterns extracted from successful results.
type SuccessPattern struct {
	Pattern      string    `json:"pattern"`
	Path         string    `json:"path"`
	Parameter    string    `json:"parameter"`
	FileType     string    `json:"file_type"`
	Context      string    `json:"context"`
	SuccessCount int       `json:"success_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// NamingConventions tracks detected naming patterns.
type NamingConventions struct {
	SubdomainPattern string   `json:"subdomain_pattern"`
	SubdomainExample []string `json:"subdomain_example"`
	EmailPattern     string   `json:"email_pattern"`
	EmailExample     []string `json:"email_example"`
	Environments     []string `json:"environments"`
	Services         []string `json:"services"`
	Regions          []string `json:"regions"`
	Confidence       float64  `json:"confidence"`
}

// CVEIntelligence tracks detected CVEs for technologies.
type CVEIntelligence struct {
	Technology  string    `json:"technology"`
	Version     string    `json:"version"`
	CVEList     []string  `json:"cve_list"`
	Severity    string    `json:"severity"`
	LastChecked time.Time `json:"last_checked"`
}

// PatternStats tracks detailed statistics for dork patterns.
type PatternStats struct {
	Pattern          string    `json:"pattern"`
	TimesUsed        int       `json:"times_used"`
	SuccessCount     int       `json:"success_count"`
	SuccessRate      float64   `json:"success_rate"`
	TotalResults     int       `json:"total_results"`
	AvgResults       float64   `json:"avg_results"`
	LastSuccess      time.Time `json:"last_success"`
	FirstUsed        time.Time `json:"first_used"`
	ValidationCount  int       `json:"validation_count,omitempty"`
	ConfirmedCount   int       `json:"confirmed_count,omitempty"`
	ConfidenceScore  float64   `json:"confidence_score,omitempty"`
	LastValidated    time.Time `json:"last_validated,omitempty"`
}

// IndustryIntelligence stores global industry patterns (shared across all targets).
type IndustryIntelligence struct {
	Industry        string               `json:"industry"`
	TargetCount     int                  `json:"target_count"`
	CommonPaths     map[string]int       `json:"common_paths"`
	CommonTech      map[string]int       `json:"common_tech"`
	SuccessPatterns []IndustryPattern    `json:"success_patterns"`
	LastUpdated     time.Time            `json:"last_updated"`
}

// IndustryPattern tracks successful patterns for an industry.
type IndustryPattern struct {
	Pattern     string  `json:"pattern"`
	Frequency   int     `json:"frequency"`
	SuccessRate float64 `json:"success_rate"`
	Description string  `json:"description"`
}

// ResponseFinding captures sensitive discoveries from response analysis.
type ResponseFinding struct {
	URL            string    `json:"url"`
	Summary        string    `json:"summary"`
	Priority       string    `json:"priority"`
	SensitiveTypes []string  `json:"sensitive_types,omitempty"`
	FoundAt        time.Time `json:"found_at"`
}

// IntelligenceFreshness tracks TTL and freshness for different data types.
type IntelligenceFreshness struct {
	SubdomainsUpdated time.Time `json:"subdomains_updated"`
	TechStackUpdated  time.Time `json:"tech_stack_updated"`
	DorksUpdated      time.Time `json:"dorks_updated"`
	PatternsUpdated   time.Time `json:"patterns_updated"`
	SubdomainsTTL     int       `json:"subdomains_ttl"`
	TechStackTTL      int       `json:"tech_stack_ttl"`
	DorksTTL          int       `json:"dorks_ttl"`
	PatternsTTL       int       `json:"patterns_ttl"`
}

// ValidationMetrics tracks pattern validation and confidence.
type ValidationMetrics struct {
	TotalPatterns     int                `json:"total_patterns"`
	ValidatedPatterns int                `json:"validated_patterns"`
	HighConfidence    int                `json:"high_confidence"`
	LowConfidence     int                `json:"low_confidence"`
	PrunedPatterns    int                `json:"pruned_patterns"`
	LastValidation    time.Time          `json:"last_validation"`
	PatternConfidence map[string]float64 `json:"pattern_confidence"`
}

// LinguisticIntelligence stores company-specific terminology and patterns.
type LinguisticIntelligence struct {
	EmailDomain     string
	ProjectNames    []string
	DepartmentTerms []string
	Jargon          []string
	ProductNames    []string
	Subsidiaries    []string
	Technologies    []string
	EmployeeNames   []string
	InternalTerms   map[string]string
	Industry        string
	Acquisitions    []string
	Partnerships    []string
	Locations       []string
}

// WaybackIntelligence contains all extracted intelligence from Wayback.
type WaybackIntelligence struct {
	Domain            string              `json:"domain"`
	Subdomains        []string            `json:"subdomains"`
	SensitivePaths    []string            `json:"sensitive_paths"`
	Parameters        map[string][]string `json:"parameters"`
	FilePatterns      map[string][]string `json:"file_patterns"`
	DirectoryPatterns []DirectoryPattern  `json:"directory_patterns"`
	TechStack         []string            `json:"tech_stack"`
	APIEndpoints      []string            `json:"api_endpoints"`
	TemporalPatterns  []TemporalPattern   `json:"temporal_patterns"`
	AdminPaths        []string            `json:"admin_paths"`
	BackupFiles       []string            `json:"backup_files"`
	ConfigFiles       []string            `json:"config_files"`
	TotalURLs         int                 `json:"total_urls"`
	ProcessedAt       time.Time           `json:"processed_at"`
}

// DirectoryPattern represents a discovered directory structure pattern.
type DirectoryPattern struct {
	Template  string   `json:"template"`
	Variables []string `json:"variables"`
	Examples  []string `json:"examples"`
	Count     int      `json:"count"`
}

// TemporalPattern represents time-based patterns in URLs.
type TemporalPattern struct {
	Pattern      string    `json:"pattern"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	MissingYears []int     `json:"missing_years"`
	SeenYears    []int     `json:"seen_years"`
}
