package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AICache represents cached AI responses.
type AICache struct {
	Prompt     string    `json:"prompt"`
	Response   string    `json:"response"`
	Model      string    `json:"model"`
	CachedAt   time.Time `json:"cached_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	TokensUsed int       `json:"tokens_used"`
	HitCount   int       `json:"hit_count"`
}

// AICacheManager handles AI response caching
type AICacheManager struct {
	cache        map[string]*AICache
	cacheFile    string
	cacheTTL     time.Duration
	maxCacheSize int
}

// NewAICacheManager creates a new AI cache manager
func NewAICacheManager(configDir string) *AICacheManager {
	cacheFile := filepath.Join(configDir, ".ai_cache.json")
	manager := &AICacheManager{
		cache:        make(map[string]*AICache),
		cacheFile:    cacheFile,
		cacheTTL:     24 * time.Hour, // 24 hour TTL
		maxCacheSize: 1000,            // Max 1000 cached responses
	}

	// Load existing cache
	manager.loadCache()

	return manager
}

// loadCache loads cached responses from disk
func (m *AICacheManager) loadCache() error {
	if !fileExists(m.cacheFile) {
		return nil
	}

	data, err := os.ReadFile(m.cacheFile)
	if err != nil {
		return err
	}

	var cacheData map[string]*AICache
	if err := json.Unmarshal(data, &cacheData); err != nil {
		return err
	}

	// Load only non-expired cache entries
	now := time.Now()
	for key, entry := range cacheData {
		if now.Before(entry.ExpiresAt) {
			m.cache[key] = entry
		}
	}

	return nil
}

// saveCache persists cache to disk
func (m *AICacheManager) saveCache() error {
	// Clean expired entries before saving
	m.cleanExpired()

	data, err := json.MarshalIndent(m.cache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.cacheFile, data, 0644)
}

// generateCacheKey creates a unique cache key from prompt and model
func (m *AICacheManager) generateCacheKey(prompt, model string) string {
	// Normalize prompt (trim whitespace, lowercase)
	normalizedPrompt := strings.ToLower(strings.TrimSpace(prompt))

	// Create hash
	hash := sha256.Sum256([]byte(normalizedPrompt + "|" + model))
	return hex.EncodeToString(hash[:])
}

// Get retrieves a cached response if available and not expired
func (m *AICacheManager) Get(prompt, model string) (string, bool) {
	key := m.generateCacheKey(prompt, model)

	entry, exists := m.cache[key]
	if !exists {
		return "", false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		delete(m.cache, key)
		return "", false
	}

	// Update hit count
	entry.HitCount++

	return entry.Response, true
}

// Set stores a new AI response in cache
func (m *AICacheManager) Set(prompt, response, model string, tokensUsed int) {
	key := m.generateCacheKey(prompt, model)

	now := time.Now()
	m.cache[key] = &AICache{
		Prompt:     prompt,
		Response:   response,
		Model:      model,
		CachedAt:   now,
		ExpiresAt:  now.Add(m.cacheTTL),
		TokensUsed: tokensUsed,
		HitCount:   0,
	}

	// Enforce max cache size (LRU-style)
	if len(m.cache) > m.maxCacheSize {
		m.evictOldest()
	}

	// Save to disk
	m.saveCache()
}

// cleanExpired removes expired cache entries
func (m *AICacheManager) cleanExpired() int {
	now := time.Now()
	cleaned := 0

	for key, entry := range m.cache {
		if now.After(entry.ExpiresAt) {
			delete(m.cache, key)
			cleaned++
		}
	}

	return cleaned
}

// evictOldest removes the oldest cache entries to stay under max size
func (m *AICacheManager) evictOldest() {
	if len(m.cache) <= m.maxCacheSize {
		return
	}

	// Find oldest entries
	type cacheEntry struct {
		key       string
		cachedAt  time.Time
		hitCount  int
	}

	entries := []cacheEntry{}
	for key, cache := range m.cache {
		entries = append(entries, cacheEntry{
			key:      key,
			cachedAt: cache.CachedAt,
			hitCount: cache.HitCount,
		})
	}

	// Sort by hit count (ascending) then by age (oldest first)
	// Remove entries with low hit counts and old age
	toRemove := len(m.cache) - m.maxCacheSize + 100 // Remove extra to avoid frequent evictions

	for i := 0; i < toRemove && i < len(entries); i++ {
		// Prioritize removing old, low-hit entries
		oldest := entries[0]
		for _, entry := range entries {
			if entry.hitCount < oldest.hitCount ||
			   (entry.hitCount == oldest.hitCount && entry.cachedAt.Before(oldest.cachedAt)) {
				oldest = entry
			}
		}
		delete(m.cache, oldest.key)
	}
}

// GetStats returns cache statistics
func (m *AICacheManager) GetStats() map[string]interface{} {
	totalEntries := len(m.cache)
	totalHits := 0
	totalTokensSaved := 0

	for _, entry := range m.cache {
		totalHits += entry.HitCount
		totalTokensSaved += entry.TokensUsed * entry.HitCount
	}

	return map[string]interface{}{
		"total_entries":    totalEntries,
		"total_cache_hits": totalHits,
		"tokens_saved":     totalTokensSaved,
		"cache_ttl_hours":  m.cacheTTL.Hours(),
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DorkPromptTemplates provides pre-built, optimized prompts for common operations
var DorkPromptTemplates = map[string]string{
	"admin_panels": `Generate {count} Google dorks to find admin panels and login pages for {target}.
Focus on:
- Common admin paths (/admin, /administrator, /login, /dashboard)
- CMS admin panels (WordPress, Drupal, Joomla)
- Admin parameter patterns (?admin=, ?user=admin)
- Authentication endpoints
Use operators: site:, inurl:, intitle:, intext:
Format: One dork per line, no numbering or explanations.`,

	"api_endpoints": `Generate {count} Google dorks to discover API endpoints for {target}.
Focus on:
- REST API paths (/api/, /v1/, /v2/, /graphql)
- API documentation (swagger, openapi, api-docs)
- API keys and tokens
- JSON/XML responses
Use operators: site:, inurl:, filetype:, ext:
Format: One dork per line, no numbering or explanations.`,

	"sensitive_files": `Generate {count} Google dorks to find sensitive files and documents for {target}.
Focus on:
- Configuration files (.env, config.php, settings.json)
- Backup files (.bak, .old, .backup, .sql)
- Log files (.log)
- Database exports (.sql, .db)
Use operators: site:, filetype:, ext:, inurl:
Format: One dork per line, no numbering or explanations.`,

	"cloud_storage": `Generate {count} Google dorks to find exposed cloud storage for {target}.
Focus on:
- AWS S3 buckets (s3.amazonaws.com)
- Azure Blob Storage (blob.core.windows.net)
- Google Cloud Storage (storage.googleapis.com)
- Digital Ocean Spaces
Use operators: site:, inurl:, intext:
Format: One dork per line, no numbering or explanations.`,

	"subdomains": `Generate {count} Google dorks to enumerate subdomains for {target}.
Focus on:
- Common subdomain patterns (dev, staging, test, api, admin)
- Environment-specific subdomains
- Geographic subdomains
- Service-specific subdomains
Use operators: site:, inurl:
Format: One dork per line, no numbering or explanations.`,

	"exposed_data": `Generate {count} Google dorks to find exposed sensitive data for {target}.
Focus on:
- Email addresses and contact information
- Employee information
- Credentials and passwords
- API keys and tokens
- PII (personal identifiable information)
Use operators: site:, intext:, inurl:, filetype:
Format: One dork per line, no numbering or explanations.`,

	"technology_fingerprinting": `Generate {count} Google dorks to fingerprint technologies used by {target}.
Focus on:
- Web servers (Apache, Nginx, IIS)
- Frameworks (Laravel, Django, Rails, Express)
- CMS platforms (WordPress, Drupal, Joomla)
- JavaScript libraries and frameworks
Use operators: site:, intext:, intitle:
Format: One dork per line, no numbering or explanations.`,
}

// GetPromptTemplate returns a template filled with target and count
func GetPromptTemplate(templateName, target string, count int) (string, error) {
	template, exists := DorkPromptTemplates[templateName]
	if !exists {
		return "", fmt.Errorf("template '%s' not found", templateName)
	}

	// Replace placeholders
	prompt := strings.ReplaceAll(template, "{target}", target)
	prompt = strings.ReplaceAll(prompt, "{count}", fmt.Sprintf("%d", count))

	return prompt, nil
}

// ListPromptTemplates returns all available template names with descriptions
func ListPromptTemplates() map[string]string {
	return map[string]string{
		"admin_panels":              "Find admin panels and login pages",
		"api_endpoints":             "Discover API endpoints and documentation",
		"sensitive_files":           "Find configuration files, backups, and logs",
		"cloud_storage":             "Discover exposed cloud storage buckets",
		"subdomains":                "Enumerate subdomains and related domains",
		"exposed_data":              "Find exposed sensitive data and credentials",
		"technology_fingerprinting": "Fingerprint technologies and frameworks",
	}
}

// OptimizePrompt compresses a prompt while preserving context
func OptimizePrompt(prompt string) string {
	// Remove redundant whitespace
	prompt = strings.Join(strings.Fields(prompt), " ")

	// Remove common filler words while preserving meaning
	fillerWords := []string{
		" please ", " kindly ", " could you ", " would you ",
		" I would like ", " I want ", " can you ",
	}

	lower := strings.ToLower(prompt)
	for _, filler := range fillerWords {
		lower = strings.ReplaceAll(lower, filler, " ")
	}

	// Rebuild with cleaned content
	words := strings.Fields(lower)
	optimized := strings.Join(words, " ")

	// Capitalize first letter
	if len(optimized) > 0 {
		optimized = strings.ToUpper(string(optimized[0])) + optimized[1:]
	}

	return optimized
}
