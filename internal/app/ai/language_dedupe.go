package ai

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// detectTargetLanguage detects the primary language of the target website
func (cfg *Config) detectTargetLanguage(ctx context.Context) string {
	if cfg.Target == "" {
		return "en"
	}

	// Try to fetch the homepage and detect language
	url := "https://" + cfg.Target

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		console.Logv(cfg.Verbose, "[MULTI-LANG] Failed to create request: %v", err)
		return cfg.detectLanguageWithAI(ctx, "")
	}
	req.Header.Set("User-Agent", core.DefaultUserAgent)

	client := cfg.ProxyClient
	if client == nil {
		client = cfg.Client
	}
	if client == nil {
		console.Logv(cfg.Verbose, "[MULTI-LANG] No HTTP client available")
		return "en"
	}

	resp, err := client.Do(req)
	if err != nil {
		console.Logv(cfg.Verbose, "[MULTI-LANG] Failed to fetch homepage: %v", err)
		return cfg.detectLanguageWithAI(ctx, "")
	}
	defer resp.Body.Close()

	// METHOD 1: Check Content-Language HTTP header
	if contentLang := resp.Header.Get("Content-Language"); contentLang != "" {
		// Extract language code (e.g., "en-US" -> "en")
		if len(contentLang) >= 2 {
			langCode := strings.ToLower(contentLang[:2])
			console.Logv(cfg.Verbose, "[MULTI-LANG] Detected from HTTP header: %s", langCode)
			return langCode
		}
	}

	// Read first 10KB of response for HTML analysis
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10240))
	if err != nil {
		console.Logv(cfg.Verbose, "[MULTI-LANG] Failed to read response body: %v", err)
		return "en"
	}
	body := string(bodyBytes)

	// METHOD 2: Check lang attribute in HTML tag (improved regex - more flexible)
	langPatterns := []string{
		`<html[^>]*\slang=["']([a-zA-Z]{2})(?:-[a-zA-Z]{2})?["']`, // lang="en-US" or lang="en"
		`<html[^>]*\slang=([a-zA-Z]{2})(?:-[a-zA-Z]{2})?\s`,       // lang=en-US or lang=en (no quotes)
		`<html[^>]*\slang=["']([a-zA-Z]{2})["']`,                  // lang="en"
		`<html[^>]*\slang=([a-zA-Z]{2})\s`,                        // lang=en (no quotes, followed by space)
	}
	for _, pattern := range langPatterns {
		langRegex := regexp.MustCompile(pattern)
		if matches := langRegex.FindStringSubmatch(body); len(matches) > 1 {
			langCode := strings.ToLower(matches[1])
			return langCode
		}
	}

	// METHOD 3: Check meta content-language (improved)
	metaLangPatterns := []string{
		`<meta[^>]*http-equiv=["']?content-language["']?[^>]*content=["']([a-zA-Z]{2})(?:-[a-zA-Z]{2})?["']`,
		`<meta[^>]*content=["']([a-zA-Z]{2})(?:-[a-zA-Z]{2})?["'][^>]*http-equiv=["']?content-language["']?`,
	}
	for _, pattern := range metaLangPatterns {
		metaLangRegex := regexp.MustCompile(pattern)
		if matches := metaLangRegex.FindStringSubmatch(body); len(matches) > 1 {
			langCode := strings.ToLower(matches[1])
			console.Logv(cfg.Verbose, "[MULTI-LANG] Detected from meta content-language: %s", langCode)
			return langCode
		}
	}

	// METHOD 4: Check og:locale meta tag (OpenGraph)
	ogLocaleRegex := regexp.MustCompile(`<meta[^>]*property=["']og:locale["'][^>]*content=["']([a-zA-Z]{2})(?:_[a-zA-Z]{2})?["']`)
	if matches := ogLocaleRegex.FindStringSubmatch(body); len(matches) > 1 {
		langCode := strings.ToLower(matches[1])
		console.Logv(cfg.Verbose, "[MULTI-LANG] Detected from og:locale: %s", langCode)
		return langCode
	}

	// METHOD 5: Check for common language-specific keywords in body
	langCode := cfg.detectLanguageFromContent(body)
	if langCode != "" && langCode != "en" {
		console.Logv(cfg.Verbose, "[MULTI-LANG] Detected from content Keywords: %s", langCode)
		return langCode
	}

	// METHOD 6: Fallback to AI-based detection using content sample
	if cfg.AiPrompt != "" { // Only if AI is available
		langCode := cfg.detectLanguageWithAI(ctx, body)
		if langCode != "" && langCode != "en" {
			console.Logv(cfg.Verbose, "[MULTI-LANG] Detected from AI analysis: %s", langCode)
			return langCode
		}
	}

	// METHOD 7 (Tier 3): Last resort - AI company language research based on domain
	if cfg.AiPrompt != "" { // Only if AI is available
		langCode := cfg.detectCompanyLanguageWithAI(ctx, cfg.Target)
		if langCode != "" && langCode != "en" {
			console.Logv(cfg.Verbose, "[MULTI-LANG] Detected from AI company research (tier 3): %s", langCode)
			return langCode
		}
	}

	// Default to English if all methods fail
	console.Logv(cfg.Verbose, "[MULTI-LANG] All detection methods failed, defaulting to English")
	return "en"
}

// detectLanguageFromContent analyzes HTML content for language-specific patterns
func (cfg *Config) detectLanguageFromContent(body string) string {
	// Common words/patterns in different languages (using more specific terms to avoid false positives)
	languagePatterns := map[string][]string{
		"es": {"español", "página", "también", "información", "últimas", "noticias", "servicios"},
		"fr": {"français", "également", "première", "société", "accueil", "être", "nouvelles"},
		"de": {"deutsch", "über", "können", "wurden", "müssen", "nachrichten", "unternehmen"},
		"it": {"italiano", "anche", "nella", "essere", "tutto", "notizie", "servizi"},
		"pt": {"português", "também", "sobre", "todos", "podem", "notícias", "serviços"},
		"ru": {"русский", "также", "более", "который", "может", "года", "новости"},
		"ja": {"日本語", "について", "ください", "こちら", "サイト", "ニュース", "会社"},
		"zh": {"中文", "网站", "关于", "信息", "更多", "新闻", "公司"},
		"ar": {"العربية", "حول", "معلومات", "المزيد", "اتصل", "أخبار"},
		"nl": {"nederlands", "vandaag", "wij", "zijn", "heeft", "worden", "nieuwsberichten"},
		"pl": {"polski", "również", "więcej", "informacje", "wiadomości", "firma"},
		"tr": {"türkçe", "hakkında", "bilgi", "iletişim", "haberler", "şirket"},
		"ko": {"한국어", "정보", "연락", "사이트", "대해", "뉴스"},
	}

	bodyLower := strings.ToLower(body)
	langScores := make(map[string]int)

	for lang, keywords := range languagePatterns {
		score := 0
		for _, keyword := range keywords {
			if strings.Contains(bodyLower, keyword) {
				score++
			}
		}
		if score > 0 {
			langScores[lang] = score
		}
	}

	// Find language with highest score
	maxScore := 0
	detectedLang := ""
	for lang, score := range langScores {
		if score > maxScore {
			maxScore = score
			detectedLang = lang
		}
	}

	// Only return if we have sufficient confidence (at least 4 keyword matches to prevent false positives)
	if maxScore >= 4 {
		return detectedLang
	}

	return ""
}

// detectLanguageWithAI uses AI to detect language from content sample
func (cfg *Config) detectLanguageWithAI(ctx context.Context, content string) string {
	// Only use AI if available and we have content
	if cfg.AiPrompt == "" || content == "" {
		return "en"
	}

	// Create a small content sample (first 500 chars to save on API quota)
	sample := content
	if len(sample) > 500 {
		sample = sample[:500]
	}

	systemPrompt := "You are a language detection expert. Analyze the provided text and return ONLY the ISO 639-1 two-letter language code (e.g., 'en', 'es', 'fr', 'de', etc.). Return nothing else, just the language code."
	userPrompt := fmt.Sprintf("Detect the language of this text:\n\n%s", sample)

	result, err := cfg.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		console.Logv(cfg.Verbose, "[MULTI-LANG] AI language detection failed: %v", err)
		return "en"
	}

	// Extract language code (should be 2 letters)
	langCode := strings.TrimSpace(strings.ToLower(result))
	if len(langCode) == 2 {
		return langCode
	}

	// If response is longer, try to extract 2-letter code
	words := strings.Fields(langCode)
	for _, word := range words {
		word = strings.Trim(word, "\"'.,;:")
		if len(word) == 2 {
			return strings.ToLower(word)
		}
	}

	return "en"
}

// detectCompanyLanguageWithAI uses AI to research the company's primary language (tier 3 fallback)
func (cfg *Config) detectCompanyLanguageWithAI(ctx context.Context, domain string) string {
	// Only use AI if available
	if cfg.AiPrompt == "" || domain == "" {
		return "en"
	}

	systemPrompt := "You are a business research expert. Based on the company domain name provided, determine the primary language used by that company/organization. Return ONLY the ISO 639-1 two-letter language code (e.g., 'en', 'es', 'fr', 'de', etc.). Return nothing else, just the language code."
	userPrompt := fmt.Sprintf("What is the primary language used by the company/organization at domain: %s\n\nConsider: company headquarters location, primary market, regional focus. Return only the 2-letter language code.", domain)

	result, err := cfg.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		console.Logv(cfg.Verbose, "[MULTI-LANG] AI company language research failed: %v", err)
		return "en"
	}

	// Extract language code (should be 2 letters)
	langCode := strings.TrimSpace(strings.ToLower(result))
	if len(langCode) == 2 {
		console.Logv(cfg.Verbose, "[MULTI-LANG] AI researched company language: %s", langCode)
		return langCode
	}

	// If response is longer, try to extract 2-letter code
	words := strings.Fields(langCode)
	for _, word := range words {
		word = strings.Trim(word, "\"'.,;:")
		if len(word) == 2 {
			console.Logv(cfg.Verbose, "[MULTI-LANG] AI researched company language: %s", strings.ToLower(word))
			return strings.ToLower(word)
		}
	}

	return "en"
}

// URLSignature represents a normalized URL for deduplication
type URLSignature struct {
	scheme    string
	host      string
	path      string
	paramKeys []string // sorted parameter keys (without values)
	hasParams bool
	original  string
	priority  int // Higher priority = more important
}

// intelligentDedupe performs intelligent deduplication with semantic analysis
func (cfg *Config) intelligentDedupe(urls []string) []string {
	if !cfg.DedupeMode || len(urls) == 0 {
		return urls
	}

	// Dedupe process is silent - results shown in final count

	signatures := make(map[string]*URLSignature)
	urlToSig := make(map[string]string) // original URL -> signature key

	for _, urlStr := range urls {
		sig := cfg.createURLSignature(urlStr)
		if sig == nil {
			continue
		}

		// Create signature key for grouping
		sigKey := cfg.getSignatureKey(sig)

		// Keep the highest priority URL for each signature
		if existing, exists := signatures[sigKey]; exists {
			if sig.priority > existing.priority {
				signatures[sigKey] = sig
				urlToSig[sig.original] = sigKey
			}
		} else {
			signatures[sigKey] = sig
			urlToSig[sig.original] = sigKey
		}
	}

	// Collect unique URLs (highest priority per signature)
	uniqueURLs := make([]string, 0, len(signatures))
	clustered := make(map[string]int) // signature -> count of variants

	for _, url := range urls {
		sigKey, ok := urlToSig[url]
		if !ok {
			uniqueURLs = append(uniqueURLs, url)
			continue
		}

		sig := signatures[sigKey]
		if sig.original == url {
			uniqueURLs = append(uniqueURLs, url)
			clustered[sigKey]++
		} else {
			clustered[sigKey]++
		}
	}

	// Show dedupe results with cleaner message when no clustering occurred
	variantCount := len(urls) - len(uniqueURLs)
	if variantCount == 0 {
		console.Logv(cfg.Verbose, "[DEDUPE] No variants clustered")
	} else {
		console.Logv(cfg.Verbose, "[DEDUPE] Reduced %d URLs to %d unique endpoints (%d variants clustered)",
			len(urls), len(uniqueURLs), variantCount)
	}

	// Show clustering stats if verbose
	if cfg.Verbose && len(clustered) > 0 {
		highClusters := 0
		for _, count := range clustered {
			if count > 5 {
				highClusters++
			}
		}
		if highClusters > 0 {
			console.Logv(cfg.Verbose, "[DEDUPE] Found %d high-value clusters (>5 variants each)", highClusters)
		}
	}

	return uniqueURLs
}

// createURLSignature creates a signature for URL deduplication (uro-compatible)
func (cfg *Config) createURLSignature(urlStr string) *URLSignature {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	// Normalize scheme (treat http and https as same, like uro)
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "http" || scheme == "https" {
		scheme = "http" // Normalize both to http for deduplication
	}

	sig := &URLSignature{
		scheme:   scheme,
		host:     strings.ToLower(parsed.Host),
		path:     strings.ToLower(parsed.Path),
		original: urlStr,
		priority: cfg.calculateURLPriority(urlStr, parsed),
	}

	// Normalize path: remove trailing slashes for comparison (uro behavior)
	sig.path = strings.TrimSuffix(sig.path, "/")
	// Handle empty path
	if sig.path == "" {
		sig.path = "/"
	}

	// Extract parameter keys (without values) for semantic deduplication (uro behavior)
	// This is the key feature of uro: URLs with same param keys but different values are considered duplicates
	if parsed.RawQuery != "" {
		sig.hasParams = true
		params, _ := url.ParseQuery(parsed.RawQuery)
		keys := make([]string, 0, len(params))
		for k := range params {
			// Normalize parameter keys to lowercase
			keys = append(keys, strings.ToLower(k))
		}
		// Sort keys for consistent signature (essential for uro-like deduplication)
		sort.Strings(keys)
		sig.paramKeys = keys
	}

	return sig
}

// getSignatureKey creates a unique key for grouping similar URLs
func (cfg *Config) getSignatureKey(sig *URLSignature) string {
	// Normalize CDN/mirror hosts
	normalizedHost := cfg.normalizeCDNHost(sig.host)

	// Create key from: normalized_host + normalized_path + param_keys
	key := normalizedHost + "|" + sig.path

	if sig.hasParams && len(sig.paramKeys) > 0 {
		key += "|" + strings.Join(sig.paramKeys, ",")
	}

	return key
}

// normalizeCDNHost normalizes CDN and mirror hosts to main domain
func (cfg *Config) normalizeCDNHost(host string) string {
	// Remove common CDN prefixes
	cdnPrefixes := []string{"cdn.", "cdn1.", "cdn2.", "cdn3.", "static.", "assets.", "media.", "img.", "images."}
	for _, prefix := range cdnPrefixes {
		if strings.HasPrefix(host, prefix) {
			return strings.TrimPrefix(host, prefix)
		}
	}

	// Remove wayback machine hosts
	if strings.Contains(host, "web.archive.org") {
		return "archive"
	}

	return host
}

// calculateURLPriority assigns priority score to URLs for smart ranking
func (cfg *Config) calculateURLPriority(urlStr string, parsed *url.URL) int {
	priority := 100 // Base priority

	lower := strings.ToLower(urlStr)

	// High-value keywords (increase priority)
	highValueKeywords := []string{
		"admin", "login", "api", "config", "dashboard", "panel",
		"backup", "database", "private", "internal", "secret",
		"upload", "credential", "token", "password", "key",
		"jenkins", "phpmyadmin", "swagger", "grafana", "kibana",
	}
	for _, kw := range highValueKeywords {
		if strings.Contains(lower, kw) {
			priority += 50
			break
		}
	}

	// Specific file types (increase priority)
	highValueExts := []string{".env", ".config", ".sql", ".bak", ".backup", ".old", ".zip", ".tar.gz"}
	for _, ext := range highValueExts {
		if strings.HasSuffix(lower, ext) {
			priority += 30
			break
		}
	}

	// Penalize common low-value paths
	lowValueKeywords := []string{"css", "js", "img", "image", "font", "static", "asset", "public", "vendor"}
	for _, kw := range lowValueKeywords {
		if strings.Contains(lower, kw) {
			priority -= 20
			break
		}
	}

	// Penalize URLs with many pagination parameters
	if parsed.RawQuery != "" {
		params, _ := url.ParseQuery(parsed.RawQuery)
		paginationParams := []string{"page", "p", "offset", "start", "skip"}
		for _, pp := range paginationParams {
			if _, ok := params[pp]; ok {
				priority -= 10
				break
			}
		}
	}

	// Prefer HTTPS over HTTP
	if parsed.Scheme == "https" {
		priority += 5
	}

	return priority
}

// matchesStatusCode checks if a status code matches the --mc filter
func matchesStatusCode(statusCode int, matchCodes string) bool {
	if matchCodes == "" {
		return true // No filter, accept all
	}

	codes := strings.Split(matchCodes, ",")
	codeStr := strconv.Itoa(statusCode)

	for _, code := range codes {
		code = strings.TrimSpace(code)
		if code == codeStr {
			return true
		}
	}

	return false
}

// checkURLStatus checks the HTTP status of a URL
func (cfg *Config) checkURLStatus(ctx context.Context, urlStr string) int {
	req, err := http.NewRequestWithContext(ctx, "HEAD", urlStr, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", core.DefaultUserAgent)

	client := cfg.ProxyClient
	if client == nil {
		client = cfg.Client
	}
	if client == nil {
		return 0
	}

	resp, err := client.Do(req)
	if err != nil {
		// Try GET if HEAD fails
		req, err = http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			return 0
		}
		req.Header.Set("User-Agent", core.DefaultUserAgent)
		resp, err = client.Do(req)
		if err != nil {
			return 0
		}
	}
	defer resp.Body.Close()

	return resp.StatusCode
}

// generateMultiLangDorks generates dorks with multi-language support
func (cfg *Config) generateMultiLangDorks(ctx context.Context, baseDorks []string, language string) []string {
	if !cfg.MultiLang || language == "en" || len(baseDorks) == 0 {
		return baseDorks
	}

	// Language-specific keywords mapping
	langKeywords := map[string]map[string]string{
		"fr": { // French
			"admin":         "administrateur",
			"login":         "connexion",
			"password":      "mot de passe",
			"user":          "utilisateur",
			"configuration": "configuration",
			"dashboard":     "tableau de bord",
			"file":          "fichier",
			"document":      "document",
			"backup":        "sauvegarde",
			"database":      "base de données",
		},
		"es": { // Spanish
			"admin":         "administrador",
			"login":         "inicio de sesión",
			"password":      "contraseña",
			"user":          "usuario",
			"configuration": "configuración",
			"dashboard":     "panel de control",
			"file":          "archivo",
			"document":      "documento",
			"backup":        "copia de seguridad",
			"database":      "base de datos",
		},
		"de": { // German
			"admin":         "administrator",
			"login":         "anmeldung",
			"password":      "passwort",
			"user":          "benutzer",
			"configuration": "konfiguration",
			"dashboard":     "armaturenbrett",
			"file":          "datei",
			"document":      "dokument",
			"backup":        "sicherung",
			"database":      "datenbank",
		},
		"it": { // Italian
			"admin":         "amministratore",
			"login":         "accesso",
			"password":      "parola d'ordine",
			"user":          "utente",
			"configuration": "configurazione",
			"dashboard":     "cruscotto",
			"file":          "file",
			"document":      "documento",
			"backup":        "backup",
			"database":      "database",
		},
		"pt": { // Portuguese
			"admin":         "administrador",
			"login":         "login",
			"password":      "senha",
			"user":          "usuário",
			"configuration": "configuração",
			"dashboard":     "painel",
			"file":          "arquivo",
			"document":      "documento",
			"backup":        "backup",
			"database":      "banco de dados",
		},
		"ru": { // Russian
			"admin":         "администратор",
			"login":         "вход",
			"password":      "пароль",
			"user":          "пользователь",
			"configuration": "конфигурация",
			"dashboard":     "панель",
			"file":          "файл",
			"document":      "документ",
			"backup":        "резервная копия",
			"database":      "база данных",
		},
		"zh": { // Chinese
			"admin":         "管理员",
			"login":         "登录",
			"password":      "密码",
			"user":          "用户",
			"configuration": "配置",
			"dashboard":     "仪表板",
			"file":          "文件",
			"document":      "文档",
			"backup":        "备份",
			"database":      "数据库",
		},
		"ja": { // Japanese
			"admin":         "管理者",
			"login":         "ログイン",
			"password":      "パスワード",
			"user":          "ユーザー",
			"configuration": "設定",
			"dashboard":     "ダッシュボード",
			"file":          "ファイル",
			"document":      "ドキュメント",
			"backup":        "バックアップ",
			"database":      "データベース",
		},
		"ar": { // Arabic
			"admin":         "مسؤل",
			"login":         "تسجيل الدخول",
			"password":      "كلمة المرور",
			"user":          "المستخدم",
			"configuration": "التكوين",
			"dashboard":     "لوحة القيادة",
			"file":          "ملف",
			"document":      "وثيقة",
			"backup":        "نسخة احتياطية",
			"database":      "قاعدة البيانات",
		},
	}

	keywords, ok := langKeywords[language]
	if !ok {
		return baseDorks // Language not supported, return original
	}

	// Target: keep total count exactly equal to the original request while translating a portion.
	portion := cfg.MultiLangMultiplier
	if portion < 0 || portion > 100 {
		portion = 25
	}
	if portion == 0 {
		return baseDorks
	}
	desiredTranslations := len(baseDorks) * portion / 100
	if desiredTranslations < 1 {
		desiredTranslations = 1
	}
	if desiredTranslations > len(baseDorks) {
		desiredTranslations = len(baseDorks)
	}

	out := make([]string, 0, len(baseDorks))
	seen := make(map[string]struct{}, len(baseDorks))
	applied := 0

	for _, dork := range baseDorks {
		candidate := dork

		if applied < desiredTranslations {
			translated := dork
			for enWord, foreignWord := range keywords {
				re := regexp.MustCompile(`(?i)\b` + enWord + `\b`)
				translated = re.ReplaceAllString(translated, foreignWord)
			}
			if translated != dork {
				if _, exists := seen[translated]; !exists {
					candidate = translated
					applied++
				}
			}
		}

		if candidate != dork {
			if _, exists := seen[candidate]; exists {
				// Fallback to original to avoid duplicates
				candidate = dork
			}
		}

		// Track and preserve order; duplicates are avoided when possible
		out = append(out, candidate)
		seen[candidate] = struct{}{}
	}

	return out
}
