package search

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"banshee/internal/app/core"

	"golang.org/x/net/proxy"
)

// --- HTTP client and requests ---

func buildHTTPClient(proxyURL string, insecure bool) (*http.Client, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   20 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second, // Increased for proxy compatibility
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false, // Disable HTTP/2 for proxy compatibility
	}

	// Configure TLS for proxy compatibility (Burp Suite, etc.)
	if insecure {
		// Permissive TLS config for intercepting proxies
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         0,                             // Allow any TLS version
			MaxVersion:         0,                             // Allow any TLS version
			CipherSuites:       nil,                           // Allow any cipher suite
			Renegotiation:      tls.RenegotiateFreelyAsClient, // Allow TLS renegotiation
		}
		// Disable HTTP/2 for better proxy compatibility
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
		// Disable connection reuse for better proxy compatibility
		transport.DisableKeepAlives = true
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		// Check if it's a SOCKS proxy
		if u.Scheme == "socks5" || u.Scheme == "socks5h" || u.Scheme == "socks4" || u.Scheme == "socks4a" {
			// SOCKS proxy support
			var auth *proxy.Auth
			if u.User != nil {
				password, _ := u.User.Password()
				auth = &proxy.Auth{
					User:     u.User.Username(),
					Password: password,
				}
			}

			// Create SOCKS5 dialer
			dialer, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
			}

			// Use SOCKS dialer for HTTP transport
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		} else {
			// HTTP/HTTPS proxy
			transport.Proxy = http.ProxyURL(u)
		}
	}

	// Increase timeout when using proxy for better compatibility
	timeout := 30 * time.Second
	if proxyURL != "" {
		timeout = 60 * time.Second
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

func (c *Config) httpGetJSON(ctx context.Context, u string) (*GoogleResponse, int, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("User-Agent", core.DefaultUserAgent)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, 0, err
	}
	var gr GoogleResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		// still return code for troubleshooting
		return nil, resp.StatusCode, len(body), fmt.Errorf("decode error: %w, body: %s", err, string(body))
	}
	return &gr, resp.StatusCode, len(body), nil
}

func (c *Config) notFound() {
	// HTML redirect check; here API returns JSON errors.
	// keep silent as per commented-out prints.
}

func (c *Config) showContentInFile() {
	// This only prints when contents set; kept minimal
	if c.Contents != "" && c.Verbose {
		fmt.Printf("Files found containing: %s\n", c.Contents)
	}
}

// urlDecode similar to sed
func urlDecodeLikeSed(s string) string {
	// First standard percent-decoding
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		decoded = s
	}
	// Then specific replacements to mimic the sed line (some overlapped)
	repls := map[string]string{
		"%2520": " ",
		"%20":   " ",
		"%3F":   "?",
		"%3D":   "=",
		"%21":   "!",
		"%23":   "#",
		"%24":   "$",
		"%2B":   "+",
		"%26":   "&",
	}
	for k, v := range repls {
		decoded = strings.ReplaceAll(decoded, k, v)
	}
	return decoded
}

var googleHostFilter = regexp.MustCompile(`(?i)google`)

// Cloud platform domains to accept in cloud enumeration mode
var cloudPlatforms = []string{
	"s3.amazonaws.com",
	"blob.core.windows.net",
	"storage.googleapis.com",
	"storage.cloud.google.com",
	"digitaloceanspaces.com",
	"cloudfront.net",
	"backblazeb2.com",
	"amazonaws.com", // Broader AWS domains
	"azurewebsites.net",
	"blob.core.chinacloudapi.cn",  // Azure China
	"blob.core.usgovcloudapi.net", // Azure Gov
}

// isCloudDork checks if a dork/query contains cloud platform domains
func isCloudDork(query string) bool {
	lowerQuery := strings.ToLower(query)
	for _, platform := range cloudPlatforms {
		if strings.Contains(lowerQuery, platform) {
			return true
		}
	}
	return false
}

// isCloudPrompt checks if the user prompt implies cloud enumeration
func isCloudPrompt(prompt string) bool {
	l := strings.ToLower(prompt)
	keywords := []string{
		"cloud", "bucket", "s3", "azure", "gcp", "storage", "blob",
		"cloudfront", "r2", "spaces", "sharepoint", "onedrive", "googleapis",
		"digitalocean", "wasabi", "linode", "aliyun", "supabase", "firebase",
	}
	for _, k := range keywords {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// buildCloudPromptHint gives concise guidance for cloud-oriented AI prompts
func buildCloudPromptHint(target string) string {
	return fmt.Sprintf(`One provider per dork. Use "%[1]s" as keyword with provider hosts instead of chaining many site: operators. Target S3 (s3.amazonaws.com, s3-external-1, s3.dualstack.us-east-1, cloudfront.net, r2.cloudflarestorage.com), Azure (blob.core.windows.net, dev.azure.com, sharepoint.com, onedrive.live.com), GCP (storage.googleapis.com, storage.cloud.google.com, googleapis.com, appspot.com, docs/drive.google.com), DigitalOcean (digitaloceanspaces.com), Wasabi (wasabisys.com), Linode (linodeobjects.com), Aliyun (aliyuncs.com), Supabase (supabase.co), Firebase (firebaseio.com), Box/Dropbox (box.com/s, dropbox.com/s). Use filetype:json/xml/env/conf/log/txt and bucket/space names like %[1]s-backup, %[1]s-assets, %[1]s-dev, %[1]s-prod, %[1]s-uploads, %[1]s-staging.`, target)
}

// detectCloudIntentWithAI tries to classify whether the prompt is about cloud enumeration using the AI model.
func detectCloudIntentWithAI(ctx context.Context, prompt, model string) bool {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return false
	}

	// Build a tiny classification prompt (explicitly differentiate non-cloud intents)
	system := "You are a classifier. Reply with ONLY YES or NO. Answer YES only if the user wants cloud asset enumeration (storage buckets, blobs, object stores, drive/sharepoint/onedrive, cloud credentials). Answer NO for all other intents, including documents/PII/leak hunting, PDF/DOC searches, Kubernetes dashboards, SQLi, XSS, admin panels, CVEs, general vuln searches, tech detection, or anything that is not explicitly about cloud storage/services."
	user := fmt.Sprintf("Prompt: %s", prompt)

	// Prepare command; reuse gemini-cli similar to other invocations
	var args []string
	if model != "" {
		args = []string{"--model", model, "-p", user}
	} else {
		args = []string{"-p", user}
	}

	// Short timeout guard
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "gemini-cli", args...)
	cmd.Stdin = strings.NewReader(system)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return false
	}

	output := strings.ToLower(strings.TrimSpace(stdout.String()))
	if strings.HasPrefix(output, "yes") {
		return true
	}
	if strings.HasPrefix(output, "no") {
		return false
	}

	// Fallback if ambiguous
	return false
}

func filterLinks(items []string, target string, cloudMode bool) []string {
	out := make([]string, 0, len(items))
	for _, l := range items {
		if l == "" {
			continue
		}

		lowerLink := strings.ToLower(l)
		lowerTarget := strings.ToLower(target)

		// If no target specified, accept all results (universal search mode)
		if target == "" {
			// Still filter out Google results
			if googleHostFilter.MatchString(l) {
				continue
			}
			out = append(out, urlDecodeLikeSed(l))
			continue
		}

		// In cloud mode, accept URLs from cloud platforms even if they don't contain the exact target
		if cloudMode {
			// Check if link contains the target OR is from a known cloud platform
			containsTarget := strings.Contains(lowerLink, lowerTarget)
			isCloudPlatform := false
			for _, platform := range cloudPlatforms {
				if strings.Contains(lowerLink, platform) {
					isCloudPlatform = true
					break
				}
			}

			// Accept if it's from a cloud platform OR contains the target
			if !containsTarget && !isCloudPlatform {
				continue
			}
		} else {
			// Normal mode: require target in URL
			if !strings.Contains(lowerLink, lowerTarget) {
				continue
			}
		}

		if googleHostFilter.MatchString(l) {
			continue
		}
		out = append(out, urlDecodeLikeSed(l))
	}
	return uniqueStrings(out)
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func (c *Config) delayControl() {
	d := c.DynamicDelay
	if c.Delay > 0 {
		d = c.Delay
	}
	if d > 0 {
		time.Sleep(time.Duration(d * float64(time.Second)))
	}
}
