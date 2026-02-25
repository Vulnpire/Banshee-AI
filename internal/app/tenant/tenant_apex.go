package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"banshee/internal/app/console"
	"banshee/internal/app/core"
)

type tenantOpenIDConfig struct {
	TokenEndpoint string `json:"token_endpoint"`
}

type tenantDomainsResponse struct {
	Domains []string `json:"domains"`
}

func (c *Config) resolveApexTargets(ctx context.Context, inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	lookedUp := make(map[string]struct{})
	resolved := make([]string, 0, len(inputs))

	for _, raw := range inputs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		domain := normalizeTenantDomain(raw)
		if domain == "" {
			continue
		}

		if strings.HasPrefix(domain, ".") {
			if _, ok := seen[domain]; !ok {
				seen[domain] = struct{}{}
				resolved = append(resolved, domain)
			}
			continue
		}

		if _, ok := lookedUp[domain]; ok {
			continue
		}
		lookedUp[domain] = struct{}{}

		domains, err := c.lookupTenantDomains(ctx, domain)
		if err != nil {
			console.Logv(c.Verbose, "[APEX] Lookup failed for %s: %v", domain, err)
			if _, ok := seen[domain]; !ok {
				seen[domain] = struct{}{}
				resolved = append(resolved, domain)
			}
			continue
		}

		if len(domains) == 0 {
			console.Logv(c.Verbose, "[APEX] No apex domains found for %s", domain)
			if _, ok := seen[domain]; !ok {
				seen[domain] = struct{}{}
				resolved = append(resolved, domain)
			}
			continue
		}

		console.Logv(c.Verbose, "[APEX] %s -> %d apex domain(s)", domain, len(domains))
		for _, apex := range domains {
			apex = normalizeTenantDomain(apex)
			if apex == "" {
				continue
			}
			if _, ok := seen[apex]; ok {
				continue
			}
			seen[apex] = struct{}{}
			resolved = append(resolved, apex)
		}
	}

	if c != nil {
		c.recordApexTargets(resolved)
	}

	return resolved, nil
}

func (c *Config) lookupTenantDomains(ctx context.Context, domain string) ([]string, error) {
	tenantID, err := c.fetchTenantID(ctx, domain)
	if err != nil {
		return nil, err
	}
	if tenantID == "" {
		return nil, nil
	}

	if err := sleepWithJitter(ctx, 1, 10); err != nil {
		return nil, err
	}

	return c.fetchTenantDomains(ctx, tenantID)
}

func (c *Config) fetchTenantID(ctx context.Context, domain string) (string, error) {
	if c.Client == nil {
		return "", fmt.Errorf("http client not initialized")
	}

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", core.DefaultUserAgent)

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("openid config status %d: %s", resp.StatusCode, strings.TrimSpace(naiveTrim(string(body), 200)))
	}

	var payload tenantOpenIDConfig
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}

	return extractTenantID(payload.TokenEndpoint), nil
}

func (c *Config) fetchTenantDomains(ctx context.Context, tenantID string) ([]string, error) {
	if c.Client == nil {
		return nil, fmt.Errorf("http client not initialized")
	}

	endpoint := fmt.Sprintf("https://tenant-api.micahvandeusen.com/search?tenant_id=%s", url.QueryEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", core.DefaultUserAgent)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tenant api status %d: %s", resp.StatusCode, strings.TrimSpace(naiveTrim(string(body), 200)))
	}

	var payload tenantDomainsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	return payload.Domains, nil
}

func extractTenantID(tokenEndpoint string) string {
	tokenEndpoint = strings.TrimSpace(tokenEndpoint)
	if tokenEndpoint == "" {
		return ""
	}

	if parsed, err := url.Parse(tokenEndpoint); err == nil {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}

	parts := strings.Split(tokenEndpoint, "/")
	if len(parts) >= 4 {
		return parts[3]
	}

	return ""
}

func normalizeTenantDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	raw = strings.Trim(raw, "\"'`")
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")

	if at := strings.LastIndex(raw, "@"); at != -1 {
		raw = raw[at+1:]
	}

	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
			raw = parsed.Host
		}
	} else if strings.ContainsAny(raw, "/?#") {
		if parsed, err := url.Parse("http://" + raw); err == nil && parsed.Host != "" {
			raw = parsed.Host
		}
	}

	if host, _, found := strings.Cut(raw, ":"); found {
		raw = host
	}

	raw = strings.TrimPrefix(raw, "www.")
	return strings.ToLower(strings.TrimSpace(raw))
}

func sleepWithJitter(ctx context.Context, minSeconds, maxSeconds int) error {
	if maxSeconds < minSeconds {
		maxSeconds = minSeconds
	}
	delay := rand.Intn(maxSeconds-minSeconds+1) + minSeconds
	timer := time.NewTimer(time.Duration(delay) * time.Second)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func naiveTrim(input string, limit int) string {
	if limit <= 0 || len(input) <= limit {
		return input
	}
	return input[:limit] + "..."
}

func (c *Config) recordApexTargets(targets []string) {
	if c == nil {
		return
	}
	c.ApexResolved = true
	if len(targets) == 0 {
		return
	}

	existing := make(map[string]struct{}, len(c.ApexTargets))
	for _, target := range c.ApexTargets {
		existing[target] = struct{}{}
	}

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := existing[target]; ok {
			continue
		}
		existing[target] = struct{}{}
		c.ApexTargets = append(c.ApexTargets, target)
	}
}

func (c *Config) printApexSummary() {
	if c == nil || !c.FindApex || c.ApexSummaryPrinted || !c.ApexResolved {
		return
	}
	c.ApexSummaryPrinted = true

	if len(c.ApexTargets) == 0 {
		console.LogErr("[APEX] No apex domains resolved.")
		return
	}

	console.LogErr("")
	console.LogErr("[APEX] Resolved %d apex domain(s):", len(c.ApexTargets))
	for i, target := range c.ApexTargets {
		console.LogErr("  %d. %s", i+1, target)
	}
}

func (c *Config) logApexTargets(targets []string) {
	if c == nil || !c.Verbose || len(targets) == 0 {
		return
	}

	console.Logv(c.Verbose, "[APEX] Resolved apex domains:")
	for i, target := range targets {
		console.Logv(c.Verbose, "[APEX] %d. %s", i+1, target)
	}
}
