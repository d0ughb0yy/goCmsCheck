package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// DrupalChecks stores results of Drupal-specific checks
type DrupalChecks struct {
	Version         string
	Vulnerabilities []Vulnerability
	LoginEndpoints  []Endpoint
	AdminEndpoints  []Endpoint
	Nodes           []Endpoint
	Users           []Endpoint
	Modules         []Module
	Theme           Theme
	ConfigFiles     map[string]string
}

// Module represents a scanned Drupal module
type Module struct {
	Name          string
	Slug          string
	Vulnerability bool
	CVEs          []string
	Enabled       bool
}

// osvVulnerabilityCache stores API responses to avoid redundant requests
var osvVulnerabilityCache = make(map[string][]Vulnerability)

// ScanDrupal performs all Drupal-specific scans
func (hc *HTTPClient) ScanDrupal(ctx context.Context, baseURL string, scanAllModules bool, homeHTML string) (*DrupalChecks, error) {
	checks := &DrupalChecks{
		ConfigFiles: make(map[string]string),
	}

	// 1. Get Drupal Version
	version, err := hc.GetDrupalVersion(ctx, baseURL)
	if err == nil {
		checks.Version = version
		// Check core vulnerabilities
		if vulns, err := hc.CheckOsvVulnerability(ctx, "drupal/drupal", version); err == nil && len(vulns) > 0 {
			checks.Vulnerabilities = append(checks.Vulnerabilities, vulns...)
		}
	}

	// 2. Check Login/Admin Endpoints
	checks.LoginEndpoints = hc.CheckDrupalLoginEndpoints(ctx, baseURL)
	checks.AdminEndpoints = hc.CheckDrupalAdminEndpoints(ctx, baseURL)

	// 3. Enumerate Nodes and Users (with parallel rate limiting)
	// Note: User enumeration may be blocked by robots.txt (403 forbidden)
	checks.Nodes = hc.EnumerateNodes(ctx, baseURL)
	checks.Users = hc.EnumerateUsers(ctx, baseURL)

	// 4. Extract Theme and Modules from cached HTML
	if homeHTML != "" {
		// Extract and check theme
		themeSlug := ExtractDrupalTheme(homeHTML)
		if themeSlug != "" {
			checks.Theme.Slug = themeSlug
			checks.Theme.Name = themeSlug
			// Check theme vulnerabilities using OSV API
			if vulns, err := hc.CheckOsvVulnerability(ctx, "drupal/theme", themeSlug); err == nil && len(vulns) > 0 {
				checks.Theme.Vulnerability = true
				for _, v := range vulns {
					checks.Theme.CVEs = append(checks.Theme.CVEs, v.CVE)
				}
			}
		}

		// Extract and check modules
		moduleSlugs := ExtractDrupalModules(homeHTML)
		limit := 10
		if scanAllModules {
			limit = len(moduleSlugs)
		}
		if len(moduleSlugs) > limit {
			moduleSlugs = moduleSlugs[:limit]
		}

		for _, slug := range moduleSlugs {
			module := Module{
				Name:    slug,
				Slug:    slug,
				Enabled: true, // Assume enabled if found in HTML
			}
			if vulns, err := hc.CheckOsvVulnerability(ctx, "drupal/module", slug); err == nil && len(vulns) > 0 {
				module.Vulnerability = true
				for _, v := range vulns {
					module.CVEs = append(module.CVEs, v.CVE)
				}
			}
			checks.Modules = append(checks.Modules, module)
		}
	}

	// 5. Check Configuration Files
	checks.ConfigFiles = hc.CheckDrupalConfigFiles(ctx, baseURL)

	return checks, nil
}

// GetDrupalVersion tries to extract Drupal version from HTML or CHANGELOG
func (hc *HTTPClient) GetDrupalVersion(ctx context.Context, baseURL string) (string, error) {
	// Try to fetch homepage and look for version in meta tags
	homeURL := strings.TrimSuffix(baseURL, "/") + "/"
	resp, err := hc.Get(ctx, homeURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			html := string(body)

			// Look for version in meta generator tag (supports Drupal 7 format)
			re := regexp.MustCompile(`<meta[^>]*name=["']Generator["'][^>]*content=["']Drupal\s+(\d+)[^"']*["']`)
			matches := re.FindStringSubmatch(html)
			if len(matches) > 1 {
				return matches[1], nil
			}

			// Look for version in meta generator tag (supports Drupal 8+ format)
			re = regexp.MustCompile(`<meta[^>]*name=["']generator["'][^>]*content=["']Drupal\s+(\d+\.\d+)[^"']*["']`)
			matches = re.FindStringSubmatch(html)
			if len(matches) > 1 {
				return matches[1], nil
			}

			// Look for version in version string
			re = regexp.MustCompile(`Drupal\s+(\d+\.\d+(\.\d+)?)`)
			matches = re.FindStringSubmatch(html)
			if len(matches) > 1 {
				return matches[1], nil
			}
		}
	}

	// Fallback to check for CHANGELOG.txt in possible locations
	changelogPaths := []string{
		"/CHANGELOG.txt",
		"/core/CHANGELOG.txt",
		"/includes/CHANGELOG.txt",
	}

	for _, path := range changelogPaths {
		changelogURL := strings.TrimSuffix(baseURL, "/") + path
		resp, err := hc.Get(ctx, changelogURL)
		if err == nil {
			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				lines := strings.Split(string(body), "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "Drupal") {
						re := regexp.MustCompile(`Drupal\s+(\d+\.\d+(\.\d+)?)`)
						matches := re.FindStringSubmatch(line)
						if len(matches) > 1 {
							return matches[1], nil
						}
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}

	return "", fmt.Errorf("could not determine Drupal version")
}

// CheckOsvVulnerability queries the OSV API for Drupal vulnerabilities
func (hc *HTTPClient) CheckOsvVulnerability(ctx context.Context, component string, slug string) ([]Vulnerability, error) {
	cacheKey := component + ":" + slug
	if cached, ok := osvVulnerabilityCache[cacheKey]; ok {
		return cached, nil
	}

	// Map component to actual package name
	var packageName string
	var version string
	switch component {
	case "drupal/drupal":
		packageName = "drupal/drupal"
		version = slug
	case "drupal/module":
		packageName = "drupal/" + slug
	case "drupal/theme":
		packageName = "drupal/" + slug
	default:
		return nil, fmt.Errorf("unknown component type: %s", component)
	}

	// Query OSV API
	apiURL := "https://api.osv.dev/v1/query"
	payload := map[string]interface{}{
		"package": map[string]string{
			"name":      packageName,
			"ecosystem": "Packagist:https://packages.drupal.org/8",
		},
	}
	if version != "" {
		payload["version"] = version
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(jsonPayload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var vulnerabilities []Vulnerability
	if vulns, ok := result["vulns"].([]interface{}); ok {
		for _, v := range vulns {
			if vulnMap, ok := v.(map[string]interface{}); ok {
				// Extract CVE identifiers from aliases
				cves := []string{}
				if aliases, ok := vulnMap["aliases"].([]interface{}); ok {
					for _, alias := range aliases {
						if aliasStr, ok := alias.(string); ok {
							if strings.HasPrefix(aliasStr, "CVE-") {
								cves = append(cves, aliasStr)
							}
						}
					}
				}

				// Fallback to OSV advisory ID if no CVEs found
				if len(cves) == 0 {
					if id := getString(vulnMap, "id"); id != "" {
						cves = append(cves, id)
					}
				}

				// Create vulnerability entries for each CVE
				for _, cve := range cves {
					title := getString(vulnMap, "summary")
					if title == "" {
						title = getString(vulnMap, "details")
					}
					// Truncate long titles
					if len(title) > 80 {
						title = title[:77] + "..."
					}
					vuln := Vulnerability{
						CVE:      cve,
						Severity: "unknown",
						FixedIn:  getString(vulnMap, "id"),
						Title:    title,
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}

	osvVulnerabilityCache[cacheKey] = vulnerabilities
	return vulnerabilities, nil
}

// CheckDrupalLoginEndpoints checks common Drupal login endpoints
func (hc *HTTPClient) CheckDrupalLoginEndpoints(ctx context.Context, baseURL string) []Endpoint {
	endpoints := []Endpoint{
		{URL: strings.TrimSuffix(baseURL, "/") + "/user/login"},
		{URL: strings.TrimSuffix(baseURL, "/") + "/user/login?destination=user"},
	}

	var found []Endpoint
	for _, ep := range endpoints {
		resp, err := hc.Get(ctx, ep.URL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		ep.StatusCode = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			found = append(found, ep)
		}
	}
	return found
}

// CheckDrupalAdminEndpoints checks common Drupal admin endpoints
func (hc *HTTPClient) CheckDrupalAdminEndpoints(ctx context.Context, baseURL string) []Endpoint {
	endpoints := []Endpoint{
		{URL: strings.TrimSuffix(baseURL, "/") + "/user/register"},
		{URL: strings.TrimSuffix(baseURL, "/") + "/admin"},
		{URL: strings.TrimSuffix(baseURL, "/") + "/admin/config"},
	}

	var found []Endpoint
	for _, ep := range endpoints {
		resp, err := hc.Get(ctx, ep.URL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		ep.StatusCode = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			found = append(found, ep)
		}
	}
	return found
}

// EnumerateNodes enumerates /node/<id> endpoints (1-100)
func (hc *HTTPClient) EnumerateNodes(ctx context.Context, baseURL string) []Endpoint {
	var found []Endpoint
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Enumerate nodes 1-100 (uses global rate limiter 5 req/s from httpclient)
	// 5 req/s = ~20 seconds for 100 requests
	for i := 1; i <= 100; i++ {
		nodeURL := fmt.Sprintf("%s/node/%d", baseURL, i)
		resp, err := hc.Get(ctx, nodeURL)
		if err != nil {
			continue
		}
		// Close body immediately instead of using defer in loop
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			found = append(found, Endpoint{
				URL:        nodeURL,
				StatusCode: resp.StatusCode,
			})
		}
	}

	return found
}

// EnumerateUsers enumerates /user/<id> endpoints (1-100)
func (hc *HTTPClient) EnumerateUsers(ctx context.Context, baseURL string) []Endpoint {
	var found []Endpoint
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Enumerate users 1-100 (uses global rate limiter 5 req/s from httpclient)
	// 5 req/s = ~20 seconds for 100 requests
	for i := 1; i <= 100; i++ {
		userURL := fmt.Sprintf("%s/user/%d", baseURL, i)
		resp, err := hc.Get(ctx, userURL)
		if err != nil {
			continue
		}
		// Close body immediately instead of using defer in loop
		resp.Body.Close()

		// Only count non-403 responses (403 usually means access denied, not missing)
		if resp.StatusCode >= 200 && resp.StatusCode < 400 && resp.StatusCode != 403 {
			found = append(found, Endpoint{
				URL:        userURL,
				StatusCode: resp.StatusCode,
			})
		}
	}

	return found
}

// CheckDrupalConfigFiles checks common Drupal configuration files
func (hc *HTTPClient) CheckDrupalConfigFiles(ctx context.Context, baseURL string) map[string]string {
	configFiles := make(map[string]string)
	baseURL = strings.TrimSuffix(baseURL, "/")

	files := []string{
		"/config/sync/core.extension.yml",
		"/core/core.services.yml",
		"/config/sync/swiftmailer.transport.yml",
	}

	for _, file := range files {
		fileURL := baseURL + file
		resp, err := hc.Get(ctx, fileURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			configFiles[file] = string(body)
		}
	}

	return configFiles
}

// ExtractDrupalTheme extracts the active theme slug from HTML
func ExtractDrupalTheme(html string) string {
	// Pattern: /themes/theme-name/ or /sites/*/themes/theme-name/
	re := regexp.MustCompile(`/sites/[^/]+/themes/([^"'/]+)/`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}

	// Fallback to simple pattern
	re = regexp.MustCompile(`/themes/([^"'/]+)/`)
	matches = re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractDrupalModules extracts module slugs from HTML
func ExtractDrupalModules(html string) []string {
	// Pattern: /sites/*/modules/module-name/
	re := regexp.MustCompile(`/sites/[^/]+/modules/([^"'/]+)/`)
	matches := re.FindAllStringSubmatch(html, -1)

	uniqueModules := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			uniqueModules[match[1]] = true
		}
	}

	// Fallback to simple pattern
	re = regexp.MustCompile(`/modules/([^"'/]+)/`)
	matches = re.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			uniqueModules[match[1]] = true
		}
	}

	var modules []string
	for module := range uniqueModules {
		modules = append(modules, module)
	}
	return modules
}
