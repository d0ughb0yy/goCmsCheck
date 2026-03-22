package scanner

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// WordPressChecks stores results of WordPress-specific checks
type WordPressChecks struct {
	Version         string
	Vulnerabilities []Vulnerability
	LoginEndpoints  []Endpoint
	XmlRpcEnabled   bool
	XmlRpcMethods   []string
	PingbackCheck   PingbackResult
	Plugins         []Plugin
	Theme           Theme
}

// Vulnerability represents a vulnerability found via WPVulnerability API
type Vulnerability struct {
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	FixedIn  string `json:"fixed_in"`
	Title    string `json:"title"`
}

// Plugin represents a scanned plugin
type Plugin struct {
	Name          string
	Slug          string
	Vulnerability bool
	CVEs          []string
}

// Theme represents a scanned theme
type Theme struct {
	Name          string
	Slug          string
	Vulnerability bool
	CVEs          []string
}

// PingbackResult stores result of pingback check
type PingbackResult struct {
	Enabled bool
	URL     string
	Error   string
}

// wpVulnerabilityCache stores API responses to avoid redundant requests
var wpVulnerabilityCache = make(map[string][]Vulnerability)

//go:embed plugins.txt
var bundledPlugins string

// LoadBundledPlugins parses the embedded plugins.txt into a slice of slugs
func LoadBundledPlugins() []string {
	var plugins []string
	for _, line := range strings.Split(bundledPlugins, "\n") {
		slug := strings.TrimSpace(line)
		if slug != "" {
			plugins = append(plugins, slug)
		}
	}
	return plugins
}

// ScanWordPress performs all WordPress-specific scans
func (hc *HTTPClient) ScanWordPress(ctx context.Context, baseURL string, serverFlag string, scanAllPlugins bool) (*WordPressChecks, error) {
	checks := &WordPressChecks{}

	// 1. Get WordPress Version
	version, err := hc.GetWordPressVersion(ctx, baseURL)
	if err == nil {
		checks.Version = version
		// Check core vulnerabilities
		if vulns, err := hc.CheckWpvulnerability(ctx, "wordpress", version); err == nil && len(vulns) > 0 {
			checks.Vulnerabilities = append(checks.Vulnerabilities, vulns...)
		}
	}

	// 2. Check Login Endpoints (wp-login.php, wp-admin)
	checks.LoginEndpoints = hc.CheckWordpressLoginEndpoints(ctx, baseURL)

	// 3. Check XML-RPC
	xmlRpcResult, err := hc.CheckXmlRpc(ctx, baseURL)
	if err == nil {
		checks.XmlRpcEnabled = xmlRpcResult.Enabled
		checks.XmlRpcMethods = xmlRpcResult.Methods
	}

	// 4. Check Pingback (if server flag provided and XML-RPC is enabled)
	if serverFlag != "" && checks.XmlRpcEnabled {
		checks.PingbackCheck = hc.PerformPingbackCheck(ctx, baseURL, serverFlag)
	}

	// 5. Check bundled plugin list against WPVulnerability API
	checkedSlugs := make(map[string]bool)
	bundled := LoadBundledPlugins()

	for _, slug := range bundled {
		checkedSlugs[slug] = true
		plugin := Plugin{
			Name: slug,
			Slug: slug,
		}
		if vulns, err := hc.CheckWpvulnerability(ctx, "plugin", slug); err == nil && len(vulns) > 0 {
			plugin.Vulnerability = true
			for _, v := range vulns {
				plugin.CVEs = append(plugin.CVEs, v.CVE)
			}
			checks.Vulnerabilities = append(checks.Vulnerabilities, vulns...)
		}
		checks.Plugins = append(checks.Plugins, plugin)
	}

	// 6. Fetch homepage HTML for theme and dynamic plugin parsing
	homeHTML, err := hc.FetchHomePageHTML(ctx, baseURL)
	if err == nil {
		// Extract and check theme
		themeSlug := ExtractActiveTheme(homeHTML)
		if themeSlug != "" {
			checks.Theme.Slug = themeSlug
			checks.Theme.Name = themeSlug
			if vulns, err := hc.CheckWpvulnerability(ctx, "theme", themeSlug); err == nil && len(vulns) > 0 {
				checks.Theme.Vulnerability = true
				for _, v := range vulns {
					checks.Theme.CVEs = append(checks.Theme.CVEs, v.CVE)
				}
				checks.Vulnerabilities = append(checks.Vulnerabilities, vulns...)
			}
		}

		// Dynamically extract plugins from HTML, skip already-checked
		htmlSlugs := ExtractPlugins(homeHTML)
		limit := 10
		if scanAllPlugins {
			limit = len(htmlSlugs)
		}

		var newSlugs []string
		for _, slug := range htmlSlugs {
			if !checkedSlugs[slug] {
				newSlugs = append(newSlugs, slug)
				checkedSlugs[slug] = true
			}
		}
		if len(newSlugs) > limit {
			newSlugs = newSlugs[:limit]
		}

		for _, slug := range newSlugs {
			plugin := Plugin{
				Name: slug,
				Slug: slug,
			}
			if vulns, err := hc.CheckWpvulnerability(ctx, "plugin", slug); err == nil && len(vulns) > 0 {
				plugin.Vulnerability = true
				for _, v := range vulns {
					plugin.CVEs = append(plugin.CVEs, v.CVE)
				}
				checks.Vulnerabilities = append(checks.Vulnerabilities, vulns...)
			}
			checks.Plugins = append(checks.Plugins, plugin)
		}
	}

	return checks, nil
}

// GetWordPressVersion tries to extract WP version from CSS or readme
func (hc *HTTPClient) GetWordPressVersion(ctx context.Context, baseURL string) (string, error) {
	// Try dashicons CSS first
	cssURL := strings.TrimSuffix(baseURL, "/") + "/wp-includes/css/dashicons.min.css"
	resp, err := hc.Get(ctx, cssURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			// Regex for ver=1.2.3
			re := regexp.MustCompile(`ver=(\d+\.\d+(?:\.\d+)?)`)
			matches := re.FindStringSubmatch(string(body))
			if len(matches) > 1 {
				return matches[1], nil
			}
		}
	}

	// Fallback to readme.html
	readmeURL := strings.TrimSuffix(baseURL, "/") + "/readme.html"
	resp, err = hc.Get(ctx, readmeURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			// Regex for "Version 1.2.3"
			re := regexp.MustCompile(`Version\s+(\d+\.\d+(?:\.\d+)?)`)
			matches := re.FindStringSubmatch(string(body))
			if len(matches) > 1 {
				return matches[1], nil
			}
		}
	}

	return "", fmt.Errorf("could not determine WordPress version")
}

// CheckWpvulnerability queries the WPVulnerability API
func (hc *HTTPClient) CheckWpvulnerability(ctx context.Context, component string, slug string) ([]Vulnerability, error) {
	cacheKey := component + ":" + slug
	if cached, ok := wpVulnerabilityCache[cacheKey]; ok {
		return cached, nil
	}

	apiURL := fmt.Sprintf("https://www.wpvulnerability.net/%s/%s", component, url.PathEscape(slug))
	resp, err := hc.Get(ctx, apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Component not found in DB, treat as no vulnerabilities
		wpVulnerabilityCache[cacheKey] = []Vulnerability{}
		return []Vulnerability{}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
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
	// Parse the actual API response structure: data.vulnerability[]
	if data, ok := result["data"].(map[string]interface{}); ok {
		if vulns, ok := data["vulnerability"].([]interface{}); ok {
			for _, v := range vulns {
				if vulnMap, ok := v.(map[string]interface{}); ok {
					// Extract all CVE identifiers from source array
					cves := []string{}
					if sources, ok := vulnMap["source"].([]interface{}); ok {
						for _, source := range sources {
							if sourceMap, ok := source.(map[string]interface{}); ok {
								id := getString(sourceMap, "id")
								// Only include actual CVE identifiers
								if strings.HasPrefix(id, "CVE-") {
									cves = append(cves, id)
								}
							}
						}
					}

					// Create a vulnerability entry for each CVE found
					for _, cve := range cves {
						vuln := Vulnerability{
							CVE:      cve,
							Severity: "unknown",                  // API doesn't provide severity directly
							FixedIn:  getString(vulnMap, "name"), // Name contains version info
							Title:    getString(vulnMap, "name"),
						}
						vulnerabilities = append(vulnerabilities, vuln)
					}
				}
			}
		}
	}

	wpVulnerabilityCache[cacheKey] = vulnerabilities
	return vulnerabilities, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// CheckWordpressLoginEndpoints checks common WP login/admin endpoints
func (hc *HTTPClient) CheckWordpressLoginEndpoints(ctx context.Context, baseURL string) []Endpoint {
	endpoints := []Endpoint{
		{URL: strings.TrimSuffix(baseURL, "/") + "/wp-login.php"},
		{URL: strings.TrimSuffix(baseURL, "/") + "/wp-admin"},
		{URL: strings.TrimSuffix(baseURL, "/") + "/wp-admin/"},
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

// CheckXmlRpc checks if xmlrpc.php is enabled and lists methods
func (hc *HTTPClient) CheckXmlRpc(ctx context.Context, baseURL string) (struct {
	Enabled bool
	Methods []string
}, error) {
	result := struct {
		Enabled bool
		Methods []string
	}{}

	xmlRpcURL := strings.TrimSuffix(baseURL, "/") + "/xmlrpc.php"
	resp, err := hc.Get(ctx, xmlRpcURL)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.Enabled = false
		return result, nil
	}

	result.Enabled = true

	// Try to list methods (standard XML-RPC request)
	body := `<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>`

	resp2, err := hc.DoRequest(ctx, "POST", xmlRpcURL, strings.NewReader(body))
	if err != nil {
		// If POST fails, just return enabled status
		return result, nil
	}
	defer resp2.Body.Close()

	// Parse response for method names (simplified parsing)
	respBody, _ := io.ReadAll(resp2.Body)
	respStr := string(respBody)

	// Simple regex to find method names in response
	re := regexp.MustCompile(`<string>([^<]+)</string>`)
	matches := re.FindAllStringSubmatch(respStr, -1)
	for _, match := range matches {
		if len(match) > 1 {
			method := match[1]
			// Avoid duplicates and non-method tags
			if !contains(result.Methods, method) {
				result.Methods = append(result.Methods, method)
			}
		}
	}

	return result, nil
}

// PerformPingbackCheck attempts to trigger a pingback
func (hc *HTTPClient) PerformPingbackCheck(ctx context.Context, baseURL string, serverURL string) PingbackResult {
	result := PingbackResult{Enabled: false, URL: serverURL}

	xmlRpcURL := strings.TrimSuffix(baseURL, "/") + "/xmlrpc.php"

	// Construct pingback request
	body := fmt.Sprintf(`<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>%s</string></value>
</param>
<param>
<value><string>%s</string></value>
</param>
</params>
</methodCall>`, serverURL, strings.TrimSuffix(baseURL, "/"))

	resp, err := hc.DoRequest(ctx, "POST", xmlRpcURL, strings.NewReader(body))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.Enabled = true
		// Check response body for success/failure indication
		respBody, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(respBody), "pingback") && !strings.Contains(string(respBody), "faultCode") {
			result.Error = "Pingback may be enabled (check server logs)"
		} else {
			result.Error = "Pingback request sent, check server logs"
		}
	} else {
		result.Error = fmt.Sprintf("XML-RPC blocked (HTTP %d)", resp.StatusCode)
	}

	return result
}

// FetchHomePageHTML fetches the homepage HTML content
func (hc *HTTPClient) FetchHomePageHTML(ctx context.Context, baseURL string) (string, error) {
	resp, err := hc.Get(ctx, baseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ExtractActiveTheme extracts the active theme slug from HTML
func ExtractActiveTheme(html string) string {
	// Pattern: /wp-content/themes/theme-name/
	re := regexp.MustCompile(`/wp-content/themes/([^"'/]+)/`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractPlugins extracts plugin slugs from HTML
func ExtractPlugins(html string) []string {
	// Pattern: /wp-content/plugins/plugin-name/
	re := regexp.MustCompile(`/wp-content/plugins/([^"'/]+)/`)
	matches := re.FindAllStringSubmatch(html, -1)

	uniquePlugins := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			uniquePlugins[match[1]] = true
		}
	}

	var plugins []string
	for plugin := range uniquePlugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
