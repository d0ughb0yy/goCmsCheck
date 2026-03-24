package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// CommonChecks stores results of common recon checks
type CommonChecks struct {
	RobotsTxt      string
	Headers        map[string]string
	GitExposed     bool
	GitURL         string
	GitStatusCode  int
	EnvExposed     bool
	EnvURL         string
	EnvStatusCode  int
	AdminEndpoints []Endpoint
	CMSDetected    string
	HomepageHTML   string
}

// Endpoint represents a discovered endpoint
type Endpoint struct {
	URL         string
	StatusCode  int
	RedirectURL string
}

// FetchRobotsTxt fetches and parses robots.txt
func (hc *HTTPClient) FetchRobotsTxt(ctx context.Context, baseURL string) (string, error) {
	url := strings.TrimSuffix(baseURL, "/") + "/robots.txt"
	resp, err := hc.Get(ctx, url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch robots.txt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("robots.txt not found (status %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read robots.txt body: %w", err)
	}

	return string(body), nil
}

// FetchHeaders fetches all response headers from the base URL
func (hc *HTTPClient) FetchHeaders(ctx context.Context, baseURL string) (map[string]string, error) {
	url := strings.TrimSuffix(baseURL, "/") + "/"
	resp, err := hc.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch headers: %w", err)
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return headers, nil
}

// CheckGitFolder checks if .git directory is exposed
func (hc *HTTPClient) CheckGitFolder(ctx context.Context, baseURL string) (bool, string, int, error) {
	url := strings.TrimSuffix(baseURL, "/") + "/.git/"
	resp, err := hc.Get(ctx, url)
	if err != nil {
		return false, "", 0, fmt.Errorf("failed to check .git folder: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
		return true, url, resp.StatusCode, nil
	}

	return false, "", resp.StatusCode, nil
}

// CheckEnvFile checks if .env file is exposed
func (hc *HTTPClient) CheckEnvFile(ctx context.Context, baseURL string) (bool, string, int, error) {
	url := strings.TrimSuffix(baseURL, "/") + "/.env"
	resp, err := hc.Get(ctx, url)
	if err != nil {
		return false, "", 0, fmt.Errorf("failed to check .env file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
		return true, url, resp.StatusCode, nil
	}

	return false, "", resp.StatusCode, nil
}

// CheckAdminEndpoints checks common admin endpoints
func (hc *HTTPClient) CheckAdminEndpoints(ctx context.Context, baseURL string) ([]Endpoint, error) {
	adminPaths := []string{
		"/admin",
		"/administrator",
		"/backend",
		"/dashboard",
		"/wp-admin",
		"/user/login",
		"/user/register",
	}

	var endpoints []Endpoint
	baseURL = strings.TrimSuffix(baseURL, "/")

	for _, path := range adminPaths {
		url := baseURL + path
		resp, err := hc.Get(ctx, url)
		if err != nil {
			continue // Skip on error
		}

		endpoint := Endpoint{
			URL:        url,
			StatusCode: resp.StatusCode,
		}

		// Check for redirect
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location != "" {
				endpoint.RedirectURL = location
			}
		}

		endpoints = append(endpoints, endpoint)
		resp.Body.Close()
	}

	return endpoints, nil
}

// RunCommonChecks performs all common recon checks
func (hc *HTTPClient) RunCommonChecks(ctx context.Context, baseURL string) (*CommonChecks, error) {
	checks := &CommonChecks{
		Headers: make(map[string]string),
	}

	// Fetch robots.txt
	robotsTxt, err := hc.FetchRobotsTxt(ctx, baseURL)
	if err == nil {
		checks.RobotsTxt = robotsTxt
	}

	// Fetch headers
	headers, err := hc.FetchHeaders(ctx, baseURL)
	if err == nil {
		checks.Headers = headers
	}

	// Check .git folder
	gitExposed, gitURL, gitStatus, err := hc.CheckGitFolder(ctx, baseURL)
	if err == nil {
		checks.GitExposed = gitExposed
		checks.GitURL = gitURL
		checks.GitStatusCode = gitStatus
	}

	// Check .env file
	envExposed, envURL, envStatus, err := hc.CheckEnvFile(ctx, baseURL)
	if err == nil {
		checks.EnvExposed = envExposed
		checks.EnvURL = envURL
		checks.EnvStatusCode = envStatus
	}

	// Check admin endpoints
	adminEndpoints, err := hc.CheckAdminEndpoints(ctx, baseURL)
	if err == nil {
		checks.AdminEndpoints = adminEndpoints
	}

	// Detect CMS from homepage HTML
	homeHTML, err := hc.FetchHomePageHTML(ctx, baseURL)
	if err == nil {
		checks.HomepageHTML = homeHTML
		checks.CMSDetected = hc.DetectCMS(ctx, baseURL, homeHTML)
	}

	return checks, nil
}

// DetectCMS identifies the CMS type from homepage HTML and endpoint probes.
// Returns "wordpress", "drupal", or "" if unknown.
// WordPress takes priority when signals from both CMS types are present.
func (hc *HTTPClient) DetectCMS(ctx context.Context, baseURL, html string) string {
	wpConfirmed := false
	drupalConfirmed := false

	// 1. Check meta generator tags (near-definitive)
	re := regexp.MustCompile(`(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			generator := match[1]
			if strings.Contains(strings.ToLower(generator), "wordpress") {
				return "wordpress"
			}
			if strings.Contains(strings.ToLower(generator), "drupal") {
				return "drupal"
			}
		}
	}

	// 2. Check HTML path patterns (strong signal)
	if strings.Contains(html, "/wp-content/") || strings.Contains(html, "/wp-includes/") {
		wpConfirmed = true
	}
	if strings.Contains(html, "/sites/") && (strings.Contains(html, "/modules/") || strings.Contains(html, "/themes/")) {
		drupalConfirmed = true
	}

	// 3. Endpoint probes (fallback)
	if !wpConfirmed {
		wpLoginURL := strings.TrimSuffix(baseURL, "/") + "/wp-login.php"
		resp, err := hc.Get(ctx, wpLoginURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				wpConfirmed = true
			}
		}
	}

	// WordPress priority on ambiguous matches
	if wpConfirmed {
		return "wordpress"
	}
	if drupalConfirmed {
		return "drupal"
	}

	return ""
}
