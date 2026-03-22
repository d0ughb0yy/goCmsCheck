package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	// UserAgent is a common Chrome User-Agent
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// HTTPClient wraps http.Client with rate limiting and retry logic
type HTTPClient struct {
	client     *http.Client
	limiter    *rate.Limiter
	maxRetries int
	retryDelay time.Duration
}

// NewHTTPClient creates a new HTTPClient with rate limiting (5 req/s)
func NewHTTPClient() *HTTPClient {
	// Rate limiter: 5 requests per second
	limiter := rate.NewLimiter(rate.Limit(5), 1)

	// Configure TLS to skip certificate verification (for local/testing environments)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &HTTPClient{
		client:     client,
		limiter:    limiter,
		maxRetries: 5,
		retryDelay: 1 * time.Second,
	}
}

// DoRequest performs an HTTP request with rate limiting and retry logic
func (hc *HTTPClient) DoRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)

	// Wait for rate limiter
	if err := hc.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}

	// Retry logic
	var lastErr error
	for attempt := 0; attempt <= hc.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(hc.retryDelay * time.Duration(attempt))
		}

		resp, err := hc.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Check for 429 (Too Many Requests) - abort immediately
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			return nil, fmt.Errorf("rate limited (HTTP 429) - aborting")
		}

		// Check for server errors (5xx) - retry
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			resp.Body.Close()
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// Get performs a GET request
func (hc *HTTPClient) Get(ctx context.Context, url string) (*http.Response, error) {
	return hc.DoRequest(ctx, "GET", url, nil)
}

// Post performs a POST request with rate limiting and retry logic
func (hc *HTTPClient) Post(ctx context.Context, url string, body string) (*http.Response, error) {
	return hc.DoRequest(ctx, "POST", url, strings.NewReader(body))
}
