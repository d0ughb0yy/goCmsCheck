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
	baseDelay time.Duration
	maxDelay  time.Duration
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
		baseDelay: 1 * time.Second,
		maxDelay:  10 * time.Second,
	}
}

// DoRequest performs an HTTP request with rate limiting and retry logic.
// Rate limiting: waits for global 5 req/s token bucket before sending.
// Retry logic: exponential backoff on 5xx errors (1s->2s->4s->8s->10s capped), aborts on 429.
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

	// Retry logic: exponential backoff on server errors (5xx)
	// - attempt 0: original request
	// - attempt 1-4: delay = min(baseDelay * 2^attempt, maxDelay)
	// - attempt 5: max retries exceeded, return error
	var lastErr error
	for attempt := 0; attempt <= hc.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: baseDelay * 2^attempt, capped at maxDelay
			delay := hc.baseDelay * time.Duration(1<<uint(attempt))
			if delay > hc.maxDelay {
				delay = hc.maxDelay
			}
			time.Sleep(delay)
		}

		resp, err := hc.client.Do(req)
		if err != nil {
			lastErr = err
			continue // Network error, retry
		}

		// HTTP 429: server-side rate limiting detected, abort immediately
		// This differs from 5xx retries as it indicates we should stop entirely
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			return nil, fmt.Errorf("rate limited (HTTP 429) - aborting")
		}

		// Server error (5xx): transient issue, retry with backoff
		// Different from 429 as the server may recover
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			resp.Body.Close()
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			continue
		}

		// Success (2xx/3xx) or client error (4xx): return immediately
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
