package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/d0ughb0yy/goCmsCheck/internal/scanner"
)

// Report generates and outputs the scan report
type Report struct {
	URL          string
	Timestamp    time.Time
	CommonChecks *scanner.CommonChecks
	OutputFile   string
}

// NewReport creates a new Report instance
func NewReport(url, outputFile string, commonChecks *scanner.CommonChecks) *Report {
	return &Report{
		URL:          url,
		Timestamp:    time.Now(),
		CommonChecks: commonChecks,
		OutputFile:   outputFile,
	}
}

// ANSI color codes
const (
	ansiReset    = "\033[0m"
	ansiBold     = "\033[1m"
	ansiCyan     = "\033[36m"
	ansiBoldCyan = "\033[1;36m"
)

// Generate generates the report text
func (r *Report) Generate() string {
	var builder strings.Builder

	// Title with colors (for stdout)
	builder.WriteString(ansiBoldCyan)
	builder.WriteString("Report for ")
	builder.WriteString(r.URL)
	builder.WriteString(" -- ")
	builder.WriteString(r.Timestamp.Format("2006-01-02 15:04:05"))
	builder.WriteString(ansiReset)
	builder.WriteString("\n\n")

	// robots.txt section
	builder.WriteString(ansiBold)
	builder.WriteString("robots.txt:")
	builder.WriteString(ansiReset)
	builder.WriteString("\n")
	builder.WriteString(ansiBold)
	builder.WriteString("-------------")
	builder.WriteString(ansiReset)
	builder.WriteString("\n")
	if r.CommonChecks.RobotsTxt != "" {
		builder.WriteString(r.CommonChecks.RobotsTxt)
	} else {
		builder.WriteString("No robots.txt found\n")
	}

	// Common Checks section
	builder.WriteString("\n")
	builder.WriteString(ansiBold)
	builder.WriteString("Common Checks:")
	builder.WriteString(ansiReset)
	builder.WriteString("\n")
	builder.WriteString(ansiBold)
	builder.WriteString("----------------")
	builder.WriteString(ansiReset)
	builder.WriteString("\n")

	// .git folder
	if r.CommonChecks.GitExposed {
		builder.WriteString(fmt.Sprintf("[+] Found endpoint: /.git [status %d]\n", r.CommonChecks.GitStatusCode))
	}

	// .env file
	if r.CommonChecks.EnvExposed {
		builder.WriteString(fmt.Sprintf("[+] Found endpoint: /.env [status %d]\n", r.CommonChecks.EnvStatusCode))
	}

	// Admin endpoints (now called just "endpoints")
	for _, endpoint := range r.CommonChecks.AdminEndpoints {
		if endpoint.StatusCode == 200 || endpoint.StatusCode == 403 || endpoint.StatusCode == 302 || endpoint.StatusCode == 301 {
			// Extract path from full URL
			urlParts := strings.SplitN(endpoint.URL, "://", 2)
			path := endpoint.URL
			if len(urlParts) == 2 {
				// Remove host part
				hostAndPath := urlParts[1]
				if slashIdx := strings.Index(hostAndPath, "/"); slashIdx != -1 {
					path = hostAndPath[slashIdx:]
				} else {
					path = "/"
				}
			}
			builder.WriteString(fmt.Sprintf("[+] Found endpoint: %s [status %d]", path, endpoint.StatusCode))
			if endpoint.RedirectURL != "" {
				builder.WriteString(fmt.Sprintf(" [redirect: %s]", endpoint.RedirectURL))
			}
			builder.WriteString("\n")
		}
	}

	// Headers section
	builder.WriteString("\nHeaders returned for request " + r.URL + ":\n")
	builder.WriteString("---------------------\n")
	for key, value := range r.CommonChecks.Headers {
		builder.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	return builder.String()
}

// Output writes the report to stdout and file
func (r *Report) Output(reportText string) error {
	// Print to stdout (with colors if applicable)
	fmt.Println(reportText)

	// Write to file
	file, err := os.Create(r.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write plain text (without ANSI codes) to file
	plainText := stripANSICodes(reportText)
	_, err = file.WriteString(plainText)
	if err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}

	fmt.Printf("\nReport saved to: %s\n", r.OutputFile)
	return nil
}

// stripANSICodes removes ANSI color codes from text for plain text output
func stripANSICodes(text string) string {
	// Remove all ANSI escape sequences (starting with \033[)
	var result strings.Builder
	i := 0
	for i < len(text) {
		if text[i] == '\033' && i+1 < len(text) && text[i+1] == '[' {
			// Skip until the 'm' character that ends the sequence
			for i < len(text) && text[i] != 'm' {
				i++
			}
			i++ // Skip the 'm'
		} else {
			result.WriteByte(text[i])
			i++
		}
	}
	return result.String()
}
