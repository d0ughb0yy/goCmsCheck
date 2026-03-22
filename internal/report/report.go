package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/d0ughb0yy/goCmsCheck/internal/scanner"
	"github.com/fatih/color"
)

// Report generates and outputs the scan report
type Report struct {
	URL             string
	Timestamp       time.Time
	CommonChecks    *scanner.CommonChecks
	WordPressChecks *scanner.WordPressChecks
	DrupalChecks    *scanner.DrupalChecks
	OutputFile      string
}

// NewReport creates a new Report instance
func NewReport(url, outputFile string, commonChecks *scanner.CommonChecks, wordpressChecks *scanner.WordPressChecks, drupalChecks *scanner.DrupalChecks) *Report {
	return &Report{
		URL:             url,
		Timestamp:       time.Now(),
		CommonChecks:    commonChecks,
		WordPressChecks: wordpressChecks,
		DrupalChecks:    drupalChecks,
		OutputFile:      outputFile,
	}
}

// ANSI color codes using fatih/color
var (
	colorReset    = color.New(color.Reset).SprintFunc()
	colorBold     = color.New(color.Bold).SprintFunc()
	colorCyan     = color.New(color.FgCyan).SprintFunc()
	colorBoldCyan = color.New(color.Bold, color.FgCyan).SprintFunc()
)

// Generate generates the report text
func (r *Report) Generate() string {
	var builder strings.Builder

	// Title with colors (for stdout)
	builder.WriteString(colorBoldCyan("Report for ") + r.URL + " -- " + r.Timestamp.Format("2006-01-02 15:04:05"))
	builder.WriteString("\n\n")

	// robots.txt section
	builder.WriteString(colorBoldCyan("robots.txt:"))
	builder.WriteString("\n")
	builder.WriteString(colorBold("-------------"))
	builder.WriteString("\n")
	if r.CommonChecks.RobotsTxt != "" {
		builder.WriteString(r.CommonChecks.RobotsTxt)
	} else {
		builder.WriteString("No robots.txt found\n")
	}

	// Common Checks section
	builder.WriteString("\n")
	builder.WriteString(colorBoldCyan("Common Checks:"))
	builder.WriteString("\n")
	builder.WriteString(colorBold("----------------"))
	builder.WriteString("\n")

	// .git folder (only display if status is 200)
	if r.CommonChecks.GitExposed && r.CommonChecks.GitStatusCode == 200 {
		builder.WriteString(colorBold("[+] Found endpoint:") + fmt.Sprintf(" /.git [status %d]\n", r.CommonChecks.GitStatusCode))
	}

	// .env file (only display if status is 200)
	if r.CommonChecks.EnvExposed && r.CommonChecks.EnvStatusCode == 200 {
		builder.WriteString(colorBold("[+] Found endpoint:") + fmt.Sprintf(" /.env [status %d]\n", r.CommonChecks.EnvStatusCode))
	}

	// Admin endpoints (now called just "endpoints")
	for _, endpoint := range r.CommonChecks.AdminEndpoints {
		// Only show 200 or 30x redirects
		if endpoint.StatusCode == 200 || endpoint.StatusCode == 302 || endpoint.StatusCode == 301 {
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
			builder.WriteString(colorBold("[+] Found endpoint:") + fmt.Sprintf(" %s [status %d]", path, endpoint.StatusCode))
			if endpoint.RedirectURL != "" {
				builder.WriteString(fmt.Sprintf(" [redirect: %s]", endpoint.RedirectURL))
			}
			builder.WriteString("\n")
		}
	}

	// Headers section
	builder.WriteString("\n")
	builder.WriteString(colorBoldCyan("Headers returned for request " + r.URL + ":"))
	builder.WriteString("\n")
	builder.WriteString(colorBold("---------------------"))
	builder.WriteString("\n")
	for key, value := range r.CommonChecks.Headers {
		builder.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	// WordPress Scan section
	if r.WordPressChecks != nil {
		builder.WriteString("\n")
		builder.WriteString(colorBoldCyan("WordPress Scan:"))
		builder.WriteString("\n")
		builder.WriteString(colorBold("--------------------"))
		builder.WriteString("\n")

		// Version and Vulnerabilities
		if r.WordPressChecks.Version != "" {
			builder.WriteString(colorBold(""))
			builder.WriteString("Version:")
			builder.WriteString(colorReset(""))
			builder.WriteString(" " + r.WordPressChecks.Version + "\n")
			if len(r.WordPressChecks.Vulnerabilities) > 0 {
				for _, vuln := range r.WordPressChecks.Vulnerabilities {
					builder.WriteString(fmt.Sprintf("[!] Vulnerability: %s (CVE: %s, Severity: %s, Fixed in: %s)\n", vuln.Title, vuln.CVE, vuln.Severity, vuln.FixedIn))
				}
			}
		}

		// Login Endpoints
		if len(r.WordPressChecks.LoginEndpoints) > 0 {
			for _, ep := range r.WordPressChecks.LoginEndpoints {
				builder.WriteString(colorBold(""))
				builder.WriteString("[+] Found endpoint:")
				builder.WriteString(colorReset(""))
				builder.WriteString(fmt.Sprintf(" %s [status %d]\n", ep.URL, ep.StatusCode))
			}
		}

		// XML-RPC
		if r.WordPressChecks.XmlRpcEnabled {
			builder.WriteString(colorBold(""))
			builder.WriteString("[+] XML-RPC enabled")
			builder.WriteString(colorReset(""))
			builder.WriteString("\n")
			if len(r.WordPressChecks.XmlRpcMethods) > 0 {
				builder.WriteString("[!] Available methods:\n")
				for _, method := range r.WordPressChecks.XmlRpcMethods {
					builder.WriteString(fmt.Sprintf("    - %s\n", method))
				}
			}
		} else {
			builder.WriteString(colorBold(""))
			builder.WriteString("[-] XML-RPC disabled")
			builder.WriteString(colorReset(""))
			builder.WriteString("\n")
		}

		// Pingback Check
		if r.WordPressChecks.PingbackCheck.Enabled {
			builder.WriteString(colorBold(""))
			builder.WriteString("[+] Pingback enabled")
			builder.WriteString(colorReset(""))
			builder.WriteString("\n")
			if r.WordPressChecks.PingbackCheck.Error != "" {
				builder.WriteString(fmt.Sprintf("[!] Pingback check: %s\n", r.WordPressChecks.PingbackCheck.Error))
			}
		} else if r.WordPressChecks.PingbackCheck.Error != "" {
			builder.WriteString(colorBold(""))
			builder.WriteString("[-] Pingback disabled")
			builder.WriteString(colorReset(""))
			builder.WriteString(fmt.Sprintf(": %s\n", r.WordPressChecks.PingbackCheck.Error))
		}

		// Theme
		if r.WordPressChecks.Theme.Slug != "" {
			builder.WriteString(colorBold(""))
			builder.WriteString("[+] Theme in use:")
			builder.WriteString(colorReset(""))
			builder.WriteString(" " + r.WordPressChecks.Theme.Slug + "\n")
			if r.WordPressChecks.Theme.Vulnerability {
				builder.WriteString("[!] Theme vulnerabilities:\n")
				for _, cve := range r.WordPressChecks.Theme.CVEs {
					builder.WriteString(fmt.Sprintf("    - %s\n", cve))
				}
			}
		}

		// Plugins
		if len(r.WordPressChecks.Plugins) > 0 {
			builder.WriteString(colorBold(""))
			builder.WriteString("[+] Plugins found:")
			builder.WriteString(colorReset(""))
			builder.WriteString("\n")
			for _, plugin := range r.WordPressChecks.Plugins {
				if plugin.Vulnerability {
					builder.WriteString(fmt.Sprintf("    - %s (Vulnerable)\n", plugin.Name))
					for _, cve := range plugin.CVEs {
						builder.WriteString(fmt.Sprintf("        [!] %s\n", cve))
					}
				} else {
					builder.WriteString(fmt.Sprintf("    - %s\n", plugin.Name))
				}
			}
		}
	}

	// Drupal Scan section
	if r.DrupalChecks != nil {
		builder.WriteString("\n")
		builder.WriteString(colorBoldCyan("Drupal Scan:"))
		builder.WriteString("\n")
		builder.WriteString(colorBold("--------------------"))
		builder.WriteString("\n")

		// Version and Vulnerabilities
		if r.DrupalChecks.Version != "" {
			builder.WriteString(colorBold(""))
			builder.WriteString("Version:")
			builder.WriteString(colorReset(""))
			builder.WriteString(" " + r.DrupalChecks.Version + "\n")
			if len(r.DrupalChecks.Vulnerabilities) > 0 {
				for _, vuln := range r.DrupalChecks.Vulnerabilities {
					builder.WriteString(fmt.Sprintf("[!] Vulnerability: %s (CVE: %s, Severity: %s, Fixed in: %s)\n", vuln.Title, vuln.CVE, vuln.Severity, vuln.FixedIn))
				}
			}
		}

		// Login Endpoints
		if len(r.DrupalChecks.LoginEndpoints) > 0 {
			for _, ep := range r.DrupalChecks.LoginEndpoints {
				builder.WriteString(colorBold(""))
				builder.WriteString("[+] Found endpoint:")
				builder.WriteString(colorReset(""))
				builder.WriteString(fmt.Sprintf(" %s [status %d]\n", ep.URL, ep.StatusCode))
			}
		}

		// Admin Endpoints
		if len(r.DrupalChecks.AdminEndpoints) > 0 {
			for _, ep := range r.DrupalChecks.AdminEndpoints {
				builder.WriteString(colorBold(""))
				builder.WriteString("[+] Found endpoint:")
				builder.WriteString(colorReset(""))
				builder.WriteString(fmt.Sprintf(" %s [status %d]\n", ep.URL, ep.StatusCode))
			}
		}

		// Nodes
		if len(r.DrupalChecks.Nodes) > 0 {
			for _, ep := range r.DrupalChecks.Nodes {
				// Extract path from full URL
				urlParts := strings.SplitN(ep.URL, "://", 2)
				path := ep.URL
				if len(urlParts) == 2 {
					hostAndPath := urlParts[1]
					if slashIdx := strings.Index(hostAndPath, "/"); slashIdx != -1 {
						path = hostAndPath[slashIdx:]
					}
				}
				builder.WriteString(colorBold(""))
				builder.WriteString("[+] Found endpoint:")
				builder.WriteString(colorReset(""))
				builder.WriteString(fmt.Sprintf(" %s [status %d]\n", path, ep.StatusCode))
			}
		}

		// Users
		if len(r.DrupalChecks.Users) > 0 {
			for _, ep := range r.DrupalChecks.Users {
				// Extract path from full URL
				urlParts := strings.SplitN(ep.URL, "://", 2)
				path := ep.URL
				if len(urlParts) == 2 {
					hostAndPath := urlParts[1]
					if slashIdx := strings.Index(hostAndPath, "/"); slashIdx != -1 {
						path = hostAndPath[slashIdx:]
					}
				}
				builder.WriteString(colorBold(""))
				builder.WriteString("[+] Found endpoint:")
				builder.WriteString(colorReset(""))
				builder.WriteString(fmt.Sprintf(" %s [status %d]\n", path, ep.StatusCode))
			}
		}

		// Modules
		if len(r.DrupalChecks.Modules) > 0 {
			builder.WriteString(colorBold(""))
			builder.WriteString("[+] Modules found:")
			builder.WriteString(colorReset(""))
			builder.WriteString("\n")
			for _, module := range r.DrupalChecks.Modules {
				if module.Vulnerability {
					builder.WriteString(fmt.Sprintf("    - %s (Vulnerable)\n", module.Name))
					for _, cve := range module.CVEs {
						builder.WriteString(fmt.Sprintf("        [!] %s\n", cve))
					}
				} else {
					builder.WriteString(fmt.Sprintf("    - %s\n", module.Name))
				}
			}
		}

		// Theme
		if r.DrupalChecks.Theme.Slug != "" {
			builder.WriteString(colorBold(""))
			builder.WriteString("[+] Theme in use:")
			builder.WriteString(colorReset(""))
			builder.WriteString(" " + r.DrupalChecks.Theme.Slug + "\n")
			if r.DrupalChecks.Theme.Vulnerability {
				builder.WriteString("[!] Theme vulnerabilities:\n")
				for _, cve := range r.DrupalChecks.Theme.CVEs {
					builder.WriteString(fmt.Sprintf("    - %s\n", cve))
				}
			}
		}

		// Configuration Files
		if len(r.DrupalChecks.ConfigFiles) > 0 {
			builder.WriteString(colorBold(""))
			builder.WriteString("[+] Configuration files:")
			builder.WriteString(colorReset(""))
			builder.WriteString("\n")
			for file, content := range r.DrupalChecks.ConfigFiles {
				builder.WriteString(fmt.Sprintf("    %s:\n", file))
				// Display first 10 lines of content
				lines := strings.Split(content, "\n")
				for i, line := range lines {
					if i >= 10 {
						builder.WriteString("        ... (truncated)\n")
						break
					}
					if line != "" {
						builder.WriteString(fmt.Sprintf("        %s\n", line))
					}
				}
			}
		}
	}

	return builder.String()
}

// Output writes the report to stdout and optionally to file
func (r *Report) Output(reportText string) error {
	// Always print to stdout (with colors if applicable)
	fmt.Println(reportText)

	// Only write to file if OutputFile is specified
	if r.OutputFile != "" {
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
	}

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
