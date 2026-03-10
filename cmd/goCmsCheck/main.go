package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/d0ughb0yy/goCmsCheck/internal/report"
	"github.com/d0ughb0yy/goCmsCheck/internal/scanner"
)

func main() {
	// Define flags
	url := flag.String("url", "", "URL or hostname to scan (required)")
	cms := flag.String("cms", "", "CMS type: wordpress or drupal (optional)")
	server := flag.String("server", "", "User-controlled server for pingback test (optional, only for --cms wordpress)")
	output := flag.String("output", "goCmsChecker_output.txt", "Output file path (default: goCmsChecker_output.txt)")
	help := flag.Bool("help", false, "Show usage information")

	flag.Parse()

	// Show help if requested or if no flags provided
	if *help || len(os.Args) == 1 {
		showUsage()
		os.Exit(0)
	}

	// Validate required flags
	if *url == "" {
		fmt.Fprintln(os.Stderr, "Error: --url flag is required")
		showUsage()
		os.Exit(1)
	}

	// Validate CMS flag if provided
	if *cms != "" && *cms != "wordpress" && *cms != "drupal" {
		fmt.Fprintln(os.Stderr, "Error: --cms must be 'wordpress' or 'drupal'")
		showUsage()
		os.Exit(1)
	}

	// Validate server flag usage
	if *server != "" && *cms != "wordpress" {
		fmt.Fprintln(os.Stderr, "Error: --server flag is only valid with --cms wordpress")
		showUsage()
		os.Exit(1)
	}

	// Process URL - add https:// if needed
	processedURL := processURL(*url)

	fmt.Printf("Scanning: %s\n", processedURL)
	if *cms != "" {
		fmt.Printf("CMS: %s\n", *cms)
	}
	fmt.Printf("Output: %s\n", *output)

	// Create HTTP client with rate limiting
	httpClient := scanner.NewHTTPClient()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Perform common recon checks (always run)
	fmt.Println("\nPerforming common recon checks...")
	commonChecks, err := httpClient.RunCommonChecks(ctx, processedURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during common checks: %v\n", err)
	}

	// Generate report
	reportInstance := report.NewReport(processedURL, *output, commonChecks)
	reportText := reportInstance.Generate()

	// Output report (stdout and file)
	if err := reportInstance.Output(reportText); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
	}

	// Based on CMS flag, perform CMS-specific scans
	switch *cms {
	case "wordpress":
		fmt.Println("\nWordPress scanning logic will be added in Phase 3")
	case "drupal":
		fmt.Println("\nDrupal scanning logic will be added in Phase 4")
	default:
		fmt.Println("\nNo CMS specified - common checks only")
	}
}

func showUsage() {
	fmt.Println("GoCmsCheck - CMS Security Scanner")
	fmt.Println("Usage:")
	fmt.Println("  goCmsCheck --url <URL> [flags]")
	fmt.Println()
	fmt.Println("Flags:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  goCmsCheck --url example.com")
	fmt.Println("  goCmsCheck --url https://example.com --cms wordpress")
	fmt.Println("  goCmsCheck --url example.com --cms drupal --output scan_report.txt")
	fmt.Println("  goCmsCheck --url example.com --cms wordpress --server https://myserver.com/pingback")
}

func processURL(url string) string {
	// Add https:// if URL doesn't start with http:// or https://
	if len(url) >= 8 && (url[:7] == "http://" || url[:8] == "https://") {
		return url
	}
	return "https://" + url
}
