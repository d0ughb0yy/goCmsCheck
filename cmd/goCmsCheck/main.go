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
	server := flag.String("server", "", "User-controlled server for pingback test (optional, WordPress only)")
	output := flag.String("output", "", "Output file path (optional, if not provided only stdout)")
	allPlugins := flag.Bool("all-plugins", false, "Scan all plugins found (default: scan top 10)")
	allModules := flag.Bool("all-modules", false, "Scan all modules found (default: scan top 10)")
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

	// Process URL - add https:// if needed
	processedURL := processURL(*url)

	fmt.Printf("Scanning: %s\n", processedURL)
	if *output != "" {
		fmt.Printf("Output: %s\n", *output)
	}

	// Create HTTP client with rate limiting
	httpClient := scanner.NewHTTPClient()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*60*time.Second)
	defer cancel()

	// Perform common recon checks (always run, includes CMS detection)
	fmt.Println("Performing common recon checks...")
	commonChecks, err := httpClient.RunCommonChecks(ctx, processedURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during common checks: %v\n", err)
	}

	var wordpressChecks *scanner.WordPressChecks
	var drupalChecks *scanner.DrupalChecks
	// Based on detected CMS, perform CMS-specific scans
	switch commonChecks.CMSDetected {
	case "wordpress":
		fmt.Println("CMS detected: WordPress")
		fmt.Println("Performing WordPress scanning...")
		wordpressChecks, err = httpClient.ScanWordPress(ctx, processedURL, *server, *allPlugins, commonChecks.HomepageHTML)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during WordPress scan: %v\n", err)
		}
	case "drupal":
		fmt.Println("CMS detected: Drupal")
		fmt.Println("Performing Drupal scanning...")
		drupalChecks, err = httpClient.ScanDrupal(ctx, processedURL, *allModules, commonChecks.HomepageHTML)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during Drupal scan: %v\n", err)
		}
	default:
		fmt.Println("No CMS detected - common checks only")
	}

	// Generate report
	fmt.Println()
	reportInstance := report.NewReport(processedURL, *output, commonChecks, wordpressChecks, drupalChecks)
	reportText := reportInstance.Generate()

	// Output report (stdout and file if output specified)
	if err := reportInstance.Output(reportText); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
	}

	// Print file save message if output was specified
	if *output != "" {
		fmt.Printf("\nReport saved to: %s\n", *output)
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
	fmt.Println("  goCmsCheck --url example.com --output report.txt")
	fmt.Println("  goCmsCheck --url example.com --all-plugins --output report.txt")
	fmt.Println("  goCmsCheck --url example.com --all-modules --output report.txt")
	fmt.Println("  goCmsCheck --url example.com --server https://myserver.com/pingback")
}

func processURL(url string) string {
	// Add https:// if URL doesn't start with http:// or https://
	if len(url) >= 8 && (url[:7] == "http://" || url[:8] == "https://") {
		return url
	}
	return "https://" + url
}
