# AGENTS.md

## Build & Run

```bash
go build -o goCmsCheck ./cmd/goCmsCheck
./goCmsCheck --url <target>
```

Always use `go build` then run the binary—never `go run main.go`. Delete the binary after testing.

## Project Structure

- `cmd/goCmsCheck/main.go` — Entry point, CLI flags
- `internal/scanner/httpclient.go` — HTTP client with rate limiting (5 req/s global)
- `internal/scanner/recon.go` — Common recon checks, CMS detection
- `internal/scanner/wordpress.go` — WP scans: version, vuln (WPVulnerability API), XML-RPC
- `internal/scanner/drupal.go` — Drupal scans: version, vuln (OSV.dev), enumeration
- `internal/report/report.go` — Report generation with colored output

## Commands & Flags

- `--url` (required) — Target URL or hostname
- `--output` — Save report to file
- `--all-plugins` — Scan all plugins (default: top 10)
- `--all-modules` — Scan all modules (default: top 10)
- `--server` — Pingback test server (WordPress only)

## API Integration

- WPVulnerability API: `https://www.wpvulnerability.net/` (5 req/s)
- OSV.dev API: `https://api.osv.dev/v1/query` (5 req/s)
- In-memory caching for both APIs

## Go Conventions

- Tabs for indentation
- Use `go fmt` before committing
- camelCase for functions/variables, ALLCAPS for constants
- Keep files short; separate into packages under main module if needed
