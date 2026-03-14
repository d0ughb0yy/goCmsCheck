# goCmsCheck

A Go-based CMS security scanner that performs reconnaissance and vulnerability checks on WordPress and Drupal sites.

## Features

### Common Checks
- Fetch and parse `robots.txt`
- Retrieve HTTP headers
- Check for exposed `.git` directory
- Check for exposed `.env` file
- Scan common admin and login endpoints (`/admin`, `/administrator`, `/dashboard`, etc.)

### WordPress Specific Scans
- **Version Detection**: Extracts WordPress version from CSS files or readme.html
- **Vulnerability Scanning**: Queries WPVulnerability API for core, theme, and plugin vulnerabilities
- **Login Endpoint Detection**: Checks `/wp-login.php`, `/wp-admin`
- **XML-RPC Analysis**:
  - Detects if XML-RPC is enabled
  - Lists available methods
  - Performs pingback vulnerability check (requires `--server` flag)
- **Dynamic Plugin & Theme Detection**: Parses homepage HTML to find active plugins and themes

### Drupal Specific Scans
- **Version Detection**: Extracts version from meta tags or CHANGELOG.txt
- **Vulnerability Scanning**: Queries OSV.dev API for core and module vulnerabilities
- **Login/Admin Endpoint Detection**: Checks `/user/login`, `/user/register`, `/admin`, etc.
- **Node/User Enumeration**: Scans `/node/<id>` (1-100) and `/user/<id>` (1-100) at 5 req/s
- **Module & Theme Detection**: Parses homepage HTML to find active modules and themes
- **Configuration File Checks**: Attempts to fetch `.yml` config files (core.extension.yml, etc.)

## Installation

```bash
go build -o goCmsCheck ./cmd/goCmsCheck
```

Or in the project directory:
```bash
go build -o goCmsCheck ./cmd/goCmsCheck
./goCmsCheck --help
```

## Usage

### Basic Usage
```bash
# Common checks only
./goCmsCheck --url example.com

# WordPress scan
./goCmsCheck --url example.com --cms wordpress

# Drupal scan
./goCmsCheck --url example.com --cms drupal
```

### WordPress Advanced Options
```bash
# Scan all plugins found (default: top 10)
./goCmsCheck --url example.com --cms wordpress --all-plugins

# Pingback vulnerability check
./goCmsCheck --url example.com --cms wordpress --server https://your-server.com/pingback

# Custom output file
./goCmsCheck --url example.com --cms wordpress --output report.txt
```

## API Integration

### WPVulnerability API
- **Endpoint**: `https://www.wpvulnerability.net/`
- **Rate Limit**: 5 requests/second (global limit)
- **Caching**: In-memory cache to avoid redundant requests
- **Data Sources**: Core, plugin, and theme vulnerabilities

### OSV.dev API (Drupal)
- **Endpoint**: `https://api.osv.dev/v1/query`
- **Rate Limit**: 5 requests/second (global limit)
- **Caching**: In-memory cache to avoid redundant requests
- **Data Sources**: Core and module vulnerabilities
- **Package Format**: `drupal/<module-name>` with ecosystem `Packagist:https://packages.drupal.org/8`

## Architecture

### Project Structure
```
goCmsCheck/
├── cmd/goCmsCheck/main.go          # Main entry point
├── internal/
│   ├── scanner/
│   │   ├── httpclient.go           # HTTP client with rate limiting
│   │   ├── recon.go                # Common reconnaissance checks
│   │   ├── wordpress.go            # WordPress-specific scanning
│   │   └── drupal.go               # Drupal-specific scanning
│   └── report/
│       └── report.go               # Report generation (fatih/color)
├── .agents/
│   ├── agents.md                   # Agent guidelines
│   ├── go-coding-practices.md      # Go coding standards
│   └── plan.md                     # Project plan
├── CHANGELOG                       # Change log
├── go.mod                          # Module file (with fatih/color v1.18.0)
├── go.sum                          # Dependency checksums
└── README.md                       # Documentation
```

### Key Design Decisions
1. **Rate Limiting**: Global 5 req/s limit to respect API and target servers
2. **Caching**: In-memory cache for WPVulnerability API and OSV.dev API responses
3. **Dynamic Parsing**: Extracts plugins/themes from HTML rather than hardcoding
4. **Plugin Limit**: Default top 10 plugins to avoid excessive scanning
5. **Module Limit**: Default top 10 modules for Drupal scanning

## Examples

### Example 1: Basic WordPress Scan (stdout only, colored output)
```bash
./goCmsCheck --url example.com --cms wordpress
```

### Example 2: Save to File (plain text)
```bash
./goCmsCheck --url example.com --cms wordpress --output wp_report.txt
```

**Note**: With `--output`, the report is saved to file as plain text
```
Report for https://example.com -- 2026-03-14 14:30:00

robots.txt:
-------------
[content]

Common Checks:
----------------
[+] Found endpoint: /.git [status 403]

WordPress Scan:
--------------------
Version: 6.6.1
[!] Vulnerability: CVE-2024-1234 (Severity: high, Fixed in: 6.6.2)
[+] Found endpoint: https://example.com/wp-login.php [status 200]
[+] XML-RPC enabled
[+] Theme in use: twentytwentyfour
[!] Theme vulnerabilities:
    - CVE-2024-5678
[+] Plugins found:
    - elementor (Vulnerable)
        [!] CVE-2021-24891
        [!] CVE-2021-24202
```

### Example 3: Full Plugin Scan
```bash
./goCmsCheck --url example.com --cms wordpress --all-plugins
```

### Example 4: Pingback Check (stdout only)
```bash
./goCmsCheck --url example.com --cms wordpress --server https://myserver.com/pingback
```

### Example 5: Drupal Scan (stdout only, colored output)
```bash
./goCmsCheck --url example.com --cms drupal
```

### Example 6: Drupal Scan with File Output (plain text)
```bash
./goCmsCheck --url example.com --cms drupal --output drupal_report.txt
```

### Example 7: Full Drupal Module Scan with File Output
```bash
./goCmsCheck --url example.com --cms drupal --all-modules --output drupal_full_report.txt
```

### Example 8: Pingback Check with File Output
```bash
./goCmsCheck --url example.com --cms wordpress --server https://myserver.com/pingback --output pingback_report.txt
```

## Limitations

1. **API Dependency**: Vulnerability data relies on WPVulnerability API and OSV.dev API availability
2. **Dynamic Parsing**: Plugin/theme detection depends on HTML structure; some may not be detected
3. **Configuration Files**: Drupal config file checks may not work on all installations

## To Do

1. **Add plugin list**: Add most common plugins so plugin and theme detection do not rely only on dynamic parsing of HTML