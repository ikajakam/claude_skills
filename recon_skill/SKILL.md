---
name: recon-subdomain-tech-detection
description: Expert guidance for reconnaissance using subfinder and httpx during penetration testing, including subdomain enumeration, technology detection, and asset discovery
---

# Reconnaissance Skill: Subfinder + Httpx

## Overview
This skill combines two powerful reconnaissance tools for comprehensive subdomain enumeration and technology detection:
- **Subfinder**: Fast passive subdomain discovery tool that uses multiple sources
- **Httpx**: Fast and multi-purpose HTTP toolkit for probing, tech detection, and asset analysis

Together, they form a complete reconnaissance workflow for discovering and analyzing web assets during penetration testing.

## Installation

### Subfinder
```bash
# Using Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Using Homebrew (macOS)
brew install subfinder

# Binary download
# Download from: https://github.com/projectdiscovery/subfinder/releases/latest

# Verify installation
subfinder -version
```

### Httpx
```bash
# Using Go
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Using Homebrew (macOS)
brew install httpx

# Binary download
# Download from: https://github.com/projectdiscovery/httpx/releases/latest

# Verify installation
httpx -version
```

## Part 1: Subfinder - Subdomain Enumeration

### Core Concepts

#### What Subfinder Does
Subfinder performs **passive subdomain enumeration** by querying:
- Certificate transparency logs (crt.sh, censys, certspotter)
- Search engines (Google, Bing, Yahoo)
- DNS databases (DNSDumpster, Threatcrowd, VirusTotal)
- Threat intelligence platforms (AlienVault, Shodan, SecurityTrails)
- And 30+ other sources

**Key Advantages:**
- Completely passive (doesn't touch target infrastructure)
- Fast concurrent queries across multiple sources
- High accuracy with minimal false positives
- API integration for premium data sources
- Easy integration with other tools via piping

### Basic Usage

#### Simple Subdomain Discovery
```bash
# Basic subdomain enumeration
subfinder -d target.com

# With verbose output
subfinder -d target.com -v

# Silent mode (subdomains only, no banner)
subfinder -d target.com -silent

# Colored output
subfinder -d target.com -nC=false
```

#### Multiple Domains
```bash
# Multiple domains via command line
subfinder -d target.com,example.com,test.com

# From a file (one domain per line)
subfinder -dL domains.txt

# Pipe domains
cat domains.txt | subfinder
```

### Output Options

```bash
# Save to file
subfinder -d target.com -o subdomains.txt

# JSON output (includes metadata)
subfinder -d target.com -oJ -o results.json

# CSV output
subfinder -d target.com -oT -o results.csv

# Append to existing file (don't overwrite)
subfinder -d target.com -o subdomains.txt -nW

# Output with IP addresses resolved
subfinder -d target.com -oI
```

### Source Management

#### Using Specific Sources
```bash
# List all available sources
subfinder -ls

# Use only specific sources
subfinder -d target.com -sources crtsh,virustotal,shodan

# Exclude specific sources
subfinder -d target.com -exclude-sources github

# Use all sources (default behavior)
subfinder -d target.com -all
```

#### API Configuration
Create `~/.config/subfinder/provider-config.yaml`:

```yaml
# Free sources (no API key needed)
# - crtsh, certspotter, hackertarget, dnsdumpster, and more

# Paid/API sources (better results)
binaryedge:
  - 0bf8919b-aab9-42e4-9574-d3b639324597

censys:
  - ac244e2f-b635-4581-878a-33f4e79a2c13:dd510d6e-1b6e-4655-83f6-f347b363def9

chaos:
  - d23a554bbc1aabb208c9acfbd2dd41ce718f3e67e8c88a30e84557c90f4f01ab

github:
  - ghp_lkyJGU3jv1xmwk4SDXavrLDJ4dl2pSJMzj4X

shodan:
  - AAAAClP1bJJSRMEYJazgwhJKrggRwKA

securitytrails:
  - example-api-key-here

virustotal:
  - example-api-key-here

zoomeye:
  - username:password
```

**Pro Tip:** Even without API keys, subfinder provides excellent results from free sources like crt.sh and certspotter.

### Filtering and Matching

```bash
# Only show subdomains matching regex
subfinder -d target.com -m '.*\.api\..*'

# Only show subdomains with specific words
subfinder -d target.com -match 'admin,dev,staging'

# Filter out subdomains matching pattern
subfinder -d target.com -f '.*\.cdn\..*'

# Remove wildcards
subfinder -d target.com -nW
```

### DNS Resolution and Verification

```bash
# Resolve IP addresses
subfinder -d target.com -rL resolvers.txt

# Use custom DNS resolvers
subfinder -d target.com -r 8.8.8.8,1.1.1.1

# Only active subdomains (with valid DNS records)
subfinder -d target.com -active

# Verify subdomains with custom resolvers
subfinder -d target.com -r 8.8.8.8 -nW -v
```

### Rate Limiting and Performance

```bash
# Limit concurrent requests per source (default: 10)
subfinder -d target.com -rl 5

# Set timeout for sources (seconds)
subfinder -d target.com -timeout 30

# Maximum enumeration time
subfinder -d target.com -max-time 10

# Number of recursive subdomain discoveries
subfinder -d target.com -recursive
```

### Advanced Features

#### Recursive Enumeration
```bash
# Find subdomains of subdomains (one level)
subfinder -d target.com -recursive

# Example: finds dev.staging.target.com if staging.target.com exists
```

#### Integration with Other Tools
```bash
# Pipe to httpx for live host detection
subfinder -d target.com -silent | httpx -silent

# Pipe to nuclei for vulnerability scanning
subfinder -d target.com -silent | httpx -silent | nuclei -t cves/

# Pipe to naabu for port scanning
subfinder -d target.com -silent | naabu -silent

# Chain with dnsx for DNS records
subfinder -d target.com -silent | dnsx -resp
```

## Part 2: Httpx - HTTP Probing and Technology Detection

### Core Concepts

#### What Httpx Does
Httpx is a multi-purpose HTTP toolkit that:
- Probes for live web servers and applications
- Detects web technologies (CMS, frameworks, servers)
- Extracts titles, status codes, content lengths
- Screenshots web pages
- Identifies web servers and versions
- Extracts headers, cookies, and response data
- Tests for common vulnerabilities
- Supports massive scale with high concurrency

**Key Advantages:**
- Extremely fast (handles thousands of URLs)
- Rich feature set for recon and enumeration
- Technology fingerprinting built-in
- Pipeline-friendly (stdin/stdout)
- Flexible output formats (JSON, CSV, text)

### Basic Usage

#### Simple HTTP Probing
```bash
# Probe a single URL
httpx -u https://target.com

# Probe multiple URLs from file
httpx -l urls.txt

# Probe from stdin (pipe)
cat urls.txt | httpx

# Silent mode (URLs only)
httpx -l urls.txt -silent

# Verbose output
httpx -l urls.txt -verbose
```

#### Common Workflow with Subfinder
```bash
# Find subdomains and probe them
subfinder -d target.com -silent | httpx -silent

# With technology detection
subfinder -d target.com -silent | httpx -silent -tech-detect

# Save results
subfinder -d target.com -silent | httpx -silent -o live-hosts.txt
```

### Technology Detection

#### Basic Tech Detection
```bash
# Detect web technologies
httpx -l urls.txt -tech-detect

# With specific tech output
httpx -l urls.txt -tech-detect -json -o results.json

# Silent mode with tech
subfinder -d target.com -silent | httpx -silent -tech-detect
```

**Technologies Detected:**
- Web Servers: Apache, Nginx, IIS, Tomcat, etc.
- Programming Languages: PHP, Python, Ruby, Node.js, ASP.NET
- CMS: WordPress, Joomla, Drupal, Magento
- Frameworks: Laravel, Django, React, Angular, Vue.js
- CDN: Cloudflare, Akamai, Fastly
- Analytics: Google Analytics, Matomo
- Security: WAF, SSL/TLS versions
- And 1000+ other technologies

#### Comprehensive Tech Analysis
```bash
# Full tech stack with all details
httpx -l urls.txt -tech-detect -status-code -title -web-server -content-length -json

# Output format:
# {"url":"https://target.com","status-code":200,"title":"Example","webserver":"nginx/1.18","technologies":["nginx:1.18","php:7.4","wordpress:5.9"]}
```

### Information Extraction

#### Status Codes and Responses
```bash
# Show status codes
httpx -l urls.txt -status-code

# Filter by status code
httpx -l urls.txt -status-code -mc 200,301,302

# Filter out status codes
httpx -l urls.txt -status-code -fc 404,403

# Match response content
httpx -l urls.txt -match-string "admin"

# Filter response content
httpx -l urls.txt -filter-string "404 not found"
```

#### Headers and Metadata
```bash
# Extract response headers
httpx -l urls.txt -include-response-header

# Extract specific header
httpx -l urls.txt -include-response-header -match-header "server"

# Extract all headers in JSON
httpx -l urls.txt -json -include-response-header

# Show content type
httpx -l urls.txt -content-type

# Show content length
httpx -l urls.txt -content-length

# Show response time
httpx -l urls.txt -response-time
```

#### Title and Content Extraction
```bash
# Extract page titles
httpx -l urls.txt -title

# Extract with regex
httpx -l urls.txt -extract-regex '(?i)api[_-]?key["\s:=]+([a-zA-Z0-9_\-]+)'

# Extract favicons
httpx -l urls.txt -favicon

# Extract favicon hashes (for Shodan/Censys)
httpx -l urls.txt -favicon -json | jq -r '.favicon'
```

### Server and Version Detection

```bash
# Detect web server
httpx -l urls.txt -web-server

# Detect specific server versions
httpx -l urls.txt -web-server -tech-detect

# Method detection (allowed HTTP methods)
httpx -l urls.txt -method

# TLS/SSL information
httpx -l urls.txt -tls-probe

# TLS version and cipher detection
httpx -l urls.txt -tls-probe -json
```

### Probing Options

#### Protocol Detection
```bash
# Try both HTTP and HTTPS
httpx -l urls.txt -probe

# Force HTTPS only
httpx -l urls.txt -https-only

# Force HTTP only
httpx -l urls.txt -http-only

# Follow redirects
httpx -l urls.txt -follow-redirects

# Max redirect limit
httpx -l urls.txt -follow-redirects -max-redirects 5
```

#### Port Scanning
```bash
# Probe specific ports
httpx -l domains.txt -ports 80,443,8080,8443

# Probe common ports
httpx -l domains.txt -ports 80,443,8000,8080,8443,9000,9090

# Large port range (with subfinder)
subfinder -d target.com -silent | httpx -ports 80,443,8080,8443,3000,5000 -silent
```

### Screenshots and Visual Recon

```bash
# Take screenshots of all live hosts
httpx -l urls.txt -screenshot

# Screenshots with custom path
httpx -l urls.txt -screenshot -screenshot-path ./screenshots

# Screenshots in headless mode
httpx -l urls.txt -screenshot -system-chrome
```

### Filtering and Matching

#### Content-Based Filtering
```bash
# Match specific content
httpx -l urls.txt -match-string "dashboard"

# Match multiple strings (OR)
httpx -l urls.txt -match-string "admin,login,dashboard"

# Match regex
httpx -l urls.txt -match-regex '(?i)password|secret|api[_-]key'

# Filter out content
httpx -l urls.txt -filter-string "404,not found,error"

# Filter by regex
httpx -l urls.txt -filter-regex '(?i)cdn|cloudflare'
```

#### Size-Based Filtering
```bash
# Match specific content length
httpx -l urls.txt -match-length 1234

# Filter by content length
httpx -l urls.txt -filter-length 0,404

# Match content length range
httpx -l urls.txt -match-length 1000-5000
```

#### Status Code Filtering
```bash
# Match specific status codes
httpx -l urls.txt -mc 200,301,302

# Filter out status codes
httpx -l urls.txt -fc 404,403,500

# Only successful responses
httpx -l urls.txt -mc 200
```

### Rate Limiting and Performance

```bash
# Set thread count (default: 50)
httpx -l urls.txt -threads 100

# Rate limit (requests per second)
httpx -l urls.txt -rate-limit 10

# Add delay between requests
httpx -l urls.txt -delay 1s

# Set timeout (default: 10s)
httpx -l urls.txt -timeout 5

# Retry failed requests
httpx -l urls.txt -retries 2
```

### Output Formats

```bash
# JSON output
httpx -l urls.txt -json -o results.json

# JSON with all fields
httpx -l urls.txt -json -tech-detect -status-code -title -web-server -content-length -response-time

# CSV output
httpx -l urls.txt -csv -o results.csv

# Specific fields only
httpx -l urls.txt -silent -status-code -title -tech-detect

# Store response bodies
httpx -l urls.txt -store-response -store-response-dir ./responses
```

### Advanced Techniques

#### Pipeline Integration
```bash
# Full recon pipeline
subfinder -d target.com -silent | \
  httpx -silent -tech-detect -status-code -title -web-server | \
  tee live-hosts.txt

# With nuclei vulnerability scanning
subfinder -d target.com -silent | \
  httpx -silent | \
  nuclei -t cves/ -severity critical,high

# With custom filtering
subfinder -d target.com -silent | \
  httpx -silent -tech-detect -mc 200 -match-string "admin,dashboard" | \
  tee interesting-hosts.txt
```

#### CDN Detection and Bypass
```bash
# Detect CDN usage
httpx -l urls.txt -tech-detect -cdn

# Extract real IP behind CDN
httpx -l urls.txt -probe -json | jq -r 'select(.cdn==false) | .url'

# Test for CDN bypass
httpx -l urls.txt -random-agent -follow-redirects
```

#### Path Discovery
```bash
# Probe common paths
httpx -l domains.txt -path /admin,/login,/dashboard,/api

# With status code filtering
httpx -l domains.txt -path /admin,/login -mc 200,301,302

# Save interesting paths
httpx -l domains.txt -path /admin,/login,/.git,/backup -mc 200,403 -o interesting-paths.txt
```

#### Request Customization
```bash
# Custom headers
httpx -l urls.txt -header "Authorization: Bearer TOKEN"

# Custom User-Agent
httpx -l urls.txt -random-agent

# Custom method
httpx -l urls.txt -method POST

# Custom body
httpx -l urls.txt -method POST -body '{"key":"value"}'

# Follow redirects with custom headers
httpx -l urls.txt -follow-redirects -header "X-Custom: Value"
```

### Vulnerability Testing

#### Common Security Checks
```bash
# Check for common vulnerabilities
httpx -l urls.txt -path /.git/config,/.env,/backup.sql -mc 200

# Check for exposed files
httpx -l urls.txt -path /.git/HEAD,/.env,.env.backup,/config.php.bak -mc 200

# Test for directory listing
httpx -l urls.txt -match-string "Index of"

# Check for default credentials pages
httpx -l urls.txt -path /admin,/login,/phpmyadmin -title
```

#### Technology-Specific Testing
```bash
# WordPress detection and testing
httpx -l urls.txt -path /wp-admin,/wp-login.php -mc 200,302

# API endpoint discovery
httpx -l urls.txt -path /api,/api/v1,/api/v2,/graphql -mc 200

# Check for common frameworks
httpx -l urls.txt -tech-detect -match-string "Laravel,Django,Rails"
```

## Complete Reconnaissance Workflows

### Workflow 1: Basic Subdomain Recon
```bash
# Step 1: Discover subdomains
subfinder -d target.com -o subdomains.txt

# Step 2: Probe for live hosts
cat subdomains.txt | httpx -silent -o live-hosts.txt

# Step 3: Get tech stack
cat live-hosts.txt | httpx -tech-detect -title -status-code -web-server
```

### Workflow 2: Comprehensive Tech Detection
```bash
# Single command pipeline
subfinder -d target.com -silent | \
  httpx -silent -tech-detect -status-code -title -web-server -content-length -json -o recon-results.json

# Analyze results
cat recon-results.json | jq -r '.technologies[]' | sort -u
```

### Workflow 3: Multi-Domain Recon
```bash
# From domains file
cat domains.txt | while read domain; do
  echo "[*] Scanning $domain"
  subfinder -d $domain -silent | \
    httpx -silent -tech-detect -status-code -title -o "$domain-results.txt"
done
```

### Workflow 4: Detailed Asset Discovery
```bash
#!/bin/bash
DOMAIN=$1

# Step 1: Subdomain enumeration
echo "[+] Finding subdomains for $DOMAIN"
subfinder -d $DOMAIN -silent -o subs.txt

# Step 2: Live host detection
echo "[+] Probing for live hosts"
cat subs.txt | httpx -silent -threads 50 -o live.txt

# Step 3: Technology detection
echo "[+] Detecting technologies"
cat live.txt | httpx -tech-detect -title -status-code -web-server -json -o tech.json

# Step 4: Screenshots
echo "[+] Taking screenshots"
cat live.txt | httpx -screenshot -screenshot-path ./screenshots

# Step 5: Check for interesting paths
echo "[+] Checking common paths"
cat live.txt | httpx -path /admin,/login,/.git,/backup,/api -mc 200,403 -o interesting.txt

echo "[+] Recon complete! Results:"
echo "  - Subdomains: $(wc -l < subs.txt)"
echo "  - Live hosts: $(wc -l < live.txt)"
echo "  - Interesting paths: $(wc -l < interesting.txt)"
```

### Workflow 5: API-Focused Recon
```bash
# Find API endpoints
subfinder -d target.com -silent | \
  httpx -silent -path /api,/api/v1,/api/v2,/graphql,/rest -mc 200,401,403 | \
  httpx -tech-detect -title -status-code -json -o api-endpoints.json

# Extract API technologies
cat api-endpoints.json | jq -r 'select(.technologies[] | contains("api")) | .url'
```

### Workflow 6: Large-Scale Enumeration
```bash
# For massive scope
subfinder -dL domains.txt -all -recursive -o all-subdomains.txt

# Probe with high concurrency
cat all-subdomains.txt | httpx -threads 200 -rate-limit 100 -timeout 5 -silent -o live-massive.txt

# Get quick tech overview
cat live-massive.txt | httpx -tech-detect -title -status-code -silent | tee tech-overview.txt
```

## Best Practices

### 1. Always Use Pipelines
Combine subfinder and httpx for efficient workflows:
```bash
subfinder -d target.com -silent | httpx -silent -tech-detect -o results.txt
```

### 2. Save All Output
Always save results for documentation and analysis:
```bash
subfinder -d target.com -o subs.txt
cat subs.txt | httpx -tech-detect -json -o tech.json
```

### 3. Use JSON for Parsing
JSON output makes it easy to parse and analyze:
```bash
httpx -l urls.txt -tech-detect -json | jq -r '.technologies[]' | sort -u
```

### 4. Rate Limit for Production
Don't overwhelm targets:
```bash
httpx -l urls.txt -rate-limit 10 -threads 20
```

### 5. Organize Results by Domain
```bash
for domain in $(cat domains.txt); do
  subfinder -d $domain -silent | httpx -silent -o "${domain}-live.txt"
done
```

### 6. Use Resolvers for Accuracy
Custom DNS resolvers improve accuracy:
```bash
subfinder -d target.com -r 8.8.8.8,1.1.1.1 -o subs.txt
```

### 7. Extract Specific Technologies
```bash
# Find all WordPress sites
httpx -l urls.txt -tech-detect -json | jq -r 'select(.technologies[] | contains("WordPress")) | .url'

# Find all PHP sites
httpx -l urls.txt -tech-detect -json | jq -r 'select(.technologies[] | contains("PHP")) | .url'

# Find specific versions
httpx -l urls.txt -tech-detect -json | jq -r 'select(.technologies[] | contains("nginx:1.18")) | .url'
```

### 8. Monitor for Changes
```bash
# Save baseline
subfinder -d target.com -silent | httpx -silent -o baseline.txt

# Compare later
subfinder -d target.com -silent | httpx -silent -o current.txt
diff baseline.txt current.txt
```

## Common Patterns and One-Liners

### Quick Subdomain to Live Hosts
```bash
subfinder -d target.com -silent | httpx -silent -mc 200 -title -tech-detect
```

### Technology Stack Enumeration
```bash
subfinder -d target.com -silent | httpx -tech-detect -json | jq -r '.technologies[]' | sort -u
```

### Find Admin Panels
```bash
subfinder -d target.com -silent | httpx -path /admin,/login,/dashboard -mc 200,301,302 -title
```

### Extract All Subdomains with Tech
```bash
subfinder -d target.com -silent | httpx -tech-detect -status-code -title -web-server -o full-recon.txt
```

### Screenshot All Live Hosts
```bash
subfinder -d target.com -silent | httpx -silent -screenshot -screenshot-path ./screenshots
```

### Find Specific CMS
```bash
subfinder -d target.com -silent | httpx -tech-detect -json | jq -r 'select(.technologies[] | contains("WordPress")) | .url'
```

### API Discovery
```bash
subfinder -d target.com -silent | httpx -path /api,/api/v1,/graphql -mc 200 -title
```

### Multiple Domains Quick Scan
```bash
cat domains.txt | xargs -I {} subfinder -d {} -silent | httpx -silent -tech-detect -o all-results.txt
```

### Find Interesting Technologies
```bash
subfinder -d target.com -silent | httpx -tech-detect -json | \
  jq -r 'select(.technologies[] | test("admin|panel|dashboard|api|jenkins|gitlab")) | .url'
```

### CDN vs Origin Detection
```bash
httpx -l urls.txt -tech-detect -json | jq -r 'select(.cdn==true) | .url + " [CDN: " + .cdn_name + "]"'
```

## Configuration Files

### Subfinder Config
Create `~/.config/subfinder/config.yaml`:
```yaml
# API keys
resolvers:
  - 8.8.8.8
  - 1.1.1.1
sources:
  - crtsh
  - virustotal
  - shodan
timeout: 30
```

### Httpx Config
Create `~/.config/httpx/config.yaml`:
```yaml
threads: 50
timeout: 10
follow-redirects: true
status-code: true
tech-detect: true
title: true
```

## Troubleshooting

### Subfinder Issues

**No Results Found:**
- Verify domain is correct
- Check internet connection
- Try with specific sources: `-sources crtsh`
- Use `-v` to see what's happening

**Too Many False Positives:**
- Use `-nW` to remove wildcards
- Use `-active` to verify DNS records
- Filter with `-f` or `-m`

**Slow Performance:**
- Reduce timeout: `-timeout 10`
- Limit sources: `-sources crtsh,virustotal`
- Check API rate limits

### Httpx Issues

**Missing Live Hosts:**
- Try both HTTP and HTTPS: `-probe`
- Increase timeout: `-timeout 30`
- Check for custom ports: `-ports 80,443,8080`

**Rate Limiting/Blocking:**
- Reduce threads: `-threads 10`
- Add rate limit: `-rate-limit 5`
- Use random User-Agent: `-random-agent`

**Tech Detection Missing:**
- Ensure `-tech-detect` flag is used
- Check response with `-include-response-header`
- Some sites may block fingerprinting

## Output Analysis with jq

### Common jq Patterns
```bash
# Extract all URLs
cat results.json | jq -r '.url'

# Extract URLs with specific status
cat results.json | jq -r 'select(.status_code==200) | .url'

# Extract unique technologies
cat results.json | jq -r '.technologies[]' | sort -u

# Find servers running specific tech
cat results.json | jq -r 'select(.technologies[] | contains("nginx")) | .url'

# Extract title and URL
cat results.json | jq -r '"\(.url) - \(.title)"'

# Count by technology
cat results.json | jq -r '.technologies[]' | sort | uniq -c | sort -rn

# Extract servers with errors
cat results.json | jq -r 'select(.status_code>=500) | .url'

# Find URLs with specific content
cat results.json | jq -r 'select(.body | contains("admin")) | .url'
```

## Integration with Other Tools

### With Nuclei (Vulnerability Scanning)
```bash
subfinder -d target.com -silent | httpx -silent | nuclei -t cves/
```

### With Naabu (Port Scanning)
```bash
subfinder -d target.com -silent | naabu -silent | httpx -silent
```

### With DNSx (DNS Records)
```bash
subfinder -d target.com -silent | dnsx -resp -a -aaaa -cname
```

### With Katana (Crawler)
```bash
subfinder -d target.com -silent | httpx -silent | katana -d 3
```

### With FFUF (Fuzzing)
```bash
# Find live hosts, then fuzz
subfinder -d target.com -silent | httpx -silent -o live.txt
cat live.txt | xargs -I {} ffuf -w wordlist.txt -u {}/FUZZ -ac
```

## Resources

### Official Documentation
- Subfinder GitHub: https://github.com/projectdiscovery/subfinder
- Httpx GitHub: https://github.com/projectdiscovery/httpx
- ProjectDiscovery Docs: https://docs.projectdiscovery.io

### Recommended Wordlists
For path discovery with httpx:
- SecLists Discovery/Web-Content
- Assetnote wordlists: https://wordlists.assetnote.io/

### Community Resources
- ProjectDiscovery Cloud Platform: https://cloud.projectdiscovery.io
- Discord Community: https://discord.gg/projectdiscovery
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates

## Quick Reference Card

| Task | Command Template |
|------|------------------|
| Basic Subdomain Enum | `subfinder -d target.com` |
| Save Subdomains | `subfinder -d target.com -o subs.txt` |
| Multiple Domains | `subfinder -dL domains.txt` |
| With Specific Sources | `subfinder -d target.com -sources crtsh,virustotal` |
| Recursive Enum | `subfinder -d target.com -recursive` |
| Active Verification | `subfinder -d target.com -active` |
| Probe URLs | `httpx -l urls.txt` |
| Tech Detection | `httpx -l urls.txt -tech-detect` |
| With Screenshots | `httpx -l urls.txt -screenshot` |
| Status + Title | `httpx -l urls.txt -status-code -title` |
| JSON Output | `httpx -l urls.txt -json -o results.json` |
| Path Testing | `httpx -l urls.txt -path /admin,/api` |
| Filter Status | `httpx -l urls.txt -mc 200,301,302` |
| Rate Limited | `httpx -l urls.txt -rate-limit 10` |
| Full Pipeline | `subfinder -d target.com -silent \| httpx -silent -tech-detect` |

## Advanced Scripting Examples

### Automated Recon Script
```bash
#!/bin/bash
# recon.sh - Automated reconnaissance script

DOMAIN=$1
OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR

echo "[+] Starting reconnaissance for $DOMAIN"

# Subdomain enumeration
echo "[1/5] Subdomain enumeration..."
subfinder -d $DOMAIN -all -recursive -o $OUTPUT_DIR/subdomains.txt
echo "    Found $(wc -l < $OUTPUT_DIR/subdomains.txt) subdomains"

# Live host detection
echo "[2/5] Probing for live hosts..."
cat $OUTPUT_DIR/subdomains.txt | httpx -silent -threads 100 -o $OUTPUT_DIR/live-hosts.txt
echo "    Found $(wc -l < $OUTPUT_DIR/live-hosts.txt) live hosts"

# Technology detection
echo "[3/5] Detecting technologies..."
cat $OUTPUT_DIR/live-hosts.txt | httpx -tech-detect -title -status-code -web-server -json -o $OUTPUT_DIR/tech-detection.json
echo "    Technology detection complete"

# Screenshots
echo "[4/5] Taking screenshots..."
cat $OUTPUT_DIR/live-hosts.txt | httpx -screenshot -screenshot-path $OUTPUT_DIR/screenshots -silent
echo "    Screenshots saved"

# Interesting paths
echo "[5/5] Checking for interesting paths..."
cat $OUTPUT_DIR/live-hosts.txt | httpx -path /admin,/login,/api,/.git,/backup,/config -mc 200,403,401 -o $OUTPUT_DIR/interesting-paths.txt
echo "    Found $(wc -l < $OUTPUT_DIR/interesting-paths.txt) interesting paths"

# Summary
echo ""
echo "========================================="
echo "Reconnaissance Summary for $DOMAIN"
echo "========================================="
echo "Total Subdomains: $(wc -l < $OUTPUT_DIR/subdomains.txt)"
echo "Live Hosts: $(wc -l < $OUTPUT_DIR/live-hosts.txt)"
echo "Interesting Paths: $(wc -l < $OUTPUT_DIR/interesting-paths.txt)"
echo ""
echo "Results saved in: $OUTPUT_DIR/"
echo "========================================="

# Extract technology summary
echo ""
echo "Top Technologies Detected:"
cat $OUTPUT_DIR/tech-detection.json | jq -r '.technologies[]' | sort | uniq -c | sort -rn | head -10
```

### Multi-Domain Recon with Reporting
```bash
#!/bin/bash
# multi-recon.sh - Scan multiple domains and generate report

INPUT_FILE=$1
REPORT_FILE="recon_report_$(date +%Y%m%d_%H%M%S).html"

echo "<html><head><title>Recon Report</title></head><body>" > $REPORT_FILE
echo "<h1>Reconnaissance Report</h1>" >> $REPORT_FILE
echo "<p>Generated: $(date)</p>" >> $REPORT_FILE

while read domain; do
  echo "[+] Scanning $domain..."
  
  # Subdomain enumeration
  subs=$(subfinder -d $domain -silent | wc -l)
  
  # Live hosts
  live=$(subfinder -d $domain -silent | httpx -silent | wc -l)
  
  # Tech detection
  tech=$(subfinder -d $domain -silent | httpx -silent -tech-detect -json | jq -r '.technologies[]' | sort -u | tr '\n' ', ')
  
  # Add to report
  echo "<h2>$domain</h2>" >> $REPORT_FILE
  echo "<ul>" >> $REPORT_FILE
  echo "<li>Subdomains: $subs</li>" >> $REPORT_FILE
  echo "<li>Live Hosts: $live</li>" >> $REPORT_FILE
  echo "<li>Technologies: $tech</li>" >> $REPORT_FILE
  echo "</ul>" >> $REPORT_FILE
  
done < $INPUT_FILE

echo "</body></html>" >> $REPORT_FILE
echo "[+] Report saved to $REPORT_FILE"
```

### Continuous Monitoring Script
```bash
#!/bin/bash
# monitor-recon.sh - Monitor for new subdomains and changes

DOMAIN=$1
BASELINE="baseline_${DOMAIN}.txt"
CURRENT="current_${DOMAIN}.txt"
DIFF_FILE="changes_${DOMAIN}_$(date +%Y%m%d_%H%M%S).txt"

# Create baseline if doesn't exist
if [ ! -f $BASELINE ]; then
  echo "[+] Creating baseline for $DOMAIN"
  subfinder -d $DOMAIN -silent | httpx -silent | sort > $BASELINE
  echo "[+] Baseline created with $(wc -l < $BASELINE) hosts"
  exit 0
fi

# Current scan
echo "[+] Scanning $DOMAIN for changes..."
subfinder -d $DOMAIN -silent | httpx -silent | sort > $CURRENT

# Compare
NEW=$(comm -13 $BASELINE $CURRENT)
REMOVED=$(comm -23 $BASELINE $CURRENT)

if [ ! -z "$NEW" ]; then
  echo "[!] New hosts discovered:" | tee -a $DIFF_FILE
  echo "$NEW" | tee -a $DIFF_FILE
  
  # Tech detect new hosts
  echo "$NEW" | httpx -tech-detect -title -status-code >> $DIFF_FILE
fi

if [ ! -z "$REMOVED" ]; then
  echo "[!] Hosts removed:" | tee -a $DIFF_FILE
  echo "$REMOVED" | tee -a $DIFF_FILE
fi

if [ -z "$NEW" ] && [ -z "$REMOVED" ]; then
  echo "[+] No changes detected"
else
  echo "[+] Changes saved to $DIFF_FILE"
fi

# Update baseline
cp $CURRENT $BASELINE
```

## Helper Scripts and Utilities

### Extract Technologies by Type
```bash
#!/bin/bash
# extract-tech.sh - Extract and categorize technologies from httpx JSON output

JSON_FILE=$1

echo "=== Web Servers ==="
cat $JSON_FILE | jq -r '.technologies[]' | grep -i "nginx\|apache\|iis\|tomcat" | sort -u

echo ""
echo "=== Programming Languages ==="
cat $JSON_FILE | jq -r '.technologies[]' | grep -i "php\|python\|ruby\|node\|java\|asp" | sort -u

echo ""
echo "=== CMS ==="
cat $JSON_FILE | jq -r '.technologies[]' | grep -i "wordpress\|joomla\|drupal\|magento" | sort -u

echo ""
echo "=== Frameworks ==="
cat $JSON_FILE | jq -r '.technologies[]' | grep -i "laravel\|django\|rails\|react\|angular\|vue" | sort -u

echo ""
echo "=== CDN ==="
cat $JSON_FILE | jq -r '.technologies[]' | grep -i "cloudflare\|akamai\|fastly\|cloudfront" | sort -u

echo ""
echo "=== Security ==="
cat $JSON_FILE | jq -r '.technologies[]' | grep -i "waf\|firewall\|recaptcha" | sort -u
```

### Find Vulnerable Versions
```bash
#!/bin/bash
# find-vulnerable.sh - Find potentially vulnerable technology versions

JSON_FILE=$1

echo "[+] Searching for potentially vulnerable versions..."

echo ""
echo "=== Outdated PHP ==="
cat $JSON_FILE | jq -r 'select(.technologies[] | test("PHP:[0-5]|PHP:7.[0-3]")) | .url + " - " + (.technologies[] | select(test("PHP")))'

echo ""
echo "=== Outdated WordPress ==="
cat $JSON_FILE | jq -r 'select(.technologies[] | test("WordPress:[0-4]|WordPress:5.[0-8]")) | .url + " - " + (.technologies[] | select(test("WordPress")))'

echo ""
echo "=== Outdated jQuery ==="
cat $JSON_FILE | jq -r 'select(.technologies[] | test("jQuery:[0-2]")) | .url + " - " + (.technologies[] | select(test("jQuery")))'

echo ""
echo "=== Old Nginx ==="
cat $JSON_FILE | jq -r 'select(.technologies[] | test("nginx:1.[0-9]\.")) | .url + " - " + (.technologies[] | select(test("nginx")))'
```

### Generate Target List for Fuzzing
```bash
#!/bin/bash
# generate-fuzz-targets.sh - Create organized target lists for ffuf

LIVE_HOSTS=$1
OUTPUT_DIR="fuzz-targets"

mkdir -p $OUTPUT_DIR

echo "[+] Generating fuzzing target lists..."

# WordPress sites
cat $LIVE_HOSTS | httpx -tech-detect -json -silent | \
  jq -r 'select(.technologies[] | contains("WordPress")) | .url' > $OUTPUT_DIR/wordpress-targets.txt
echo "    WordPress targets: $(wc -l < $OUTPUT_DIR/wordpress-targets.txt)"

# Admin panels detected
cat $LIVE_HOSTS | httpx -path /admin -mc 200,401,403 -silent > $OUTPUT_DIR/admin-panels.txt
echo "    Admin panels: $(wc -l < $OUTPUT_DIR/admin-panels.txt)"

# API endpoints
cat $LIVE_HOSTS | httpx -path /api,/api/v1,/graphql -mc 200,401 -silent > $OUTPUT_DIR/api-endpoints.txt
echo "    API endpoints: $(wc -l < $OUTPUT_DIR/api-endpoints.txt)"

# PHP applications
cat $LIVE_HOSTS | httpx -tech-detect -json -silent | \
  jq -r 'select(.technologies[] | contains("PHP")) | .url' > $OUTPUT_DIR/php-apps.txt
echo "    PHP applications: $(wc -l < $OUTPUT_DIR/php-apps.txt)"

# Sites with exposed .git
cat $LIVE_HOSTS | httpx -path /.git/config -mc 200 -silent > $OUTPUT_DIR/git-exposed.txt
echo "    Exposed .git: $(wc -l < $OUTPUT_DIR/git-exposed.txt)"

echo "[+] Target lists saved in $OUTPUT_DIR/"
```

## Resources and Helper Scripts

This skill includes supplementary materials in the `resources/` directory to enhance reconnaissance workflows:

### Resource Files

#### 1. **CONFIG_TEMPLATES.md** - Configuration & API Setup
Comprehensive configuration templates for subfinder and httpx with API key setup.

**Contents:**
- **Subfinder Configurations:**
  - Minimal free config (no API keys needed)
  - Basic config with common free APIs (Shodan, VirusTotal, GitHub, Chaos)
  - Premium/paid services configuration
  - Complete configuration with all 30+ sources
- **Httpx Configurations:**
  - Basic general reconnaissance config
  - Stealth config (slow & careful, WAF-aware)
  - Aggressive config (fast & comprehensive)
  - API testing optimized config
- **Additional Resources:**
  - Trusted DNS resolvers list
  - Custom headers templates
  - WAF bypass headers
  - Quick setup script
- **Guides:**
  - API Key Priority Guide (which free keys to get first)
  - Free vs Paid comparison table
  - Testing your configuration
  - Common issues & troubleshooting
  - Environment variables alternative

**When to Reference:**
- User needs to set up subfinder with API keys
- User asks about configuration optimization
- User wants to improve subdomain enumeration results
- User needs stealth or aggressive httpx settings
- Setting up reconnaissance tools for the first time

**Key Recommendations from CONFIG_TEMPLATES.md:**
- Start with free sources (GitHub, Chaos, VirusTotal) - subfinder works great without API keys
- GitHub token provides best ROI for free tier (5000 requests/hour)
- Use stealth config when avoiding WAF/IDS detection
- Use aggressive config on authorized targets for speed
- Keep API keys in environment variables for security

---

#### 2. **WORKFLOWS.md** - Pre-Built Reconnaissance Workflows
Ready-to-use workflow templates for common reconnaissance scenarios.

**Contents:**
- **Basic Workflows:**
  - Subdomain enumeration to live hosts (quick start)
  - Comprehensive reconnaissance with full analysis
- **Batch & Monitoring:**
  - Multi-domain batch processing (sequential & parallel)
  - Continuous monitoring & change detection
  - Automated monitoring with cron
- **Specialized Workflows:**
  - API-focused reconnaissance
  - Integration with other tools (nuclei, ffuf, naabu)
  - Technology-specific recon (WordPress, APIs, Admin panels)
- **Advanced Workflows:**
  - Large-scale enumeration (thousands of domains)
  - Stealth reconnaissance (low-noise, WAF-aware)
  - Report generation & documentation
- **Bonus Content:**
  - Quick reference one-liners
  - Best practices for Claude Code
  - Troubleshooting common issues
  - Integration examples (Slack, GitHub Actions, Database)

**When to Reference:**
- User asks "how do I scan multiple domains?"
- User needs a complete recon workflow
- User wants to monitor for new subdomains
- User needs API-focused or technology-specific scanning
- User asks about integrating with nuclei/ffuf/naabu
- User needs stealth or large-scale scanning approaches

**Example Workflows to Suggest:**
```bash
# Workflow 1: Basic subdomain to live hosts
subfinder -d target.com -silent | httpx -silent -tech-detect -o results.txt

# Workflow 4: Continuous monitoring
python3 recon_helper.py compare-subs baseline.txt current.txt -o changes.txt

# Workflow 5: API-focused reconnaissance
subfinder -d target.com -silent | \
  httpx -path /api,/api/v1,/graphql -mc 200,401,403 -tech-detect

# Workflow 6: Integration with nuclei
subfinder -d target.com -silent | httpx -silent | \
  nuclei -t cves/ -severity critical,high
```

---

#### 3. **WORDLISTS.md** - Comprehensive Wordlist Guide
Complete guide to wordlists for reconnaissance and path discovery.

**Contents:**
- **Subdomain Wordlists:**
  - SecLists collection (Top 1K, 5K, 20K, 100K+)
  - Alternative sources (Assetnote, n0kovo, jhaddix)
  - Common subdomain patterns
  - Recommendations by scope size
- **Path/Directory Wordlists for Httpx:**
  - Common paths (quick scans)
  - RAFT lists (small, medium, large)
  - Directory-list variations
  - Size and usage recommendations
- **Technology-Specific Lists:**
  - WordPress paths (complete)
  - Joomla, Drupal paths
  - API endpoint discovery paths
  - GraphQL specific paths
  - Admin panel paths
  - Sensitive files & backups
- **Custom Wordlist Creation:**
  - Number-based lists (IDOR testing)
  - Date-based lists
  - Organization-specific patterns
  - Combining multiple wordlists
- **Optimization & Integration:**
  - Wordlist quality filtering
  - Size optimization techniques
  - Integration with recon workflow
  - Download script for essential collections
  - Quick reference table

**When to Reference:**
- User asks "what wordlist should I use?"
- User needs to probe specific paths with httpx
- User wants to find admin panels, APIs, or sensitive files
- User asks about SecLists or wordlist recommendations
- User needs technology-specific wordlists
- User wants to create custom wordlists

**Key Points from WORDLISTS.md:**
- **httpx limitation:** `-path` flag accepts comma-separated paths, not wordlist files
- For wordlist-based fuzzing, use ffuf after httpx identifies live hosts
- Recommended starting point: `common.txt` (4,600 entries) for quick scans
- WordPress sites: Use WordPress-specific paths from WORDLISTS.md
- API discovery: Reference API paths section for comprehensive endpoint list
- Download script provided for SecLists and other essential wordlists

**Common Path Probing Examples:**
```bash
# Admin panels
httpx -l urls.txt -path /admin,/administrator,/login,/wp-admin -mc 200,401,403

# API endpoints
httpx -l urls.txt -path /api,/api/v1,/graphql,/swagger.json -mc 200,401

# WordPress paths
httpx -l wp-sites.txt -path /wp-admin,/wp-json,/xmlrpc.php -mc 200,403

# Sensitive files
httpx -l urls.txt -path /.git/config,.env,/backup.sql -mc 200,403
```

---

### Helper Script: recon_helper.py
A Python utility script that assists with analyzing httpx results, generating reports, and managing subdomain lists.

**Location:** Should be placed in the same directory as your reconnaissance results or in a dedicated tools directory.

**Key Capabilities:**

1. **Analyze Results** - Deep analysis of httpx JSON output
   - Technology stack categorization
   - Status code distribution analysis
   - Anomaly detection (unusual sizes, interesting titles)
   - Vulnerable version identification
   - HTML report generation

2. **Extract by Technology** - Filter hosts by specific technology
   - Extract all WordPress, Joomla, PHP sites, etc.
   - Save filtered lists for targeted testing

3. **Generate Target Lists** - Organize results for follow-up testing
   - By technology (WordPress, APIs, PHP, Node.js, etc.)
   - By status code (200, 401, 403, 500+)
   - By keywords (admin, login, api, dev, backup)

4. **Compare Subdomains** - Monitor for changes over time
   - Compare baseline vs current scans
   - Identify new/removed subdomains
   - Track infrastructure changes

5. **Merge Subdomain Lists** - Consolidate multiple scans
   - Combine results from different sources
   - Remove duplicates
   - Generate master subdomain list

**When Claude Should Use This Helper:**

- **After httpx scans with JSON output** - Always analyze JSON results to identify interesting findings
- **When user asks for technology-specific targets** - Extract hosts by technology
- **When organizing for further testing** - Generate categorized target lists
- **When monitoring changes** - Compare old vs new subdomain lists
- **When consolidating results** - Merge multiple reconnaissance outputs

**Enhanced Features:**
- `--summary` flag for quick triage (shows key metrics only)
- `--json` flag for programmatic parsing by Claude
- `--quiet` mode for cleaner piping to other tools
- `--no-color` for non-TTY environments
- Color-coded output for better readability
- Detailed error messages with actionable suggestions

**Example Usage Patterns:**

```bash
# Quick summary for fast triage
python3 recon_helper.py analyze results.json --summary

# Full analysis with HTML report
python3 recon_helper.py analyze results.json --report recon-report.html

# JSON output for Claude to parse
python3 recon_helper.py analyze results.json --json

# Extract WordPress sites for WPScan
python3 recon_helper.py extract results.json --tech wordpress -o wordpress-targets.txt

# Generate organized target lists for ffuf
python3 recon_helper.py generate-targets results.json --output-dir fuzz-targets/

# Compare with previous scan (monitoring)
python3 recon_helper.py compare-subs old-subs.txt new-subs.txt -o changes.txt

# Merge results from multiple domains
python3 recon_helper.py merge-subs domain1-subs.txt domain2-subs.txt -o all-subs.txt

# Quiet mode for piping
python3 recon_helper.py extract results.json --tech api -q -o api-targets.txt
```

---

## How Claude Should Use These Resources

### Decision Tree for Resource Usage

**1. User asks about configuration/setup:**
→ Reference **CONFIG_TEMPLATES.md**
- "How do I set up subfinder with API keys?"
- "What configuration should I use for httpx?"
- "How can I make my scans stealthier?"
- "Which free API keys should I get?"

**2. User asks about workflows/how to do something:**
→ Reference **WORKFLOWS.md**
- "How do I scan multiple domains?"
- "How do I monitor for new subdomains?"
- "How do I find API endpoints?"
- "How do I integrate with nuclei/ffuf?"
- "Show me a complete recon workflow"

**3. User asks about wordlists/paths:**
→ Reference **WORDLISTS.md**
- "What wordlist should I use?"
- "How do I find admin panels?"
- "What paths should I check for WordPress?"
- "How do I discover API endpoints?"
- "Where can I get good wordlists?"

**4. User has httpx JSON results:**
→ Use **recon_helper.py**
- Always analyze results: `python3 recon_helper.py analyze results.json`
- Generate reports: add `--report report.html`
- Extract specific tech: `python3 recon_helper.py extract results.json --tech wordpress`
- Generate target lists: `python3 recon_helper.py generate-targets results.json`

### Complete Recon Workflow Example (Using All Resources)

```bash
#!/bin/bash
DOMAIN=$1

# Step 1: Use CONFIG_TEMPLATES.md recommendations
# Ensure subfinder is configured with API keys (GitHub, Chaos, VirusTotal)

# Step 2: Use WORKFLOWS.md - Workflow 2 (Comprehensive Recon)
echo "[+] Running comprehensive reconnaissance..."
subfinder -d $DOMAIN -all -recursive -o subdomains.txt

# Step 3: Probe with httpx
cat subdomains.txt | httpx -silent -tech-detect -json -o results.json

# Step 4: Use recon_helper.py to analyze
echo "[+] Analyzing results..."
python3 recon_helper.py analyze results.json --summary
python3 recon_helper.py analyze results.json --report report.html

# Step 5: Generate target lists
python3 recon_helper.py generate-targets results.json -o targets/

# Step 6: Use WORDLISTS.md for path discovery
echo "[+] Probing for admin panels..."
cat results.json | jq -r '.url' | \
  httpx -path /admin,/login,/wp-admin,/phpmyadmin -mc 200,401,403 -title

# Step 7: Technology-specific testing (from WORKFLOWS.md)
python3 recon_helper.py extract results.json --tech wordpress -o wp-sites.txt
cat wp-sites.txt | httpx -path /wp-json,/xmlrpc.php -mc 200

# Step 8: Integration with ffuf (from WORKFLOWS.md)
cat targets/admin-panels.txt | while read url; do
  ffuf -w ~/wordlists/admin-paths.txt -u $url/FUZZ -ac
done

echo "[+] Reconnaissance complete! Check report.html"
```

## Notes for Claude Code Agent

When helping users with reconnaissance using subfinder and httpx:

### 1. **ALWAYS Recommend Pipelines**
The power of these tools is in combining them:
```bash
subfinder -d target.com -silent | httpx -silent -tech-detect
```

### 2. **Use Silent Mode for Pipelines**
Always use `-silent` when piping between tools to avoid mixing output:
```bash
subfinder -d target.com -silent | httpx -silent -o results.txt
```

### 3. **Save All Results**
Always recommend saving output for documentation:
```bash
subfinder -d target.com -o subdomains.txt
httpx -l urls.txt -tech-detect -json -o tech.json
```

### 4. **Technology Detection Is Key**
Always include `-tech-detect` with httpx for reconnaissance:
```bash
httpx -l urls.txt -tech-detect -title -status-code -web-server
```

### 5. **Use JSON for Analysis**
JSON output makes parsing and analysis much easier:
```bash
httpx -l urls.txt -tech-detect -json | jq -r '.technologies[]' | sort -u
```

### 6. **Suggest Rate Limiting for Production**
Always recommend rate limiting for production targets:
```bash
httpx -l urls.txt -rate-limit 10 -threads 20
```

### 7. **Organize by Domain**
For multiple domains, organize results clearly:
```bash
for domain in $(cat domains.txt); do
  subfinder -d $domain -silent | httpx -silent -o "${domain}-results.txt"
done
```

### 8. **Common Workflow Patterns**

**Basic Recon:**
```bash
subfinder -d target.com -silent | httpx -silent -tech-detect -o results.txt
```

**Comprehensive Recon:**
```bash
subfinder -d target.com -all -recursive | \
  httpx -tech-detect -screenshot -status-code -title -json -o full-recon.json
```

**API Discovery:**
```bash
subfinder -d target.com -silent | \
  httpx -path /api,/api/v1,/graphql -mc 200 -tech-detect
```

**Quick Tech Stack:**
```bash
subfinder -d target.com -silent | httpx -silent -tech-detect -json | \
  jq -r '.technologies[]' | sort -u
```

### 9. **Integration with FFUF**
After recon, suggest fuzzing interesting targets:
```bash
# 1. Find live hosts
subfinder -d target.com -silent | httpx -silent -o live.txt

# 2. Fuzz interesting ones
cat live.txt | while read url; do
  ffuf -w wordlist.txt -u $url/FUZZ -ac
done
```

### 10. **Vulnerability Correlation**
Help users identify potential vulnerabilities from tech detection:
- Old PHP versions → suggest checking for known CVEs
- WordPress → suggest WPScan or fuzzing wp-content
- Exposed .git → suggest GitDumper
- Admin panels → suggest password spraying or ffuf
- APIs → suggest parameter fuzzing

### 11. **Output Analysis Tips**
Help users analyze results effectively:
```bash
# Find unique technologies
cat results.json | jq -r '.technologies[]' | sort -u

# Find specific tech
cat results.json | jq -r 'select(.technologies[] | contains("WordPress")) | .url'

# Count by status code
cat results.json | jq -r '.status_code' | sort | uniq -c

# Find errors
cat results.json | jq -r 'select(.status_code >= 500) | .url'
```

### 12. **Stealth Considerations**
For sensitive targets, recommend:
- Lower thread count: `-threads 10`
- Rate limiting: `-rate-limit 5`
- Random User-Agent: `-random-agent`
- Delays between requests: `-delay 1s`

### 13. **Common User Questions**

**"How do I find subdomains?"**
```bash
subfinder -d target.com -o subdomains.txt
```

**"How do I check which are live?"**
```bash
cat subdomains.txt | httpx -silent -o live.txt
```

**"How do I detect technologies?"**
```bash
cat live.txt | httpx -tech-detect -title -status-code
```

**"How do I find WordPress sites?"**
```bash
httpx -l urls.txt -tech-detect -json | \
  jq -r 'select(.technologies[] | contains("WordPress")) | .url'
```

**"How do I take screenshots?"**
```bash
httpx -l urls.txt -screenshot -screenshot-path ./screenshots
```

**"How do I find admin panels?"**
```bash
httpx -l urls.txt -path /admin,/login,/dashboard -mc 200,301,302
```

### 14. **Performance Optimization**
- For large scans: increase threads (`-threads 100`)
- For slow networks: increase timeout (`-timeout 30`)
- For rate-limited targets: use `-rate-limit` and `-delay`
- For faster results: use `-http-only` or `-https-only` if you know the protocol

### 15. **Error Handling**
Common issues and solutions:
- No results → Check domain spelling, try `-all` with subfinder
- Connection timeouts → Increase timeout with `-timeout`
- Rate limiting → Reduce threads and add delays
- Missing tech → Ensure `-tech-detect` flag is present

### 16. **Documentation for Reports**
Recommend these outputs for pentest reports:
```bash
# JSON for detailed analysis
httpx -l urls.txt -tech-detect -json -o report.json

# HTML for visual presentation
httpx -l urls.txt -tech-detect -screenshot -screenshot-path ./screens

# CSV for client spreadsheets
subfinder -d target.com -oT -o subdomains.csv
```

### 17. **Security Checks**
Always suggest checking for:
- Exposed files: `/.git/config`, `/.env`, `/backup.sql`
- Admin interfaces: `/admin`, `/login`, `/phpmyadmin`
- API endpoints: `/api`, `/api/v1`, `/graphql`
- Default pages: `/server-status`, `/phpinfo.php`

### 18. **Next Steps After Recon**
Guide users on what to do with results:
1. Analyze tech stack for known vulnerabilities
2. Screenshot interesting hosts
3. Feed results to ffuf for content discovery
4. Use nuclei for vulnerability scanning
5. Investigate exposed sensitive files
6. Map attack surface for further testing

### 19. **Always Use the Helper Script for Analysis**
After generating JSON results with httpx, **ALWAYS** use `recon_helper.py` to analyze them:
```bash
# Run recon and analyze
subfinder -d target.com -silent | httpx -silent -tech-detect -json -o results.json
python3 recon_helper.py analyze results.json --report report.html
```

The helper provides:
- Categorized technology breakdown
- Anomaly detection
- Vulnerable version identification  
- HTML reports for documentation

**Critical:** Don't just save JSON and move on - always analyze it to find interesting targets and potential vulnerabilities.

### 20. **Generate Target Lists for Follow-Up Testing**
After analysis, generate organized target lists:
```bash
python3 recon_helper.py generate-targets results.json --output-dir targets/
```

This creates organized lists (wordpress-targets.txt, admin-panels.txt, api-endpoints.txt, etc.) that can be directly fed into ffuf, WPScan, or other tools.

### 21. **Use Subdomain Comparison for Continuous Monitoring**
When running periodic scans, compare results:
```bash
python3 recon_helper.py compare-subs baseline.txt current.txt -o changes.txt
```

Alert users to new subdomains (potential new attack surface) or removed ones (infrastructure changes).

## Example User Interactions

### Scenario 1: Basic Subdomain Recon
**User:** "I need to find all subdomains for example.com"

**Claude Response:**
```bash
# Find all subdomains
subfinder -d example.com -o subdomains.txt

# Check which ones are live
cat subdomains.txt | httpx -silent -o live-hosts.txt

# Get a quick overview with tech detection
cat live-hosts.txt | httpx -tech-detect -title -status-code
```

### Scenario 2: Finding WordPress Sites
**User:** "How do I find all WordPress sites in my scope?"

**Claude Response:**
```bash
# First, get all live hosts
subfinder -d target.com -silent | httpx -silent -o live.txt

# Then detect WordPress
cat live.txt | httpx -tech-detect -json | \
  jq -r 'select(.technologies[] | contains("WordPress")) | .url' > wordpress-sites.txt

# Or in one pipeline
subfinder -d target.com -silent | \
  httpx -silent -tech-detect -json | \
  jq -r 'select(.technologies[] | contains("WordPress")) | .url'
```

### Scenario 3: Large-Scale Multi-Domain Recon
**User:** "I have 50 domains to scan, how do I do this efficiently?"

**Claude Response:**
```bash
# Create a script for batch processing
cat > recon-all.sh << 'EOF'
#!/bin/bash
while read domain; do
  echo "[+] Scanning $domain..."
  subfinder -d $domain -silent | \
    httpx -silent -tech-detect -json -o "${domain}-results.json"
  echo "    Completed $domain"
done < domains.txt
EOF

chmod +x recon-all.sh
./recon-all.sh

# Then aggregate results
cat *-results.json | jq -r '.technologies[]' | sort | uniq -c | sort -rn
```

### Scenario 4: API-Focused Recon
**User:** "I need to find all API endpoints"

**Claude Response:**
```bash
# Discover subdomains and probe for API paths
subfinder -d target.com -silent | \
  httpx -path /api,/api/v1,/api/v2,/graphql,/rest -mc 200,401,403 -tech-detect -json -o api-endpoints.json

# Extract API URLs
cat api-endpoints.json | jq -r '.url'

# Find API technologies
cat api-endpoints.json | jq -r '.technologies[]' | grep -i api | sort -u
```

## Final Best Practices Summary

1. **Always use pipelines** - combine subfinder and httpx
2. **Save everything** - use `-o` for all outputs
3. **Use JSON** - easier to parse and analyze
4. **Tech detect by default** - always include `-tech-detect`
5. **Rate limit production** - protect targets and avoid detection
6. **Organize results** - separate files per domain
7. **Silent mode for pipes** - cleaner output
8. **Screenshot interesting** - visual confirmation
9. **Document findings** - JSON for reports
10. **Next step integration** - feed results to ffuf, nuclei, etc.

---

**End of Reconnaissance SKILL.md**