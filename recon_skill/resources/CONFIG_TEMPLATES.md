# Configuration Templates for Subfinder & Httpx

These are configuration templates for setting up subfinder and httpx for optimal reconnaissance results.

---

## Subfinder Configuration

### Location
- Linux/macOS: `~/.config/subfinder/provider-config.yaml`
- Windows: `%USERPROFILE%\.config\subfinder\provider-config.yaml`

---

## Template 1: Minimal Free Configuration (No API Keys)

```yaml
# Free sources that don't require API keys
# subfinder works great even without API keys!

# These sources work automatically:
# - crtsh (Certificate Transparency)
# - certspotter
# - hackertarget
# - dnsdumpster
# - waybackarchive
# - rapiddns
# - alienvault

# No configuration needed - just run subfinder!
```

**Usage:**
```bash
subfinder -d target.com -o subdomains.txt
# Works out of the box with 10+ free sources
```

---

## Template 2: Basic Configuration with Common Free APIs

```yaml
# Configuration with commonly available free API keys

# Shodan (Free tier: 100 queries/month)
# Get key at: https://account.shodan.io/
shodan:
  - YOUR_SHODAN_API_KEY_HERE

# VirusTotal (Free tier: 4 requests/minute)
# Get key at: https://www.virustotal.com/gui/my-apikey
virustotal:
  - YOUR_VIRUSTOTAL_API_KEY_HERE

# GitHub (Free, requires GitHub account)
# Get token at: https://github.com/settings/tokens
# Permissions needed: public_repo, read:packages
github:
  - YOUR_GITHUB_TOKEN_HERE

# Chaos (Free for security researchers)
# Get key at: https://chaos.projectdiscovery.io
chaos:
  - YOUR_CHAOS_API_KEY_HERE

# Censys (Free tier: 250 queries/month)
# Get credentials at: https://search.censys.io/account/api
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET

# ZoomEye (Free tier: available)
# Get credentials at: https://www.zoomeye.org/profile
zoomeye:
  - YOUR_ZOOMEYE_USERNAME:YOUR_ZOOMEYE_PASSWORD
```

**Setup Instructions:**
```bash
# Create config directory
mkdir -p ~/.config/subfinder

# Create config file
nano ~/.config/subfinder/provider-config.yaml

# Test configuration
subfinder -d target.com -v
# You should see "Running source: shodan" etc. in verbose mode
```

---

## Template 3: Premium/Paid Services Configuration

```yaml
# Configuration with premium/paid API services
# These provide significantly more results

# SecurityTrails (Paid)
# Plans start at $50/month
# Get key at: https://securitytrails.com/app/account/credentials
securitytrails:
  - YOUR_SECURITYTRAILS_API_KEY

# BinaryEdge (Paid)
# Plans start at $10/month
# Get key at: https://app.binaryedge.io/account/api
binaryedge:
  - YOUR_BINARYEDGE_API_KEY

# Shodan (Paid tier for more queries)
shodan:
  - YOUR_PREMIUM_SHODAN_KEY

# Censys (Paid tier for more queries)
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET

# VirusTotal (Premium for more queries)
virustotal:
  - YOUR_PREMIUM_VIRUSTOTAL_KEY

# PassiveTotal/RiskIQ (Enterprise)
passivetotal:
  - YOUR_PASSIVETOTAL_USERNAME:YOUR_PASSIVETOTAL_KEY

# WhoisXML API (Paid)
whoisxmlapi:
  - YOUR_WHOISXML_API_KEY

# FullHunt (Paid)
fullhunt:
  - YOUR_FULLHUNT_API_KEY

# Hunter.io (Paid, for email enumeration)
hunter:
  - YOUR_HUNTER_API_KEY

# Intelx (Paid)
intelx:
  - YOUR_INTELX_API_KEY:YOUR_INTELX_API_ID

# URLScan (Free tier available, paid for more)
urlscan:
  - YOUR_URLSCAN_API_KEY
```

---

## Template 4: Complete Configuration (All Sources)

```yaml
# Complete configuration with all supported sources
# Fill in only the API keys you have

# === FREE SOURCES (No API key needed) ===
# crtsh, certspotter, hackertarget, dnsdumpster, waybackarchive, 
# rapiddns, alienvault, anubis, bufferover, chinaz, dnsdb

# === FREE API SOURCES ===

shodan:
  - SHODAN_API_KEY_1
  - SHODAN_API_KEY_2  # Multiple keys for rotation

virustotal:
  - VIRUSTOTAL_API_KEY

github:
  - GITHUB_TOKEN_1
  - GITHUB_TOKEN_2  # Multiple tokens for rate limiting

chaos:
  - CHAOS_API_KEY

censys:
  - CENSYS_API_ID:CENSYS_API_SECRET

zoomeye:
  - ZOOMEYE_USERNAME:ZOOMEYE_PASSWORD

# === PAID API SOURCES ===

securitytrails:
  - SECURITYTRAILS_API_KEY

binaryedge:
  - BINARYEDGE_API_KEY

passivetotal:
  - PASSIVETOTAL_USERNAME:PASSIVETOTAL_KEY

whoisxmlapi:
  - WHOISXML_API_KEY

fullhunt:
  - FULLHUNT_API_KEY

hunter:
  - HUNTER_API_KEY

intelx:
  - INTELX_API_KEY:INTELX_API_ID

urlscan:
  - URLSCAN_API_KEY

fofa:
  - FOFA_EMAIL:FOFA_KEY

quake:
  - QUAKE_TOKEN

bevigil:
  - BEVIGIL_API_KEY

netlas:
  - NETLAS_API_KEY

# === ADVANCED OPTIONS ===

# Custom timeout for all sources (seconds)
timeout: 30

# Custom rate limit (requests per second)
ratelimit: 10

# Proxy configuration (optional)
# proxy: http://127.0.0.1:8080

# Custom DNS resolvers (optional)
resolvers:
  - 1.1.1.1
  - 8.8.8.8
  - 8.8.4.4
```

---

## Httpx Configuration

### Location
- Linux/macOS: `~/.config/httpx/config.yaml`
- Windows: `%USERPROFILE%\.config\httpx\config.yaml`

---

## Template 5: Basic Httpx Configuration

```yaml
# Basic httpx configuration for general reconnaissance

# Threading
threads: 50

# Timeout settings
timeout: 10
retries: 2

# Follow redirects
follow-redirects: true
max-redirects: 5

# Output preferences
status-code: true
title: true
tech-detect: true
content-length: true
web-server: true

# Colors in output
no-color: false

# Rate limiting (requests per second)
# rate-limit: 10

# Matchers (include these status codes)
match-code:
  - 200
  - 201
  - 202
  - 301
  - 302
  - 401
  - 403
  - 500

# Silent mode (disable by default for visibility)
silent: false
```

**Usage:**
```bash
# Create config
mkdir -p ~/.config/httpx
nano ~/.config/httpx/config.yaml

# Config will be automatically loaded
httpx -l urls.txt
```

---

## Template 6: Stealth Httpx Configuration (Slow & Careful)

```yaml
# Configuration for careful, stealthy reconnaissance
# Use when you don't want to trigger WAF/IDS

threads: 10
timeout: 15
retries: 1

# Slow down requests
rate-limit: 5
delay: 200ms

# Use random User-Agent
random-agent: true

# Follow redirects carefully
follow-redirects: true
max-redirects: 3

# Basic detection
status-code: true
title: true
content-length: true

# Don't be too noisy
tech-detect: false
screenshot: false

# Retry failed requests
retries: 2
```

---

## Template 7: Aggressive Httpx Configuration (Fast & Comprehensive)

```yaml
# Configuration for fast, comprehensive reconnaissance
# Use on authorized targets only

threads: 150
timeout: 5
retries: 0

# Fast rate
rate-limit: 100

# Get everything
status-code: true
title: true
tech-detect: true
web-server: true
content-length: true
content-type: true
response-time: true
cdn: true
method: true

# Follow redirects quickly
follow-redirects: true
max-redirects: 10

# Store responses for analysis
store-response: true
store-response-dir: ./responses

# Screenshots (comment out if not needed)
# screenshot: true
# screenshot-path: ./screenshots
```

---

## Template 8: API Testing Httpx Configuration

```yaml
# Configuration optimized for API endpoint testing

threads: 50
timeout: 10

# API-specific settings
follow-redirects: false  # APIs usually don't redirect
http2: true  # Many APIs use HTTP/2

# What to capture
status-code: true
title: true
tech-detect: true
content-type: true
content-length: true
response-time: true

# Match successful API responses
match-code:
  - 200
  - 201
  - 202
  - 400
  - 401
  - 403
  - 404

# JSON-friendly output
json: false  # Set to true for JSON output

# Headers important for APIs
include-response-header: true
```

---

## DNS Resolvers List

### Template 9: Trusted DNS Resolvers

Create file: `~/.config/subfinder/resolvers.txt`

```text
# Google Public DNS
8.8.8.8
8.8.4.4

# Cloudflare DNS
1.1.1.1
1.0.0.1

# Quad9 DNS
9.9.9.9
149.112.112.112

# OpenDNS
208.67.222.222
208.67.220.220

# Level3
4.2.2.1
4.2.2.2

# Verisign
64.6.64.6
64.6.65.6

# DNS.Watch
84.200.69.80
84.200.70.40

# Comodo Secure DNS
8.26.56.26
8.20.247.20

# AdGuard DNS
94.140.14.14
94.140.15.15
```

**Usage with Subfinder:**
```bash
subfinder -d target.com -rL ~/.config/subfinder/resolvers.txt
```

**Usage with DNSx:**
```bash
cat subdomains.txt | dnsx -r ~/.config/subfinder/resolvers.txt -resp
```

---

## Custom Headers Templates

### Template 10: Custom Headers for Httpx

Create file: `headers.txt`

```text
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
```

**Usage:**
```bash
httpx -l urls.txt -H "$(cat headers.txt)"
```

---

## Template 11: Custom Headers for Bypassing WAF

```text
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
```

**Usage:**
```bash
while IFS= read -r header; do headers+=(-H "$header"); done < bypass-headers.txt
httpx -l urls.txt "${headers[@]}"
```

---

## Setup Scripts

### Template 12: Quick Setup Script

Create `setup-recon-config.sh`:

```bash
#!/bin/bash
# Quick setup script for subfinder and httpx configurations

echo "[+] Setting up reconnaissance tool configurations..."

# Create directories
mkdir -p ~/.config/subfinder
mkdir -p ~/.config/httpx

# Check if subfinder config exists
if [ -f ~/.config/subfinder/provider-config.yaml ]; then
    echo "[!] Subfinder config already exists. Backup created."
    cp ~/.config/subfinder/provider-config.yaml ~/.config/subfinder/provider-config.yaml.backup
fi

# Create basic subfinder config
cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
# Subfinder Provider Configuration
# Add your API keys below

# Free sources (add your keys)
# shodan:
#   - YOUR_SHODAN_KEY

# virustotal:
#   - YOUR_VIRUSTOTAL_KEY

# github:
#   - YOUR_GITHUB_TOKEN

# chaos:
#   - YOUR_CHAOS_KEY

# censys:
#   - YOUR_API_ID:YOUR_API_SECRET
EOF

echo "[+] Created subfinder config at: ~/.config/subfinder/provider-config.yaml"

# Create basic httpx config
cat > ~/.config/httpx/config.yaml << 'EOF'
# Httpx Configuration
threads: 50
timeout: 10
retries: 2
follow-redirects: true
status-code: true
title: true
tech-detect: true
content-length: true
web-server: true
EOF

echo "[+] Created httpx config at: ~/.config/httpx/config.yaml"

# Create resolvers file
cat > ~/.config/subfinder/resolvers.txt << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
EOF

echo "[+] Created resolvers file at: ~/.config/subfinder/resolvers.txt"

echo ""
echo "[+] Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit ~/.config/subfinder/provider-config.yaml to add your API keys"
echo "  2. Get free API keys from:"
echo "     - Shodan: https://account.shodan.io/"
echo "     - VirusTotal: https://www.virustotal.com/gui/my-apikey"
echo "     - GitHub: https://github.com/settings/tokens"
echo "     - Chaos: https://chaos.projectdiscovery.io"
echo "  3. Test with: subfinder -d example.com -v"
```

**Usage:**
```bash
chmod +x setup-recon-config.sh
./setup-recon-config.sh
```

---

## API Key Priority Guide

### Free API Keys (Recommended for Everyone)

1. **GitHub Token** (Highly Recommended)
   - URL: https://github.com/settings/tokens
   - Cost: Free
   - Limit: 5000 requests/hour
   - Impact: High (lots of subdomain data)
   - Setup: Generate token with `public_repo` scope

2. **Chaos** (Recommended for Security Researchers)
   - URL: https://chaos.projectdiscovery.io
   - Cost: Free
   - Limit: Good for research
   - Impact: High (ProjectDiscovery's dataset)
   - Setup: Request access for security research

3. **VirusTotal** (Recommended)
   - URL: https://www.virustotal.com/gui/my-apikey
   - Cost: Free
   - Limit: 4 requests/minute
   - Impact: Medium-High
   - Setup: Create account, get API key

4. **Shodan** (Optional but Good)
   - URL: https://account.shodan.io/
   - Cost: Free tier available
   - Limit: 100 queries/month (free)
   - Impact: Medium
   - Setup: Create account, get API key

### Paid API Keys (For Professional Use)

1. **SecurityTrails** - Best ROI for subdomain enumeration
2. **Shodan** (Paid) - Better query limits
3. **BinaryEdge** - Good for large scopes
4. **Censys** (Paid) - More queries than free tier

---

## Testing Your Configuration

### Verify Subfinder Configuration

```bash
# Test with verbose mode to see which sources are working
subfinder -d example.com -v

# You should see output like:
# [INF] Running source: crtsh
# [INF] Running source: shodan (API key detected)
# [INF] Running source: virustotal (API key detected)
```

### Verify Httpx Configuration

```bash
# Test on a single URL
echo "https://example.com" | httpx -verbose

# Should show your configured settings being used
```

### Common Issues

**Issue**: "API key not detected"
```bash
# Solution: Check config file location and YAML syntax
cat ~/.config/subfinder/provider-config.yaml
# Ensure proper indentation (2 spaces, not tabs)
```

**Issue**: Rate limiting errors
```bash
# Solution: Add rate limiting to config
# Add to provider-config.yaml:
# ratelimit: 5
```

**Issue**: Timeout errors
```bash
# Solution: Increase timeout
# Add to provider-config.yaml:
# timeout: 60
```

---

## Pro Tips for Claude Code

1. **Start with free sources** - subfinder works great without any API keys
2. **Add API keys incrementally** - test each one individually
3. **Use multiple GitHub tokens** - rotate for higher rate limits
4. **Monitor API usage** - most free tiers have monthly limits
5. **Keep configs secure** - never commit API keys to Git
6. **Test before full scan** - use `-d example.com -v` to verify setup
7. **Backup configs** - keep a backup before making changes
8. **Use environment variables** - for sensitive deployments:
   ```bash
   export SHODAN_API_KEY="your_key"
   # Reference in config as: ${SHODAN_API_KEY}
   ```

---

## Quick Reference

| Service | Free Tier | Best For | Get Key |
|---------|-----------|----------|---------|
| GitHub | Yes (5k/hr) | Subdomain enum | github.com/settings/tokens |
| Chaos | Yes | Security research | chaos.projectdiscovery.io |
| VirusTotal | Yes (4/min) | General recon | virustotal.com/gui/my-apikey |
| Shodan | Yes (100/mo) | Service discovery | account.shodan.io |
| Censys | Yes (250/mo) | Certificate data | search.censys.io/account/api |
| SecurityTrails | Paid | Professional use | securitytrails.com |
| BinaryEdge | Paid | Large scopes | app.binaryedge.io |

---

## Environment Variables Alternative

Instead of storing keys in config files, use environment variables:

```bash
# Add to ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your_shodan_key"
export VIRUSTOTAL_API_KEY="your_vt_key"
export GITHUB_TOKEN="your_github_token"
export CHAOS_API_KEY="your_chaos_key"

# Subfinder will automatically detect these environment variables
```

Then in provider-config.yaml:
```yaml
shodan:
  - ${SHODAN_API_KEY}

virustotal:
  - ${VIRUSTOTAL_API_KEY}

github:
  - ${GITHUB_TOKEN}
```

This is more secure for shared systems or CI/CD pipelines.
