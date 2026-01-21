# Reconnaissance Workflows

Pre-built workflow templates for common reconnaissance scenarios using subfinder and httpx.

---

## Workflow 1: Basic Subdomain Enumeration to Live Hosts

**Use Case:** Quick reconnaissance of a single domain to find live web applications.

**Difficulty:** Beginner  
**Time:** 2-5 minutes  
**Tools:** subfinder, httpx

### Commands

```bash
# Step 1: Enumerate subdomains
subfinder -d target.com -o subdomains.txt

# Step 2: Find live hosts
cat subdomains.txt | httpx -silent -o live-hosts.txt

# Step 3: View results
cat live-hosts.txt
```

### Enhanced Version with Technology Detection

```bash
# One-liner with tech detection
subfinder -d target.com -silent | \
  httpx -silent -tech-detect -status-code -title -web-server | \
  tee live-hosts-with-tech.txt
```

### Expected Output

```
https://www.target.com [200] [nginx] WordPress 6.2
https://api.target.com [401] [Apache/2.4] 
https://dev.target.com [403] [nginx] 
https://staging.target.com [200] [Cloudflare] Laravel
```

**Pro Tips:**
- Use `-silent` for cleaner output in pipelines
- Save intermediate results for documentation
- Add `-mc 200,401,403` to httpx for specific status codes

---

## Workflow 2: Comprehensive Reconnaissance with Full Analysis

**Use Case:** Complete reconnaissance with technology detection, screenshots, and analysis.

**Difficulty:** Intermediate  
**Time:** 10-30 minutes  
**Tools:** subfinder, httpx, recon_helper.py

### Commands

```bash
#!/bin/bash
DOMAIN=$1
OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR

# Step 1: Subdomain enumeration with all sources
echo "[1/5] Enumerating subdomains..."
subfinder -d $DOMAIN -all -recursive -o $OUTPUT_DIR/subdomains.txt

# Step 2: Find live hosts
echo "[2/5] Probing for live hosts..."
cat $OUTPUT_DIR/subdomains.txt | \
  httpx -silent -threads 100 -timeout 10 -o $OUTPUT_DIR/live-hosts.txt

# Step 3: Comprehensive technology detection
echo "[3/5] Detecting technologies..."
cat $OUTPUT_DIR/live-hosts.txt | \
  httpx -tech-detect -status-code -title -web-server -content-length \
        -response-time -json -o $OUTPUT_DIR/tech-results.json

# Step 4: Take screenshots
echo "[4/5] Taking screenshots..."
cat $OUTPUT_DIR/live-hosts.txt | \
  httpx -screenshot -screenshot-path $OUTPUT_DIR/screenshots -silent

# Step 5: Analyze results
echo "[5/5] Analyzing results..."
python3 recon_helper.py analyze $OUTPUT_DIR/tech-results.json \
  --report $OUTPUT_DIR/recon-report.html

# Summary
echo ""
echo "=== Reconnaissance Complete ==="
echo "Domain: $DOMAIN"
echo "Subdomains found: $(wc -l < $OUTPUT_DIR/subdomains.txt)"
echo "Live hosts: $(wc -l < $OUTPUT_DIR/live-hosts.txt)"
echo "Results saved in: $OUTPUT_DIR/"
echo "Report: $OUTPUT_DIR/recon-report.html"
```

### Usage

```bash
chmod +x comprehensive-recon.sh
./comprehensive-recon.sh target.com
```

**Pro Tips:**
- Use `-all` with subfinder for maximum coverage
- Increase threads for faster scanning: `-threads 150`
- Screenshots help verify interesting findings
- Always generate HTML report for documentation

---

## Workflow 3: Multi-Domain Batch Processing

**Use Case:** Scan multiple domains efficiently and organize results.

**Difficulty:** Intermediate  
**Time:** Varies by number of domains  
**Tools:** subfinder, httpx, recon_helper.py

### Commands

#### Method 1: Sequential Processing

```bash
#!/bin/bash
# scan-multiple.sh

INPUT_FILE="domains.txt"
OUTPUT_DIR="multi-domain-recon-$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

while IFS= read -r domain; do
    echo "[+] Scanning: $domain"
    
    # Subdomain enumeration
    subfinder -d $domain -silent -o "$OUTPUT_DIR/${domain}-subdomains.txt"
    
    # Live host detection
    cat "$OUTPUT_DIR/${domain}-subdomains.txt" | \
      httpx -silent -tech-detect -json -o "$OUTPUT_DIR/${domain}-results.json"
    
    echo "    └─ Found $(wc -l < $OUTPUT_DIR/${domain}-subdomains.txt) subdomains"
    echo "    └─ Found $(grep -c '"url"' $OUTPUT_DIR/${domain}-results.json) live hosts"
    
done < $INPUT_FILE

echo ""
echo "[+] Batch scan complete!"
echo "[+] Generating summary report..."

# Generate combined analysis
cat $OUTPUT_DIR/*-results.json | \
  python3 recon_helper.py analyze /dev/stdin --summary
```

#### Method 2: Parallel Processing (Faster)

```bash
#!/bin/bash
# parallel-scan.sh

INPUT_FILE="domains.txt"
OUTPUT_DIR="multi-domain-recon-$(date +%Y%m%d)"
MAX_PARALLEL=5

mkdir -p $OUTPUT_DIR

# Function to scan a single domain
scan_domain() {
    domain=$1
    output_dir=$2
    
    subfinder -d $domain -silent | \
      httpx -silent -tech-detect -json -o "${output_dir}/${domain}-results.json"
    
    echo "[+] Completed: $domain"
}

export -f scan_domain
export OUTPUT_DIR

# Parallel execution
cat $INPUT_FILE | \
  xargs -I {} -P $MAX_PARALLEL bash -c 'scan_domain "$@"' _ {} $OUTPUT_DIR

echo "[+] All scans complete!"
```

**Pro Tips:**
- Use parallel processing for large lists
- Adjust `MAX_PARALLEL` based on your bandwidth
- Monitor API rate limits when scanning many domains
- Organize output by domain for easy review

---

## Workflow 4: Continuous Monitoring & Change Detection

**Use Case:** Monitor infrastructure for new subdomains and changes over time.

**Difficulty:** Intermediate  
**Time:** 5-10 minutes per scan  
**Tools:** subfinder, httpx, recon_helper.py

### Initial Setup

```bash
#!/bin/bash
# initial-baseline.sh

DOMAIN=$1
BASELINE_DIR="monitoring/${DOMAIN}/baseline"

mkdir -p $BASELINE_DIR

# Create baseline
echo "[+] Creating baseline for $DOMAIN..."
subfinder -d $DOMAIN -all -o $BASELINE_DIR/subdomains.txt

cat $BASELINE_DIR/subdomains.txt | \
  httpx -silent -tech-detect -json -o $BASELINE_DIR/tech-data.json

echo "[+] Baseline created: $BASELINE_DIR/"
echo "[+] Subdomains: $(wc -l < $BASELINE_DIR/subdomains.txt)"
```

### Monitoring Script

```bash
#!/bin/bash
# monitor-changes.sh

DOMAIN=$1
BASELINE_DIR="monitoring/${DOMAIN}/baseline"
CURRENT_DIR="monitoring/${DOMAIN}/scan-$(date +%Y%m%d_%H%M%S)"

if [ ! -d "$BASELINE_DIR" ]; then
    echo "[!] No baseline found. Run initial-baseline.sh first."
    exit 1
fi

mkdir -p $CURRENT_DIR

# Current scan
echo "[+] Scanning $DOMAIN for changes..."
subfinder -d $DOMAIN -all -o $CURRENT_DIR/subdomains.txt

cat $CURRENT_DIR/subdomains.txt | \
  httpx -silent -tech-detect -json -o $CURRENT_DIR/tech-data.json

# Compare with baseline
echo ""
echo "[+] Comparing with baseline..."
python3 recon_helper.py compare-subs \
  $BASELINE_DIR/subdomains.txt \
  $CURRENT_DIR/subdomains.txt \
  -o $CURRENT_DIR/changes-report.txt

# Check for new live hosts
comm -13 <(sort $BASELINE_DIR/subdomains.txt) \
         <(sort $CURRENT_DIR/subdomains.txt) > $CURRENT_DIR/new-subdomains.txt

if [ -s $CURRENT_DIR/new-subdomains.txt ]; then
    echo ""
    echo "[!] NEW SUBDOMAINS DETECTED!"
    cat $CURRENT_DIR/new-subdomains.txt | httpx -silent -tech-detect -title
fi

# Update baseline (optional)
# cp $CURRENT_DIR/subdomains.txt $BASELINE_DIR/subdomains.txt
```

### Automated Monitoring with Cron

```bash
# Add to crontab for daily monitoring
# crontab -e

# Run every day at 2 AM
0 2 * * * /path/to/monitor-changes.sh target.com >> /var/log/recon-monitor.log 2>&1

# Run every week on Monday at 3 AM
0 3 * * 1 /path/to/monitor-changes.sh target.com >> /var/log/recon-monitor.log 2>&1
```

**Pro Tips:**
- Keep historical scans for trend analysis
- Alert on new subdomains (integrate with Slack/Discord)
- Update baseline after verifying changes
- Monitor for removed subdomains (potential takedowns)

---

## Workflow 5: API-Focused Reconnaissance

**Use Case:** Discover and analyze API endpoints across infrastructure.

**Difficulty:** Intermediate  
**Time:** 10-20 minutes  
**Tools:** subfinder, httpx, recon_helper.py

### Commands

```bash
#!/bin/bash
# api-discovery.sh

DOMAIN=$1
OUTPUT_DIR="api-recon-${DOMAIN}-$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

# Step 1: Find all subdomains
echo "[1/5] Finding subdomains..."
subfinder -d $DOMAIN -silent -o $OUTPUT_DIR/all-subdomains.txt

# Step 2: Probe for API endpoints
echo "[2/5] Probing for API endpoints..."
cat $OUTPUT_DIR/all-subdomains.txt | \
  httpx -silent -path /api,/api/v1,/api/v2,/api/v3,/graphql,/rest,/swagger \
        -mc 200,401,403,404 -o $OUTPUT_DIR/api-paths.txt

# Step 3: Get API subdomains (api., rest., graphql., etc.)
echo "[3/5] Finding API subdomains..."
grep -iE "^https?://(api|rest|graphql|swagger|gateway|microservice)" \
  $OUTPUT_DIR/all-subdomains.txt > $OUTPUT_DIR/api-subdomains.txt || true

# Step 4: Comprehensive API analysis
echo "[4/5] Analyzing API endpoints..."
cat $OUTPUT_DIR/api-paths.txt $OUTPUT_DIR/api-subdomains.txt | \
  sort -u | \
  httpx -silent -tech-detect -status-code -content-type -json \
        -o $OUTPUT_DIR/api-results.json

# Step 5: Extract API technologies
echo "[5/5] Extracting API technologies..."
python3 recon_helper.py extract $OUTPUT_DIR/api-results.json \
  --tech api -o $OUTPUT_DIR/api-endpoints.txt

# Additional API paths to test
echo "[+] Testing additional API paths..."
cat $OUTPUT_DIR/api-endpoints.txt | \
  httpx -silent -path /docs,/swagger-ui,/api-docs,/openapi.json,/swagger.json \
        -mc 200 | tee -a $OUTPUT_DIR/api-documentation.txt

# Summary
echo ""
echo "=== API Discovery Complete ==="
echo "Total API endpoints: $(wc -l < $OUTPUT_DIR/api-endpoints.txt)"
echo "API documentation found: $(wc -l < $OUTPUT_DIR/api-documentation.txt 2>/dev/null || echo 0)"
echo "Results: $OUTPUT_DIR/"
```

### API Fuzzing Integration

```bash
# After finding API endpoints, prepare for fuzzing
cat api-endpoints.txt | while read url; do
    echo "[+] Preparing fuzzing target: $url"
    # Generate target list for ffuf
    echo $url >> api-fuzz-targets.txt
done

echo "[+] API endpoints ready for fuzzing with ffuf"
echo "[+] Next: ffuf -w api-wordlist.txt -u TARGET/FUZZ -mc 200,401"
```

**Pro Tips:**
- Look for `/swagger`, `/docs`, `/api-docs` for documentation
- Test common versioning: `/api/v1`, `/api/v2`, `/api/v3`
- Check for GraphQL introspection: `/graphql?query={__schema{types{name}}}`
- Save 401/403 responses - they confirm endpoint exists
- Use results with API-specific tools like Postman, Arjun

---

## Workflow 6: Integration with Other Tools

**Use Case:** Chain reconnaissance results with vulnerability scanning and fuzzing.

**Difficulty:** Advanced  
**Time:** 30+ minutes  
**Tools:** subfinder, httpx, nuclei, ffuf, naabu

### Full Security Assessment Pipeline

```bash
#!/bin/bash
# full-assessment.sh

DOMAIN=$1
WORK_DIR="assessment-${DOMAIN}-$(date +%Y%m%d)"

mkdir -p $WORK_DIR/{recon,vuln,fuzz,ports}

echo "=== Phase 1: Reconnaissance ==="

# Subdomain enumeration
subfinder -d $DOMAIN -all -o $WORK_DIR/recon/subdomains.txt

# Live host detection
cat $WORK_DIR/recon/subdomains.txt | \
  httpx -silent -tech-detect -json -o $WORK_DIR/recon/live-hosts.json

# Extract live URLs
cat $WORK_DIR/recon/live-hosts.json | jq -r '.url' > $WORK_DIR/recon/live-urls.txt

echo "=== Phase 2: Port Scanning ==="

# Port scan with naabu
cat $WORK_DIR/recon/subdomains.txt | \
  naabu -silent -top-ports 100 -o $WORK_DIR/ports/open-ports.txt

# Probe ports with httpx
cat $WORK_DIR/ports/open-ports.txt | \
  httpx -silent -o $WORK_DIR/recon/additional-hosts.txt

echo "=== Phase 3: Vulnerability Scanning ==="

# Nuclei vulnerability scanning
cat $WORK_DIR/recon/live-urls.txt | \
  nuclei -silent -severity critical,high,medium \
         -o $WORK_DIR/vuln/nuclei-findings.txt

# Specific technology scanning
python3 recon_helper.py extract $WORK_DIR/recon/live-hosts.json \
  --tech wordpress -o $WORK_DIR/vuln/wordpress-sites.txt

# WPScan on WordPress sites (if any)
if [ -s $WORK_DIR/vuln/wordpress-sites.txt ]; then
    cat $WORK_DIR/vuln/wordpress-sites.txt | \
      xargs -I {} wpscan --url {} --random-user-agent \
      --output $WORK_DIR/vuln/wpscan-{}.txt
fi

echo "=== Phase 4: Content Discovery ==="

# Directory fuzzing with ffuf
python3 recon_helper.py generate-targets $WORK_DIR/recon/live-hosts.json \
  -o $WORK_DIR/fuzz/

# Fuzz interesting targets
for target_file in $WORK_DIR/fuzz/*.txt; do
    name=$(basename $target_file .txt)
    cat $target_file | while read url; do
        ffuf -w ~/wordlists/common.txt -u $url/FUZZ \
             -ac -mc 200,301,302,401,403 \
             -o $WORK_DIR/fuzz/${name}-results.json -of json
    done
done

echo "=== Assessment Complete ==="
echo "Results in: $WORK_DIR/"
tree $WORK_DIR/
```

### Nuclei Integration

```bash
# Quick nuclei scan on live hosts
subfinder -d target.com -silent | \
  httpx -silent | \
  nuclei -t cves/ -severity critical,high

# Comprehensive nuclei scan
subfinder -d target.com -silent | \
  httpx -silent | \
  nuclei -t ~/nuclei-templates/ \
         -severity critical,high,medium \
         -o nuclei-findings.txt
```

### Naabu Integration

```bash
# Port scan then probe with httpx
subfinder -d target.com -silent | \
  naabu -silent -top-ports 1000 | \
  httpx -silent -tech-detect

# Full port scan
cat subdomains.txt | \
  naabu -silent -p - | \
  httpx -silent -o all-services.txt
```

### FFuf Integration

```bash
# Generate targets for fuzzing
python3 recon_helper.py generate-targets results.json -o fuzz-targets/

# Fuzz WordPress sites
cat fuzz-targets/wordpress-targets.txt | \
  xargs -I {} ffuf -w ~/wordlists/wordpress.txt -u {}/FUZZ -ac

# Fuzz admin panels
cat fuzz-targets/admin-panels.txt | \
  xargs -I {} ffuf -w ~/wordlists/admin-paths.txt -u {}/FUZZ -ac
```

**Pro Tips:**
- Run tools in sequence for systematic assessment
- Save all intermediate results
- Use parallel processing where possible
- Respect rate limits and target infrastructure
- Document findings in real-time

---

## Workflow 7: Technology-Specific Reconnaissance

**Use Case:** Target specific technologies (WordPress, APIs, etc.) for focused testing.

**Difficulty:** Intermediate  
**Time:** 10-15 minutes  
**Tools:** subfinder, httpx, recon_helper.py

### WordPress-Focused Workflow

```bash
#!/bin/bash
# wordpress-recon.sh

DOMAIN=$1
OUTPUT_DIR="wordpress-recon-$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

# Find all subdomains
subfinder -d $DOMAIN -silent | \
  httpx -silent -tech-detect -json -o $OUTPUT_DIR/all-results.json

# Extract WordPress sites
python3 recon_helper.py extract $OUTPUT_DIR/all-results.json \
  --tech wordpress -o $OUTPUT_DIR/wordpress-sites.txt

# Probe WordPress paths
cat $OUTPUT_DIR/wordpress-sites.txt | \
  httpx -path /wp-admin,/wp-login.php,/wp-json,/xmlrpc.php \
        -mc 200,301,302,403 -title -status-code

# Find WordPress version
cat $OUTPUT_DIR/wordpress-sites.txt | \
  httpx -path /wp-includes/js/jquery/jquery.js -mc 200 \
        -silent | tee $OUTPUT_DIR/wp-assets.txt

# Ready for WPScan
echo "[+] Found $(wc -l < $OUTPUT_DIR/wordpress-sites.txt) WordPress sites"
echo "[+] Ready for WPScan or WordPress-specific testing"
```

### API-Specific Workflow

```bash
#!/bin/bash
# api-recon.sh

DOMAIN=$1

# Find API endpoints and documentation
subfinder -d $DOMAIN -silent | \
  httpx -silent -path /api,/api/v1,/graphql,/swagger,/openapi.json \
        -mc 200,401,403 -tech-detect -title | \
  tee api-endpoints.txt

# Test for exposed API documentation
cat api-endpoints.txt | \
  httpx -path /swagger-ui,/docs,/api-docs,/redoc \
        -mc 200 -title

# GraphQL introspection
cat api-endpoints.txt | grep graphql | \
  httpx -method POST \
        -header "Content-Type: application/json" \
        -body '{"query":"{__schema{types{name}}}"}' \
        -mc 200
```

### Admin Panel Discovery

```bash
#!/bin/bash
# admin-discovery.sh

DOMAIN=$1

# Find admin panels
subfinder -d $DOMAIN -silent | \
  httpx -silent -path /admin,/administrator,/wp-admin,/phpmyadmin,/cpanel \
        -mc 200,301,302,401,403 -title -status-code | \
  tee admin-panels.txt

# Test common admin paths
cat admin-panels.txt | \
  httpx -path /login,/signin,/auth,/dashboard,/panel \
        -mc 200,301,302 -title -screenshot
```

**Pro Tips:**
- Use technology-specific wordlists for better results
- Screenshots help identify admin panels visually
- 403 responses often indicate valid paths
- Combine with technology-specific scanners (WPScan, etc.)

---

## Workflow 8: Large-Scale Enumeration

**Use Case:** Scan large scopes with thousands of domains efficiently.

**Difficulty:** Advanced  
**Time:** Hours (depending on scope)  
**Tools:** subfinder, httpx

### Optimized for Scale

```bash
#!/bin/bash
# large-scale-recon.sh

INPUT_FILE=$1  # File with thousands of domains
OUTPUT_DIR="large-scale-$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

# Step 1: Subdomain enumeration (parallel)
echo "[+] Phase 1: Subdomain enumeration..."
cat $INPUT_FILE | \
  xargs -P 10 -I {} sh -c 'subfinder -d {} -silent' | \
  sort -u > $OUTPUT_DIR/all-subdomains.txt

echo "    └─ Found $(wc -l < $OUTPUT_DIR/all-subdomains.txt) unique subdomains"

# Step 2: Live host detection (high threads)
echo "[+] Phase 2: Probing live hosts..."
cat $OUTPUT_DIR/all-subdomains.txt | \
  httpx -silent -threads 200 -rate-limit 100 -timeout 5 \
        -o $OUTPUT_DIR/live-hosts.txt

echo "    └─ Found $(wc -l < $OUTPUT_DIR/live-hosts.txt) live hosts"

# Step 3: Technology detection (batched)
echo "[+] Phase 3: Technology detection..."
cat $OUTPUT_DIR/live-hosts.txt | \
  httpx -tech-detect -status-code -title -threads 150 \
        -json -o $OUTPUT_DIR/tech-results.json

# Step 4: Generate summary
echo "[+] Phase 4: Generating summary..."
python3 recon_helper.py analyze $OUTPUT_DIR/tech-results.json \
  --summary --json > $OUTPUT_DIR/summary.json

# Step 5: Generate target lists
python3 recon_helper.py generate-targets $OUTPUT_DIR/tech-results.json \
  -o $OUTPUT_DIR/targets/

echo ""
echo "=== Large-Scale Recon Complete ==="
cat $OUTPUT_DIR/summary.json | jq '.'
```

### Memory-Efficient Streaming

```bash
# For extremely large datasets, use streaming
cat huge-subdomain-list.txt | \
  while read -r sub; do
    echo "$sub" | httpx -silent -tech-detect -json
  done >> streaming-results.jsonl

# Process in chunks
split -l 10000 huge-list.txt chunk-
for chunk in chunk-*; do
    cat $chunk | httpx -silent -tech-detect -json -o "results-$(basename $chunk).json"
done
```

**Pro Tips:**
- Increase threads for faster processing: `-threads 200`
- Use rate limiting to avoid overwhelming targets: `-rate-limit 100`
- Process in batches for very large scopes
- Monitor memory usage with large datasets
- Use streaming for millions of subdomains

---

## Workflow 9: Stealth Reconnaissance

**Use Case:** Careful, low-noise reconnaissance to avoid detection.

**Difficulty:** Intermediate  
**Time:** Longer (intentionally slow)  
**Tools:** subfinder, httpx

### Low-Profile Scanning

```bash
#!/bin/bash
# stealth-recon.sh

DOMAIN=$1
OUTPUT_DIR="stealth-recon-$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

# Step 1: Subdomain enumeration (passive only)
echo "[+] Passive subdomain enumeration..."
subfinder -d $DOMAIN -silent -sources crtsh,certspotter,virustotal \
  -o $OUTPUT_DIR/subdomains.txt

# Wait before next phase
sleep 10

# Step 2: Slow, careful probing
echo "[+] Careful probing (low rate)..."
cat $OUTPUT_DIR/subdomains.txt | \
  httpx -silent -threads 5 -rate-limit 2 -delay 1s \
        -random-agent -timeout 15 \
        -o $OUTPUT_DIR/live-hosts.txt

# Wait between phases
sleep 30

# Step 3: Minimal tech detection
echo "[+] Minimal reconnaissance..."
cat $OUTPUT_DIR/live-hosts.txt | \
  httpx -status-code -title -threads 5 -rate-limit 2 \
        -random-agent -o $OUTPUT_DIR/results.txt

echo "[+] Stealth recon complete"
```

### Distributed Reconnaissance

```bash
# Use different IPs/proxies for each phase
# Phase 1: From IP1
subfinder -d target.com -o phase1.txt

# Phase 2: From IP2 (different location)
cat phase1.txt | httpx -proxy http://proxy1:8080 -o phase2.txt

# Phase 3: From IP3
cat phase2.txt | httpx -tech-detect -proxy http://proxy2:8080
```

**Pro Tips:**
- Use passive sources only (no active DNS queries)
- Low thread count: `-threads 5`
- Rate limiting: `-rate-limit 2`
- Random User-Agents: `-random-agent`
- Add delays: `-delay 1s-3s`
- Spread scans over time
- Use proxies or VPNs

---

## Workflow 10: Report Generation & Documentation

**Use Case:** Generate professional reports for clients or documentation.

**Difficulty:** Beginner  
**Time:** 5 minutes  
**Tools:** recon_helper.py

### Complete Report Workflow

```bash
#!/bin/bash
# generate-report.sh

DOMAIN=$1
SCAN_DIR=$2  # Directory with scan results

# Ensure JSON results exist
if [ ! -f "$SCAN_DIR/tech-results.json" ]; then
    echo "[!] No JSON results found. Run reconnaissance first."
    exit 1
fi

# Generate HTML report
python3 recon_helper.py analyze $SCAN_DIR/tech-results.json \
  --report $SCAN_DIR/${DOMAIN}-report-$(date +%Y%m%d).html

# Generate summary for quick review
python3 recon_helper.py analyze $SCAN_DIR/tech-results.json \
  --summary > $SCAN_DIR/summary.txt

# Generate target lists for follow-up
python3 recon_helper.py generate-targets $SCAN_DIR/tech-results.json \
  -o $SCAN_DIR/targets/

# Create README
cat > $SCAN_DIR/README.md << EOF
# Reconnaissance Report: $DOMAIN
**Date:** $(date +"%Y-%m-%d")

## Summary
- Total Subdomains: $(wc -l < $SCAN_DIR/subdomains.txt 2>/dev/null || echo "N/A")
- Live Hosts: $(wc -l < $SCAN_DIR/live-hosts.txt 2>/dev/null || echo "N/A")

## Files
- Full Report: ${DOMAIN}-report-$(date +%Y%m%d).html
- Summary: summary.txt
- Target Lists: targets/

## Next Steps
1. Review HTML report for interesting findings
2. Check targets/ directory for organized target lists
3. Run vulnerability scans on identified technologies
4. Perform content discovery with ffuf

EOF

echo "[+] Report generated: $SCAN_DIR/${DOMAIN}-report-$(date +%Y%m%d).html"
echo "[+] Documentation: $SCAN_DIR/README.md"
```

**Pro Tips:**
- Always generate HTML reports for clients
- Include screenshots for visual evidence
- Organize results by technology
- Create README for context
- Version control your reports

---

## Quick Reference

### One-Liners for Common Tasks

```bash
# Quick subdomain to live hosts
subfinder -d target.com -silent | httpx -silent

# With tech detection
subfinder -d target.com -silent | httpx -silent -tech-detect -title

# Find WordPress sites
subfinder -d target.com -silent | httpx -silent -tech-detect -json | \
  jq -r 'select(.technologies[] | contains("WordPress")) | .url'

# Find admin panels
subfinder -d target.com -silent | \
  httpx -silent -path /admin,/login -mc 200,301,302,403 -title

# Find APIs
subfinder -d target.com -silent | \
  httpx -silent -path /api,/graphql -mc 200,401,403

# Quick scan with report
subfinder -d target.com -silent | \
  httpx -silent -tech-detect -json -o results.json && \
  python3 recon_helper.py analyze results.json --report report.html
```

---

## Best Practices for Claude Code

1. **Always save intermediate results** - Enable auditing and debugging
2. **Use JSON output** - Easier to parse and analyze programmatically
3. **Generate reports** - Provide users with actionable documentation
4. **Organize by domain** - Keep results separated for multiple targets
5. **Chain tools logically** - subfinder → httpx → analysis → targets
6. **Handle errors gracefully** - Check if files exist before processing
7. **Provide progress updates** - Keep users informed during long scans
8. **Use appropriate timeouts** - Adjust based on network conditions
9. **Respect rate limits** - Especially with API sources
10. **Clean up temporary files** - Good housekeeping

---

## Troubleshooting Common Issues

### Issue: No subdomains found
```bash
# Solution: Try with verbose mode to see what's happening
subfinder -d target.com -v

# Check if using API sources
subfinder -d target.com -sources shodan,virustotal -v
```

### Issue: All hosts appear down
```bash
# Solution: Increase timeout and try both protocols
httpx -l urls.txt -timeout 30 -probe
```

### Issue: Rate limiting errors
```bash
# Solution: Reduce threads and add rate limiting
httpx -l urls.txt -threads 10 -rate-limit 5 -delay 1s
```

### Issue: Too many false positives
```bash
# Solution: Add stricter matching
httpx -l urls.txt -mc 200,301,302 -fc 404,403
```

---

## Integration Examples

### With Slack Notifications

```bash
# Send summary to Slack
SUMMARY=$(python3 recon_helper.py analyze results.json --summary)
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Recon Complete:\n$SUMMARY\"}" \
  $SLACK_WEBHOOK_URL
```

### With GitHub Actions

```yaml
name: Subdomain Monitoring
on:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  recon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run reconnaissance
        run: |
          subfinder -d target.com -silent | \
            httpx -silent -json -o results.json
          python3 recon_helper.py compare-subs baseline.txt results.json
```

### With Database Storage

```bash
# Store results in database
cat results.json | while read line; do
  echo "INSERT INTO recon_results VALUES (...);" | psql -d recon_db
done
```

---

**End of Workflows Guide**