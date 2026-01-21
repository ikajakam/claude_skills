# Wordlists for Reconnaissance

Comprehensive guide to wordlists for subfinder and httpx during reconnaissance operations.

---

## SecLists - Primary Source

**Repository:** https://github.com/danielmiessler/SecLists

SecLists is the most comprehensive collection of wordlists for security testing.

### Installation

```bash
# Clone the repository
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists

# Or download specific lists
cd ~/wordlists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
```

### Directory Structure

```
SecLists/
├── Discovery/
│   ├── DNS/              # Subdomain wordlists
│   ├── Web-Content/      # Directory/file wordlists
│   └── Infrastructure/   # Common hostnames
├── Fuzzing/
├── Passwords/
├── Usernames/
└── ...
```

---

## Subdomain Wordlists (for Subfinder)

While subfinder primarily uses passive enumeration, wordlists can be useful for:
- Subdomain permutation/alteration tools
- Brute-force scenarios (when authorized)
- Completeness checks

### Recommended Subdomain Lists

#### 1. **Small/Quick (Top 1000)**
```bash
# Location in SecLists
SecLists/Discovery/DNS/subdomains-top1million-5000.txt (first 1000 lines)

# Download directly
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt

# Usage
head -1000 subdomains-top1million-5000.txt > subdomains-top1000.txt
```

**Best for:** Quick checks, small targets, initial reconnaissance

#### 2. **Medium (Top 5000)** ⭐ RECOMMENDED
```bash
# Location
SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Size: ~5,000 subdomains
# Common entries: www, mail, ftp, api, dev, staging, test, admin, etc.
```

**Best for:** Most standard reconnaissance scenarios

#### 3. **Large (Top 20,000)**
```bash
# Location
SecLists/Discovery/DNS/subdomains-top1million-20000.txt

# Size: ~20,000 subdomains
```

**Best for:** Comprehensive reconnaissance, large organizations

#### 4. **Comprehensive (Top 100,000+)**
```bash
# Location
SecLists/Discovery/DNS/subdomains-top1million-110000.txt

# Size: ~110,000 subdomains
```

**Best for:** Exhaustive enumeration, very large scopes

#### 5. **Bitquark Subdomains** ⭐ HIGH QUALITY
```bash
# Location
SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt

# High-quality, actively maintained list
```

**Best for:** Modern infrastructure, cloud-focused

### Alternative Subdomain Sources

```bash
# Assetnote Wordlists (High quality)
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt

# n0kovo subdomains (Very comprehensive)
wget https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt

# jhaddix all.txt (Popular)
wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/f58e82c9abfa46a932eb92edbe6b18214141439b/all.txt
```

### Common Subdomain Patterns

Create custom wordlist for organization-specific patterns:

```bash
# common-subdomains.txt
www
mail
ftp
smtp
pop
imap
webmail
admin
administrator
portal
login
api
api-v1
api-v2
api-v3
rest
graphql
gateway
dev
development
staging
stage
test
testing
qa
uat
prod
production
demo
sandbox
beta
alpha
preview
app
mobile
m
web
www1
www2
blog
shop
store
cdn
static
assets
img
images
media
files
upload
downloads
docs
help
support
status
monitor
internal
intranet
vpn
remote
citrix
owa
exchange
autodiscover
sip
voip
conference
video
meeting
jira
confluence
gitlab
github
jenkins
ci
cd
build
deploy
docker
k8s
kubernetes
cloud
aws
azure
gcp
s3
backup
db
database
mysql
postgres
mongo
redis
elastic
kibana
grafana
prometheus
logs
metrics
```

**Usage:**
```bash
# These can be used with subdomain alteration tools
# or for validation after passive enumeration
```

---

## Path/Directory Wordlists (for Httpx)

For probing paths with `httpx -path`

### Recommended Path Lists

#### 1. **Common Paths (Quick)** ⭐ START HERE
```bash
# Location
SecLists/Discovery/Web-Content/common.txt

# Size: ~4,600 entries
# Common paths: admin, login, api, backup, config, etc.
```

**Best for:** Quick path discovery on live hosts

**Usage:**
```bash
httpx -l live-hosts.txt -path /$(cat ~/wordlists/SecLists/Discovery/Web-Content/common.txt) -mc 200,403
```

#### 2. **raft-small-words.txt**
```bash
# Location
SecLists/Discovery/Web-Content/raft-small-words.txt

# Size: ~43,000 entries
# Good balance of speed and coverage
```

**Best for:** Standard web applications

#### 3. **raft-medium-directories.txt** ⭐ RECOMMENDED
```bash
# Location
SecLists/Discovery/Web-Content/raft-medium-directories.txt

# Size: ~30,000 entries
# Focused on directories
```

**Best for:** Directory discovery

#### 4. **directory-list-2.3-medium.txt**
```bash
# Location
SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Size: ~220,000 entries
# Very comprehensive
```

**Best for:** Comprehensive directory enumeration

### Technology-Specific Path Lists

#### WordPress Paths
```bash
# Location
SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt

# Common WordPress paths
/wp-admin
/wp-login.php
/wp-content
/wp-includes
/wp-json
/wp-json/wp/v2/users
/xmlrpc.php
/readme.html
/license.txt
/wp-config.php
/wp-config.php.bak
/.wp-config.php.swp
```

**Custom WordPress list:**
```bash
# wordpress-paths.txt
/wp-admin
/wp-admin/admin-ajax.php
/wp-login.php
/wp-content/uploads
/wp-content/plugins
/wp-content/themes
/wp-json
/wp-json/wp/v2/users
/wp-json/wp/v2/posts
/xmlrpc.php
/wp-cron.php
/readme.html
/license.txt
/wp-config.php.bak
/wp-config.php.old
/wp-config.php~
/.wp-config.php.swp
/wp-content/debug.log
```

**Usage:**
```bash
cat wordpress-sites.txt | httpx -path wordpress-paths.txt -mc 200,403,500
```

#### Joomla Paths
```bash
# joomla-paths.txt
/administrator
/administrator/index.php
/configuration.php
/configuration.php.bak
/htaccess.txt
/web.config.txt
/README.txt
/LICENSE.txt
/administrator/manifests/files/joomla.xml
/language/en-GB/en-GB.xml
/libraries/joomla/version.php
```

#### Drupal Paths
```bash
# drupal-paths.txt
/user
/user/login
/admin
/admin/config
/node
/CHANGELOG.txt
/README.txt
/core/CHANGELOG.txt
/sites/default/settings.php
/sites/default/files
/.git/config
```

### API-Specific Paths

#### API Endpoint Discovery
```bash
# api-paths.txt
/api
/api/v1
/api/v2
/api/v3
/api/v4
/rest
/rest/v1
/rest/v2
/graphql
/graphql/v1
/swagger
/swagger.json
/swagger.yaml
/swagger-ui
/swagger-ui.html
/openapi.json
/openapi.yaml
/api-docs
/api/docs
/api/documentation
/docs
/documentation
/redoc
/rapidoc
/api/swagger
/api/swagger.json
/api/openapi.json
/v1
/v2
/v3
/api/health
/api/status
/api/version
/healthcheck
/health
/status
/ping
/metrics
/api/metrics
```

**Usage:**
```bash
cat live-hosts.txt | httpx -path api-paths.txt -mc 200,401,403 -title
```

#### GraphQL Specific
```bash
# graphql-paths.txt
/graphql
/graphql/v1
/graphql/console
/graphql/playground
/graphiql
/playground
/api/graphql
/v1/graphql
/query
/api/query
```

### Admin Panel Paths

```bash
# admin-paths.txt
/admin
/admin/
/admin/index.php
/admin/login.php
/admin/login
/administrator
/administrator/
/adminpanel
/admin_panel
/admin-panel
/controlpanel
/control-panel
/cpanel
/cPanel
/manage
/manager
/management
/dashboard
/backend
/backoffice
/panel
/login
/signin
/auth
/authentication
/user/login
/account/login
/wp-admin
/wp-login.php
/phpmyadmin
/phpMyAdmin
/pma
/adminer
/adminer.php
/db
/database
/mysql
/myadmin
/admin.php
/admin.html
/login.php
/login.html
/signin.php
/console
/admin/console
/admin/dashboard
/secure
/secret
/private
```

**Usage:**
```bash
cat live-hosts.txt | httpx -path admin-paths.txt -mc 200,301,302,401,403 -title -screenshot
```

### Sensitive Files & Backups

```bash
# sensitive-files.txt
/.git
/.git/config
/.git/HEAD
/.gitignore
/.svn
/.svn/entries
/.hg
/.bzr
/.env
/.env.local
/.env.production
/.env.dev
/.env.development
/.env.staging
/.env.backup
/.env.old
/.env.save
/config.php
/config.php.bak
/configuration.php
/configuration.php.bak
/settings.php
/settings.php.bak
/database.yml
/database.php
/db.php
/db_config.php
/wp-config.php
/wp-config.php.bak
/wp-config.php.old
/web.config
/web.config.bak
/application.properties
/application.yml
/application-prod.yml
/config.json
/config.yml
/secrets.yml
/backup.sql
/backup.tar.gz
/backup.zip
/database.sql
/db.sql
/dump.sql
/site.sql
/old
/backup
/backups
/bak
/_backup
/_bak
/tmp
/temp
/cache
/logs
/log
/debug.log
/error.log
/access.log
/phpinfo.php
/info.php
/test.php
/debug.php
```

**Usage:**
```bash
cat live-hosts.txt | httpx -path sensitive-files.txt -mc 200,403 -content-length
```

### Common Technology Files

#### Framework Detection
```bash
# framework-files.txt
/composer.json
/composer.lock
/package.json
/package-lock.json
/yarn.lock
/Gemfile
/Gemfile.lock
/requirements.txt
/pom.xml
/build.gradle
/go.mod
/go.sum
/Cargo.toml
/Cargo.lock
/.dockerignore
/Dockerfile
/docker-compose.yml
/Makefile
/Rakefile
/.htaccess
/robots.txt
/sitemap.xml
/humans.txt
/security.txt
/.well-known/security.txt
/crossdomain.xml
/clientaccesspolicy.xml
```

#### Version Files
```bash
# version-files.txt
/VERSION
/version.txt
/version.php
/version.json
/CHANGELOG
/CHANGELOG.txt
/CHANGELOG.md
/README
/README.md
/README.txt
/LICENSE
/LICENSE.txt
/INSTALL
/INSTALL.txt
```

---

## Custom Wordlist Creation

### Generate Number-Based Lists (for IDOR testing)

```bash
# Generate 1-10000
seq 1 10000 > numbers-1-10000.txt

# Generate user IDs
seq 1 1000 | awk '{print "user_"$1}' > user-ids.txt

# Generate document IDs
seq 1 5000 | awk '{print "doc_"$1}' > doc-ids.txt
```

**Usage with httpx:**
```bash
# Note: httpx doesn't support FUZZ like ffuf, but you can combine with other tools
# Better to use these with ffuf after initial recon
```

### Generate Date-Based Lists

```bash
# Generate years
seq 2020 2024 > years.txt

# Generate months
echo -e "01\n02\n03\n04\n05\n06\n07\n08\n09\n10\n11\n12" > months.txt

# Generate backup dates
for year in {2020..2024}; do
  for month in {01..12}; do
    echo "backup-${year}-${month}"
  done
done > backup-dates.txt
```

### Generate Organization-Specific Patterns

```bash
#!/bin/bash
# generate-org-wordlist.sh

ORG_NAME="acme"

cat > ${ORG_NAME}-subdomains.txt << EOF
${ORG_NAME}
www-${ORG_NAME}
mail-${ORG_NAME}
${ORG_NAME}-api
${ORG_NAME}-dev
${ORG_NAME}-staging
${ORG_NAME}-prod
${ORG_NAME}-test
${ORG_NAME}-demo
${ORG_NAME}-beta
${ORG_NAME}-portal
${ORG_NAME}-app
${ORG_NAME}-mobile
${ORG_NAME}-store
${ORG_NAME}-shop
${ORG_NAME}-cdn
${ORG_NAME}-static
${ORG_NAME}-admin
${ORG_NAME}-secure
${ORG_NAME}-vpn
${ORG_NAME}-internal
EOF
```

### Combine Multiple Wordlists

```bash
# Merge and deduplicate
cat wordlist1.txt wordlist2.txt wordlist3.txt | sort -u > combined.txt

# Add prefix to all entries
cat wordlist.txt | awk '{print "api-"$1}' > api-wordlist.txt

# Add suffix to all entries
cat wordlist.txt | awk '{print $1"-v1"}' > versioned-wordlist.txt
```

---

## Wordlist Usage with Httpx

### Basic Path Probing

```bash
# Single path
httpx -l urls.txt -path /admin -mc 200,403

# Multiple paths
httpx -l urls.txt -path /admin,/login,/api -mc 200,403

# From file (note: httpx doesn't directly support wordlist files for paths)
# You need to iterate
while read path; do
  httpx -l urls.txt -path "$path" -mc 200,403
done < paths.txt
```

### Efficient Path Discovery

```bash
# Better approach: Use with other tools
# 1. Find live hosts with httpx
subfinder -d target.com -silent | httpx -silent -o live.txt

# 2. Use ffuf for path discovery
cat live.txt | while read url; do
  ffuf -w ~/wordlists/common.txt -u "${url}/FUZZ" -ac -mc 200,403
done
```

### Technology-Specific Scanning

```bash
# WordPress sites
python3 recon_helper.py extract results.json --tech wordpress -o wp-sites.txt
cat wp-sites.txt | httpx -path /wp-admin,/wp-json,/xmlrpc.php -mc 200,403

# API endpoints
cat api-endpoints.txt | httpx -path /swagger.json,/openapi.json,/graphql -mc 200

# Admin panels
cat all-hosts.txt | httpx -path /admin,/administrator,/panel -mc 200,401,403 -title
```

---

## Recommended Wordlist Collections

### Essential Downloads

```bash
#!/bin/bash
# download-wordlists.sh

WORDLIST_DIR=~/wordlists
mkdir -p $WORDLIST_DIR

cd $WORDLIST_DIR

# SecLists (comprehensive)
git clone https://github.com/danielmiessler/SecLists.git

# Assetnote (high quality)
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O assetnote-subdomains.txt

# jhaddix all.txt (popular)
wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/f58e82c9abfa46a932eb92edbe6b18214141439b/all.txt -O jhaddix-all.txt

# n0kovo (comprehensive subdomains)
wget https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt

# Create organized structure
mkdir -p organized/{subdomains,paths,api,admin,sensitive}

# Copy commonly used lists to organized directory
cp SecLists/Discovery/DNS/subdomains-top1million-5000.txt organized/subdomains/
cp SecLists/Discovery/Web-Content/common.txt organized/paths/
cp SecLists/Discovery/Web-Content/raft-medium-directories.txt organized/paths/

echo "[+] Wordlists downloaded to $WORDLIST_DIR"
```

### Wordlist Sizes Reference

| Wordlist | Size | Entries | Best For |
|----------|------|---------|----------|
| common.txt | 100 KB | 4,600 | Quick path scan |
| subdomains-top1million-5000.txt | 50 KB | 5,000 | Standard subdomain enum |
| raft-medium-directories.txt | 300 KB | 30,000 | Directory discovery |
| directory-list-2.3-medium.txt | 1.9 MB | 220,000 | Comprehensive scan |
| bitquark-subdomains-top100000.txt | 1 MB | 100,000 | Large scope subdomain |
| jhaddix all.txt | 10 MB | 2M+ | Exhaustive subdomain |

---

## Quick Reference Commands

### Subdomain Wordlists
```bash
# Small (fast)
~/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Medium (recommended)
~/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

# Large (comprehensive)
~/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
```

### Path Wordlists
```bash
# Quick scan
~/wordlists/SecLists/Discovery/Web-Content/common.txt

# Standard scan
~/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt

# Comprehensive scan
~/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### API Paths
```bash
# Create custom API list
echo -e "/api\n/api/v1\n/api/v2\n/graphql\n/swagger.json\n/openapi.json" > api-common.txt
```

### Admin Paths
```bash
# Create custom admin list
echo -e "/admin\n/administrator\n/login\n/wp-admin\n/phpmyadmin" > admin-common.txt
```

---

## Wordlist Optimization Tips

### 1. Size Optimization
```bash
# Remove duplicates
sort -u wordlist.txt -o wordlist-unique.txt

# Remove blank lines
sed '/^$/d' wordlist.txt > wordlist-clean.txt

# Convert to lowercase
tr '[:upper:]' '[:lower:]' < wordlist.txt > wordlist-lower.txt

# Remove comments
grep -v '^#' wordlist.txt > wordlist-no-comments.txt
```

### 2. Quality Filtering
```bash
# Keep only alphanumeric
grep -E '^[a-zA-Z0-9_-]+$' wordlist.txt > wordlist-alphanumeric.txt

# Remove too short entries
awk 'length($0) > 2' wordlist.txt > wordlist-min3chars.txt

# Remove too long entries
awk 'length($0) < 50' wordlist.txt > wordlist-max50chars.txt
```

### 3. Context-Specific Lists
```bash
# Extract subdomains starting with 'api'
grep '^api' subdomains.txt > api-subdomains.txt

# Extract admin-related paths
grep -iE 'admin|panel|dashboard' paths.txt > admin-paths.txt

# Extract backup-related
grep -iE 'backup|bak|old|archive' paths.txt > backup-paths.txt
```

---

## Integration with Recon Workflow

### Complete Workflow Example

```bash
#!/bin/bash
# recon-with-wordlists.sh

DOMAIN=$1
WORDLIST_DIR=~/wordlists/SecLists

# Phase 1: Passive subdomain enumeration
subfinder -d $DOMAIN -silent -o subdomains.txt

# Phase 2: Active verification
cat subdomains.txt | httpx -silent -o live-hosts.txt

# Phase 3: Path discovery on live hosts (using ffuf, not httpx)
cat live-hosts.txt | while read url; do
  ffuf -w $WORDLIST_DIR/Discovery/Web-Content/common.txt \
       -u "${url}/FUZZ" \
       -ac -mc 200,403 \
       -o "${url//[^a-zA-Z0-9]/_}-paths.json" -of json
done

# Phase 4: Technology-specific testing
# WordPress
cat live-hosts.txt | httpx -path /wp-admin,/wp-json -mc 200,403 -o wp-sites.txt

# APIs
cat live-hosts.txt | httpx -path /api,/graphql,/swagger.json -mc 200,401 -o api-sites.txt

# Admin
cat live-hosts.txt | httpx -path /admin,/login,/panel -mc 200,301,302,403 -title -o admin-sites.txt
```

---

## Notes for Claude Code

1. **Wordlist Selection:**
   - Use `common.txt` for quick initial scans
   - Use `raft-medium-directories.txt` for standard comprehensive scans
   - Use `subdomains-top1million-5000.txt` for subdomain validation

2. **Path Discovery Limitation:**
   - httpx `-path` flag accepts comma-separated paths, not wordlist files
   - For wordlist-based path fuzzing, integrate with ffuf after initial recon
   - httpx is best for probing known/specific paths

3. **Custom Wordlist Generation:**
   - Generate organization-specific patterns
   - Create technology-specific lists based on findings
   - Combine multiple sources for comprehensive coverage

4. **Performance Considerations:**
   - Larger wordlists = longer scan times
   - Use appropriate wordlist size for scope
   - Consider rate limiting with large wordlists

5. **Best Practice:**
   - Always keep SecLists updated: `cd ~/wordlists/SecLists && git pull`
   - Organize wordlists by category (subdomains, paths, api, etc.)
   - Create custom lists based on target technology stack

6. **Integration Points:**
   - Use httpx for initial path probing with small lists
   - Feed results to ffuf for comprehensive fuzzing
   - Generate technology-specific wordlists based on httpx tech detection

---

## Additional Resources

### Wordlist Repositories

- **SecLists:** https://github.com/danielmiessler/SecLists
- **Assetnote:** https://wordlists.assetnote.io/
- **FuzzDB:** https://github.com/fuzzdb-project/fuzzdb
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **Bo0oM Fuzz:** https://github.com/Bo0oM/fuzz.txt

### Wordlist Generators

- **CeWL:** Custom wordlist from website
- **crunch:** Generate custom wordlists with patterns
- **kwprocessor:** Keyboard walk wordlist generator
- **mentalist:** GUI wordlist generator

---

**End of Wordlists Guide**