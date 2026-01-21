#!/usr/bin/env python3
"""
Recon Helper - Enhanced utility script for subfinder and httpx reconnaissance
Optimized for Claude Code agent with better output and integration
Integrated with CONFIG_TEMPLATES.md, WORKFLOWS.md, and WORDLISTS.md resources
"""

import json
import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime
import re
from pathlib import Path
import os


class Colors:
    """ANSI color codes for better output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''


class ConfigValidator:
    """Validate subfinder and httpx configurations"""
    
    @staticmethod
    def validate():
        """Check if configurations are properly set up"""
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.HEADER + "CONFIGURATION VALIDATION" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        
        issues = []
        recommendations = []
        
        # Check subfinder config
        subfinder_config = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
        if subfinder_config.exists():
            with open(subfinder_config, 'r') as f:
                content = f.read()
                # Count non-comment, non-empty lines with colons (API keys)
                api_keys = len([line for line in content.split('\n') 
                               if ':' in line and not line.strip().startswith('#') 
                               and 'YOUR_' not in line and line.strip()])
            
            if api_keys > 0:
                print(f"\n{Colors.OKGREEN}[✓] Subfinder Config:{Colors.ENDC} Found at {subfinder_config}")
                print(f"    └─ {api_keys} API source(s) configured")
            else:
                print(f"\n{Colors.WARNING}[!] Subfinder Config:{Colors.ENDC} Found but no API keys configured")
                recommendations.append("Add API keys to subfinder config for better results")
                recommendations.append("See CONFIG_TEMPLATES.md - Template 2 (Basic Configuration)")
        else:
            print(f"\n{Colors.FAIL}[✗] Subfinder Config:{Colors.ENDC} Not found")
            issues.append("Subfinder config not found at ~/.config/subfinder/provider-config.yaml")
            recommendations.append("Create config: See CONFIG_TEMPLATES.md - Template 12 (Quick Setup Script)")
        
        # Check httpx config
        httpx_config = Path.home() / ".config" / "httpx" / "config.yaml"
        if httpx_config.exists():
            print(f"\n{Colors.OKGREEN}[✓] Httpx Config:{Colors.ENDC} Found at {httpx_config}")
        else:
            print(f"\n{Colors.WARNING}[!] Httpx Config:{Colors.ENDC} Not found (optional)")
            recommendations.append("Consider creating httpx config for consistent settings")
            recommendations.append("See CONFIG_TEMPLATES.md - Templates 5-8")
        
        # Check for wordlists
        wordlist_paths = [
            Path.home() / "wordlists" / "SecLists",
            Path.home() / "wordlists",
            Path("/usr/share/wordlists/SecLists"),
        ]
        
        seclists_found = False
        for path in wordlist_paths:
            if path.exists():
                print(f"\n{Colors.OKGREEN}[✓] Wordlists:{Colors.ENDC} Found at {path}")
                seclists_found = True
                break
        
        if not seclists_found:
            print(f"\n{Colors.WARNING}[!] Wordlists:{Colors.ENDC} SecLists not found in common locations")
            recommendations.append("Download SecLists for path discovery")
            recommendations.append("See WORDLISTS.md - 'Essential Downloads' section")
        
        # Check for tools
        tools = {
            'subfinder': 'Subdomain enumeration',
            'httpx': 'HTTP probing',
            'ffuf': 'Content discovery (optional)',
            'nuclei': 'Vulnerability scanning (optional)',
        }
        
        print(f"\n{Colors.OKCYAN}Tool Availability:{Colors.ENDC}")
        for tool, description in tools.items():
            if os.system(f"which {tool} >/dev/null 2>&1") == 0:
                print(f"  {Colors.OKGREEN}[✓]{Colors.ENDC} {tool:15} - {description}")
            else:
                print(f"  {Colors.FAIL}[✗]{Colors.ENDC} {tool:15} - {description}")
                if tool in ['subfinder', 'httpx']:
                    issues.append(f"{tool} not found in PATH")
        
        # Summary
        if issues:
            print(f"\n{Colors.FAIL}Issues Found:{Colors.ENDC}")
            for issue in issues:
                print(f"  • {issue}")
        
        if recommendations:
            print(f"\n{Colors.WARNING}Recommendations:{Colors.ENDC}")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        
        if not issues and not recommendations:
            print(f"\n{Colors.OKGREEN}[✓] All checks passed! Your setup is ready.{Colors.ENDC}")
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)


class RecommendationEngine:
    """Suggest next steps based on reconnaissance findings"""
    
    def __init__(self, json_file):
        self.json_file = json_file
        self.data = self.load_json()
        self.recommendations = []
    
    def load_json(self):
        """Load JSON results"""
        results = []
        try:
            with open(self.json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            return results
        except FileNotFoundError:
            print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} File not found: {self.json_file}")
            sys.exit(1)
    
    def analyze_and_recommend(self):
        """Analyze results and provide recommendations"""
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.HEADER + "RECOMMENDATIONS & NEXT STEPS" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        
        # Analyze technologies
        tech_counts = self._analyze_technologies()
        
        # Analyze status codes
        status_info = self._analyze_status_codes()
        
        # Analyze interesting findings
        interesting = self._find_interesting()
        
        # Generate recommendations
        print(f"\n{Colors.OKCYAN}{Colors.BOLD}Based on your reconnaissance findings:{Colors.ENDC}\n")
        
        rec_num = 1
        
        # WordPress recommendations
        if tech_counts.get('wordpress', 0) > 0:
            print(f"{rec_num}. {Colors.OKGREEN}WordPress Sites Detected ({tech_counts['wordpress']} sites){Colors.ENDC}")
            print(f"   └─ Next: Use WPScan for vulnerability scanning")
            print(f"   └─ Workflow: See WORKFLOWS.md - Workflow 7 (WordPress-Focused)")
            print(f"   └─ Wordlist: See WORDLISTS.md - WordPress Paths section")
            print(f"   └─ Command: python3 recon_helper.py extract {self.json_file} --tech wordpress -o wp-sites.txt")
            print()
            rec_num += 1
        
        # API recommendations
        if tech_counts.get('api', 0) > 0 or interesting.get('api_endpoints', 0) > 0:
            count = max(tech_counts.get('api', 0), interesting.get('api_endpoints', 0))
            print(f"{rec_num}. {Colors.OKGREEN}API Endpoints Found ({count} endpoints){Colors.ENDC}")
            print(f"   └─ Next: Test API endpoints for vulnerabilities")
            print(f"   └─ Workflow: See WORKFLOWS.md - Workflow 5 (API-Focused Reconnaissance)")
            print(f"   └─ Wordlist: See WORDLISTS.md - API-Specific Paths section")
            print(f"   └─ Probe: httpx -l urls.txt -path /swagger.json,/openapi.json,/graphql")
            print()
            rec_num += 1
        
        # Admin panel recommendations
        if interesting.get('admin_panels', 0) > 0:
            print(f"{rec_num}. {Colors.WARNING}Admin Panels Discovered ({interesting['admin_panels']} panels){Colors.ENDC}")
            print(f"   └─ Next: Screenshot and document admin interfaces")
            print(f"   └─ Fuzzing: Use ffuf with admin wordlists")
            print(f"   └─ Wordlist: See WORDLISTS.md - Admin Panel Paths section")
            print(f"   └─ Command: cat admin-panels.txt | httpx -screenshot")
            print()
            rec_num += 1
        
        # Vulnerable versions
        vulnerable = self._check_vulnerable_versions()
        if vulnerable > 0:
            print(f"{rec_num}. {Colors.FAIL}Potentially Vulnerable Versions ({vulnerable} found){Colors.ENDC}")
            print(f"   └─ Next: Run vulnerability scanners (nuclei, nmap scripts)")
            print(f"   └─ Workflow: See WORKFLOWS.md - Workflow 6 (Integration with Other Tools)")
            print(f"   └─ Command: cat urls.txt | nuclei -t cves/ -severity critical,high")
            print()
            rec_num += 1
        
        # 401/403 findings
        if status_info.get('401', 0) > 0 or status_info.get('403', 0) > 0:
            auth_count = status_info.get('401', 0) + status_info.get('403', 0)
            print(f"{rec_num}. {Colors.WARNING}Authentication/Authorization Issues ({auth_count} responses){Colors.ENDC}")
            print(f"   └─ 401 responses indicate authentication required")
            print(f"   └─ 403 responses may indicate valid paths with access restrictions")
            print(f"   └─ Next: Test for authentication bypass or use valid credentials")
            print()
            rec_num += 1
        
        # Large scope recommendations
        if len(self.data) > 100:
            print(f"{rec_num}. {Colors.OKCYAN}Large Scope Detected ({len(self.data)} hosts){Colors.ENDC}")
            print(f"   └─ Workflow: See WORKFLOWS.md - Workflow 8 (Large-Scale Enumeration)")
            print(f"   └─ Config: Use aggressive httpx config for speed")
            print(f"   └─ Config: See CONFIG_TEMPLATES.md - Template 7 (Aggressive)")
            print()
            rec_num += 1
        
        # Generate target lists
        print(f"{rec_num}. {Colors.OKBLUE}Generate Organized Target Lists{Colors.ENDC}")
        print(f"   └─ Command: python3 recon_helper.py generate-targets {self.json_file} -o targets/")
        print(f"   └─ This creates organized lists for WordPress, APIs, admin panels, etc.")
        print()
        rec_num += 1
        
        # Integration suggestions
        print(f"{rec_num}. {Colors.OKBLUE}Integration with Other Tools{Colors.ENDC}")
        print(f"   └─ Nuclei: cat urls.txt | nuclei -t cves/ -severity critical,high")
        print(f"   └─ FFuf: cat urls.txt | xargs -I{{}} ffuf -w wordlist.txt -u {{}}/FUZZ -ac")
        print(f"   └─ Naabu: cat subdomains.txt | naabu -top-ports 1000")
        print(f"   └─ See WORKFLOWS.md - Workflow 6 for complete integration examples")
        print()
        rec_num += 1
        
        # Monitoring
        print(f"{rec_num}. {Colors.OKBLUE}Setup Continuous Monitoring{Colors.ENDC}")
        print(f"   └─ Create baseline: cp subdomains.txt baseline.txt")
        print(f"   └─ Monitor changes: python3 recon_helper.py compare-subs baseline.txt current.txt")
        print(f"   └─ See WORKFLOWS.md - Workflow 4 (Continuous Monitoring)")
        print()
        
        print(Colors.BOLD + "="*70 + Colors.ENDC)
    
    def _analyze_technologies(self):
        """Count technology occurrences"""
        tech_counts = defaultdict(int)
        
        for result in self.data:
            if 'technologies' in result:
                for tech in result['technologies']:
                    tech_lower = tech.lower()
                    if 'wordpress' in tech_lower:
                        tech_counts['wordpress'] += 1
                    if 'api' in tech_lower or 'rest' in tech_lower or 'graphql' in tech_lower:
                        tech_counts['api'] += 1
                    if 'php' in tech_lower:
                        tech_counts['php'] += 1
                    if 'joomla' in tech_lower:
                        tech_counts['joomla'] += 1
                    if 'drupal' in tech_lower:
                        tech_counts['drupal'] += 1
        
        return dict(tech_counts)
    
    def _analyze_status_codes(self):
        """Analyze status code distribution"""
        status_counts = Counter()
        for result in self.data:
            if 'status_code' in result:
                status_counts[result['status_code']] += 1
        return dict(status_counts)
    
    def _find_interesting(self):
        """Find interesting patterns"""
        interesting = {
            'admin_panels': 0,
            'api_endpoints': 0,
            'login_pages': 0,
        }
        
        admin_keywords = ['admin', 'panel', 'dashboard']
        api_keywords = ['api', 'graphql', 'swagger', 'rest']
        login_keywords = ['login', 'signin', 'auth']
        
        for result in self.data:
            url = result.get('url', '').lower()
            title = result.get('title', '').lower()
            
            if any(kw in url or kw in title for kw in admin_keywords):
                interesting['admin_panels'] += 1
            if any(kw in url or kw in title for kw in api_keywords):
                interesting['api_endpoints'] += 1
            if any(kw in url or kw in title for kw in login_keywords):
                interesting['login_pages'] += 1
        
        return interesting
    
    def _check_vulnerable_versions(self):
        """Check for vulnerable versions"""
        vulnerable_patterns = {
            'PHP': r'PHP:[0-5]\.|PHP:7\.[0-3]',
            'WordPress': r'WordPress:[0-4]\.|WordPress:5\.[0-8]',
            'jQuery': r'jQuery:[0-2]\.',
        }
        
        count = 0
        for result in self.data:
            if 'technologies' in result:
                for tech in result['technologies']:
                    for software, pattern in vulnerable_patterns.items():
                        if re.search(pattern, tech, re.IGNORECASE):
                            count += 1
                            break
        
        return count


class ReconAnalyzer:
    """Analyze reconnaissance results from httpx JSON output"""
    
    def __init__(self, json_file, quiet=False):
        self.json_file = json_file
        self.quiet = quiet
        self.data = self.load_json()
        self.summary_data = {}
        
    def log(self, message, level="info"):
        """Log messages with appropriate formatting"""
        if self.quiet and level != "error":
            return
        
        prefix = {
            "info": f"{Colors.OKBLUE}[*]{Colors.ENDC}",
            "success": f"{Colors.OKGREEN}[+]{Colors.ENDC}",
            "warning": f"{Colors.WARNING}[!]{Colors.ENDC}",
            "error": f"{Colors.FAIL}[ERROR]{Colors.ENDC}",
        }.get(level, "[*]")
        
        print(f"{prefix} {message}")
    
    def load_json(self):
        """Load JSON results from httpx with better error handling"""
        results = []
        line_count = 0
        error_count = 0
        
        try:
            if not Path(self.json_file).exists():
                self.log(f"File not found: {self.json_file}", "error")
                self.log("Make sure the file path is correct and the file exists.", "error")
                sys.exit(1)
            
            if Path(self.json_file).stat().st_size == 0:
                self.log(f"File is empty: {self.json_file}", "error")
                self.log("Run httpx with -json flag to generate proper output.", "error")
                sys.exit(1)
            
            with open(self.json_file, 'r') as f:
                for line in f:
                    line_count += 1
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            error_count += 1
                            if error_count <= 3:  # Only show first 3 errors
                                self.log(f"JSON parse error on line {line_count}: {e}", "warning")
            
            if not results:
                self.log("No valid JSON entries found in file", "error")
                self.log("Ensure httpx was run with -json flag: httpx -l urls.txt -json -o results.json", "error")
                sys.exit(1)
            
            self.log(f"Loaded {len(results)} results from {self.json_file}", "success")
            if error_count > 0:
                self.log(f"Skipped {error_count} malformed entries", "warning")
            
            return results
            
        except FileNotFoundError:
            self.log(f"File not found: {self.json_file}", "error")
            self.log("Check the file path and try again.", "error")
            sys.exit(1)
        except PermissionError:
            self.log(f"Permission denied: {self.json_file}", "error")
            self.log("Check file permissions and try again.", "error")
            sys.exit(1)
        except Exception as e:
            self.log(f"Unexpected error loading file: {e}", "error")
            sys.exit(1)
    
    def get_summary(self):
        """Get quick summary statistics"""
        summary = {
            "total_hosts": len(self.data),
            "status_codes": {},
            "top_technologies": [],
            "interesting_findings": 0,
            "vulnerable_versions": 0,
        }
        
        # Status code breakdown
        status_codes = Counter(r.get('status_code') for r in self.data if 'status_code' in r)
        summary["status_codes"] = {
            "2xx": sum(v for k, v in status_codes.items() if 200 <= k < 300),
            "3xx": sum(v for k, v in status_codes.items() if 300 <= k < 400),
            "4xx": sum(v for k, v in status_codes.items() if 400 <= k < 500),
            "5xx": sum(v for k, v in status_codes.items() if 500 <= k < 600),
        }
        
        # Top technologies
        all_techs = []
        for result in self.data:
            if 'technologies' in result:
                all_techs.extend(result['technologies'])
        tech_counts = Counter(all_techs)
        summary["top_technologies"] = [{"name": tech, "count": count} for tech, count in tech_counts.most_common(5)]
        
        # Interesting findings
        interesting_keywords = ['admin', 'login', 'dashboard', 'panel', 'api']
        for result in self.data:
            title = result.get('title', '').lower()
            if any(kw in title for kw in interesting_keywords):
                summary["interesting_findings"] += 1
        
        # Vulnerable versions
        vulnerable_patterns = {
            'PHP': r'PHP:[0-5]\.|PHP:7\.[0-3]',
            'WordPress': r'WordPress:[0-4]\.|WordPress:5\.[0-8]',
            'jQuery': r'jQuery:[0-2]\.',
        }
        for result in self.data:
            if 'technologies' in result:
                for tech in result['technologies']:
                    for software, pattern in vulnerable_patterns.items():
                        if re.search(pattern, tech, re.IGNORECASE):
                            summary["vulnerable_versions"] += 1
                            break
        
        self.summary_data = summary
        return summary
    
    def print_summary(self, json_output=False):
        """Print quick summary for fast triage"""
        summary = self.get_summary()
        
        if json_output:
            print(json.dumps(summary, indent=2))
            return
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.HEADER + "RECONNAISSANCE SUMMARY" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        
        print(f"\n{Colors.OKGREEN}Total Hosts Discovered:{Colors.ENDC} {summary['total_hosts']}")
        
        print(f"\n{Colors.OKCYAN}Status Code Distribution:{Colors.ENDC}")
        for code_range, count in summary['status_codes'].items():
            if count > 0:
                color = Colors.OKGREEN if code_range == "2xx" else Colors.WARNING if code_range in ["3xx", "4xx"] else Colors.FAIL
                print(f"  {color}{code_range}:{Colors.ENDC} {count}")
        
        if summary['top_technologies']:
            print(f"\n{Colors.OKCYAN}Top 5 Technologies:{Colors.ENDC}")
            for tech in summary['top_technologies']:
                print(f"  • {tech['name']} ({tech['count']})")
        
        if summary['interesting_findings'] > 0:
            print(f"\n{Colors.WARNING}Interesting Findings:{Colors.ENDC} {summary['interesting_findings']} (admin/login/dashboard/api)")
        
        if summary['vulnerable_versions'] > 0:
            print(f"{Colors.FAIL}Potentially Vulnerable Versions:{Colors.ENDC} {summary['vulnerable_versions']}")
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
    
    def analyze_technologies(self, json_output=False):
        """Analyze and categorize technologies"""
        all_techs = []
        for result in self.data:
            if 'technologies' in result:
                all_techs.extend(result['technologies'])
        
        tech_counts = Counter(all_techs)
        
        # Categorize technologies
        categories = {
            'Web Servers': ['nginx', 'apache', 'iis', 'tomcat', 'caddy', 'lighttpd'],
            'Programming Languages': ['php', 'python', 'ruby', 'node', 'java', 'asp', 'perl', 'go'],
            'CMS': ['wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'wix'],
            'Frameworks': ['laravel', 'django', 'rails', 'express', 'react', 'angular', 'vue', 'next'],
            'CDN': ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'incapsula'],
            'JavaScript Libraries': ['jquery', 'bootstrap', 'moment', 'lodash', 'axios'],
            'Analytics': ['google analytics', 'matomo', 'hotjar', 'mixpanel'],
            'Security': ['waf', 'recaptcha', 'hcaptcha', 'firewall'],
        }
        
        categorized = {}
        for category, keywords in categories.items():
            category_techs = []
            for tech, count in tech_counts.items():
                if any(keyword.lower() in tech.lower() for keyword in keywords):
                    category_techs.append({"technology": tech, "count": count})
            if category_techs:
                categorized[category] = sorted(category_techs, key=lambda x: x['count'], reverse=True)
        
        if json_output:
            output = {
                "total_unique_technologies": len(tech_counts),
                "categories": categorized,
                "top_10_overall": [{"technology": tech, "count": count} for tech, count in tech_counts.most_common(10)]
            }
            print(json.dumps(output, indent=2))
            return
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.HEADER + "TECHNOLOGY ANALYSIS" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        
        for category, techs in categorized.items():
            print(f"\n{Colors.OKCYAN}{Colors.BOLD}{category}:{Colors.ENDC}")
            for tech_info in techs[:10]:
                print(f"  [{Colors.OKGREEN}{tech_info['count']:3d}{Colors.ENDC}] {tech_info['technology']}")
        
        print(f"\n{Colors.OKCYAN}{Colors.BOLD}Top 10 Technologies Overall:{Colors.ENDC}")
        for tech, count in tech_counts.most_common(10):
            print(f"  [{Colors.OKGREEN}{count:3d}{Colors.ENDC}] {tech}")
        
        return tech_counts
    
    def analyze_status_codes(self, json_output=False):
        """Analyze HTTP status codes"""
        status_codes = Counter()
        status_urls = defaultdict(list)
        
        for result in self.data:
            if 'status_code' in result:
                code = result['status_code']
                status_codes[code] += 1
                status_urls[code].append(result.get('url', 'unknown'))
        
        if json_output:
            output = {
                "distribution": dict(status_codes),
                "interesting_codes": {}
            }
            interesting = [401, 403, 500, 502, 503]
            for code in interesting:
                if code in status_codes and status_codes[code] > 0:
                    output["interesting_codes"][str(code)] = {
                        "count": status_codes[code],
                        "urls": status_urls[code][:10]
                    }
            print(json.dumps(output, indent=2))
            return
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.HEADER + "STATUS CODE ANALYSIS" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        
        categories = {
            '2xx (Success)': ([200, 201, 202, 204], Colors.OKGREEN),
            '3xx (Redirect)': ([301, 302, 303, 307, 308], Colors.WARNING),
            '4xx (Client Error)': ([400, 401, 403, 404, 405], Colors.WARNING),
            '5xx (Server Error)': ([500, 501, 502, 503, 504], Colors.FAIL),
        }
        
        for category, (codes, color) in categories.items():
            category_counts = sum(status_codes[code] for code in codes if code in status_codes)
            if category_counts > 0:
                print(f"\n{Colors.BOLD}{category}:{Colors.ENDC} {category_counts} responses")
                for code in codes:
                    if code in status_codes:
                        print(f"  {color}[{status_codes[code]:3d}]{Colors.ENDC} {code}")
        
        interesting = [401, 403, 500, 502, 503]
        print(f"\n{Colors.BOLD}{Colors.WARNING}Interesting Status Codes:{Colors.ENDC}")
        for code in interesting:
            if code in status_codes and status_codes[code] > 0:
                print(f"\n  {Colors.WARNING}{code} - {status_codes[code]} occurrences:{Colors.ENDC}")
                for url in status_urls[code][:5]:
                    print(f"    • {url}")
                if len(status_urls[code]) > 5:
                    print(f"    {Colors.OKCYAN}... and {len(status_urls[code]) - 5} more{Colors.ENDC}")
    
    def find_anomalies(self, json_output=False):
        """Find interesting anomalies in responses"""
        content_lengths = [r.get('content_length', 0) for r in self.data if 'content_length' in r]
        unusual_sizes = []
        interesting_titles = []
        
        if content_lengths:
            avg_length = sum(content_lengths) / len(content_lengths)
            
            for result in self.data:
                length = result.get('content_length', 0)
                if length > avg_length * 2 or (length < avg_length * 0.5 and length > 0):
                    unusual_sizes.append({
                        "url": result.get('url', 'unknown'),
                        "content_length": length,
                        "status_code": result.get('status_code')
                    })
        
        interesting_keywords = ['admin', 'login', 'dashboard', 'panel', 'api', 'dev', 'test', 'staging', 'backup']
        for result in self.data:
            title = result.get('title', '').lower()
            if any(keyword in title for keyword in interesting_keywords):
                interesting_titles.append({
                    "url": result.get('url'),
                    "title": result.get('title'),
                    "status_code": result.get('status_code')
                })
        
        domain_servers = defaultdict(set)
        for result in self.data:
            url = result.get('url', '')
            server = result.get('webserver', 'unknown')
            if url and server != 'unknown':
                domain = url.split('/')[2] if len(url.split('/')) > 2 else url
                base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
                domain_servers[base_domain].add(server)
        
        multiple_servers = {domain: list(servers) for domain, servers in domain_servers.items() if len(servers) > 1}
        
        if json_output:
            output = {
                "unusual_content_lengths": unusual_sizes[:20],
                "interesting_titles": interesting_titles[:20],
                "domains_with_multiple_servers": multiple_servers
            }
            print(json.dumps(output, indent=2))
            return
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.HEADER + "ANOMALY DETECTION" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        
        if unusual_sizes:
            avg_length = sum(content_lengths) / len(content_lengths)
            print(f"\n{Colors.OKCYAN}Unusual Content Lengths (avg: {int(avg_length)} bytes):{Colors.ENDC}")
            for item in unusual_sizes[:10]:
                print(f"  [{Colors.WARNING}{item['content_length']:6d} bytes{Colors.ENDC}] [{item['status_code']}] {item['url']}")
        
        if interesting_titles:
            print(f"\n{Colors.WARNING}Interesting Page Titles:{Colors.ENDC}")
            for item in interesting_titles[:15]:
                print(f"  [{item['status_code']}] {Colors.BOLD}{item['title']}{Colors.ENDC}")
                print(f"        {item['url']}")
        
        if multiple_servers:
            print(f"\n{Colors.OKCYAN}Domains with Multiple Web Servers:{Colors.ENDC}")
            for domain, servers in list(multiple_servers.items())[:10]:
                print(f"  {domain}: {', '.join(servers)}")
    
    def find_vulnerable_versions(self, json_output=False):
        """Identify potentially vulnerable software versions"""
        vulnerable_patterns = {
            'PHP': r'PHP:[0-5]\.|PHP:7\.[0-3]',
            'WordPress': r'WordPress:[0-4]\.|WordPress:5\.[0-8]',
            'jQuery': r'jQuery:[0-2]\.',
            'Apache': r'Apache:2\.[0-2]',
            'nginx': r'nginx:1\.[0-9]\.',
            'OpenSSL': r'OpenSSL:1\.0',
        }
        
        found_vulnerable = []
        
        for result in self.data:
            if 'technologies' in result:
                for tech in result['technologies']:
                    for software, pattern in vulnerable_patterns.items():
                        if re.search(pattern, tech, re.IGNORECASE):
                            found_vulnerable.append({
                                "url": result.get('url', 'unknown'),
                                "technology": tech,
                                "software": software
                            })
        
        if json_output:
            output = {
                "total_vulnerable": len(found_vulnerable),
                "findings": found_vulnerable
            }
            print(json.dumps(output, indent=2))
            return
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.FAIL + "POTENTIALLY VULNERABLE VERSIONS" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        
        if found_vulnerable:
            print(f"\n{Colors.FAIL}Found {len(found_vulnerable)} potentially vulnerable versions:{Colors.ENDC}\n")
            for item in found_vulnerable:
                print(f"  {Colors.WARNING}[!]{Colors.ENDC} {item['url']}")
                print(f"      └─ {Colors.FAIL}{item['technology']}{Colors.ENDC}")
            
            # Add recommendations
            print(f"\n{Colors.OKCYAN}Recommended Actions:{Colors.ENDC}")
            print(f"  1. Run nuclei for CVE detection: cat urls.txt | nuclei -t cves/")
            print(f"  2. Use stealth scanning if needed: See CONFIG_TEMPLATES.md - Template 6")
            print(f"  3. Integration workflow: See WORKFLOWS.md - Workflow 6")
        else:
            print(f"\n  {Colors.OKGREEN}No obviously vulnerable versions detected (this is good!){Colors.ENDC}")
        
        return found_vulnerable
    
    def extract_by_technology(self, tech_name, output_file=None, json_output=False):
        """Extract URLs using specific technology"""
        found = []
        for result in self.data:
            if 'technologies' in result:
                for tech in result['technologies']:
                    if tech_name.lower() in tech.lower():
                        found.append({
                            'url': result.get('url'),
                            'tech': tech,
                            'status': result.get('status_code'),
                            'title': result.get('title', 'N/A')
                        })
                        break
        
        if json_output:
            output = {
                "technology": tech_name,
                "count": len(found),
                "hosts": found
            }
            print(json.dumps(output, indent=2))
            return found
        
        print(f"\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(f"{Colors.BOLD}{Colors.HEADER}HOSTS USING: {tech_name.upper()}{Colors.ENDC}")
        print(Colors.BOLD + "="*70 + Colors.ENDC + "\n")
        
        if found:
            self.log(f"Found {len(found)} hosts using {tech_name}", "success")
            print()
            for item in found:
                print(f"[{Colors.OKGREEN}{item['status']}{Colors.ENDC}] {item['url']}")
                print(f"  └─ {Colors.OKCYAN}{item['tech']}{Colors.ENDC} | {item['title']}")
            
            if output_file:
                with open(output_file, 'w') as f:
                    for item in found:
                        f.write(f"{item['url']}\n")
                self.log(f"Saved {len(found)} URLs to: {output_file}", "success")
        else:
            self.log(f"No hosts found using {tech_name}", "warning")
        
        return found
    
    def generate_report(self, output_file):
        """Generate comprehensive HTML report"""
        self.log(f"Generating HTML report: {output_file}", "info")
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; margin-top: 30px; }}
        .stat {{ display: inline-block; margin: 10px 20px; padding: 15px; background: #4CAF50; color: white; border-radius: 5px; min-width: 150px; text-align: center; }}
        .stat-label {{ font-size: 12px; opacity: 0.9; }}
        .stat-value {{ font-size: 24px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .tech-badge {{ display: inline-block; padding: 5px 10px; margin: 3px; background: #2196F3; color: white; border-radius: 3px; font-size: 12px; }}
        .status-200 {{ color: #4CAF50; font-weight: bold; }}
        .status-301, .status-302 {{ color: #FF9800; font-weight: bold; }}
        .status-401, .status-403 {{ color: #F44336; font-weight: bold; }}
        .status-500 {{ color: #9C27B0; font-weight: bold; }}
        .warning {{ background: #FFF3CD; border-left: 4px solid #FFC107; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Reconnaissance Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Source:</strong> {self.json_file}</p>
        
        <h2>📊 Summary Statistics</h2>
        <div class="stat">
            <div class="stat-label">Total Hosts</div>
            <div class="stat-value">{len(self.data)}</div>
        </div>
"""
        
        status_codes = Counter(r.get('status_code') for r in self.data if 'status_code' in r)
        html += f"""
        <div class="stat" style="background: #4CAF50;">
            <div class="stat-label">2xx Success</div>
            <div class="stat-value">{sum(v for k, v in status_codes.items() if 200 <= k < 300)}</div>
        </div>
        <div class="stat" style="background: #FF9800;">
            <div class="stat-label">3xx Redirects</div>
            <div class="stat-value">{sum(v for k, v in status_codes.items() if 300 <= k < 400)}</div>
        </div>
        <div class="stat" style="background: #F44336;">
            <div class="stat-label">4xx Errors</div>
            <div class="stat-value">{sum(v for k, v in status_codes.items() if 400 <= k < 500)}</div>
        </div>
        
        <h2>🛠️ Technology Stack</h2>
"""
        
        all_techs = []
        for result in self.data:
            if 'technologies' in result:
                all_techs.extend(result['technologies'])
        tech_counts = Counter(all_techs)
        
        html += "<table><tr><th>Technology</th><th>Count</th></tr>"
        for tech, count in tech_counts.most_common(20):
            html += f"<tr><td>{tech}</td><td>{count}</td></tr>"
        html += "</table>"
        
        html += "<h2>🎯 Interesting Findings</h2>"
        interesting_keywords = ['admin', 'login', 'dashboard', 'panel', 'api']
        interesting = []
        for result in self.data:
            title = result.get('title', '').lower()
            if any(kw in title for kw in interesting_keywords):
                interesting.append(result)
        
        if interesting:
            html += "<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Technologies</th></tr>"
            for result in interesting[:20]:
                status = result.get('status_code', 'N/A')
                status_class = f"status-{status}" if status != 'N/A' else ""
                techs = result.get('technologies', [])
                tech_badges = ''.join([f'<span class="tech-badge">{t}</span>' for t in techs[:5]])
                html += f"""<tr>
                    <td><a href="{result.get('url', '#')}" target="_blank">{result.get('url', 'N/A')}</a></td>
                    <td class="{status_class}">{status}</td>
                    <td>{result.get('title', 'N/A')}</td>
                    <td>{tech_badges}</td>
                </tr>"""
            html += "</table>"
        
        html += "<h2>⚠️ Potentially Vulnerable Versions</h2>"
        vulnerable_patterns = {
            'PHP': r'PHP:[0-5]\.|PHP:7\.[0-3]',
            'WordPress': r'WordPress:[0-4]\.|WordPress:5\.[0-8]',
            'jQuery': r'jQuery:[0-2]\.',
        }
        
        vulnerable_found = []
        for result in self.data:
            if 'technologies' in result:
                for tech in result['technologies']:
                    for software, pattern in vulnerable_patterns.items():
                        if re.search(pattern, tech, re.IGNORECASE):
                            vulnerable_found.append((result.get('url'), tech))
        
        if vulnerable_found:
            html += '<div class="warning">Found potentially vulnerable versions:</div>'
            html += "<table><tr><th>URL</th><th>Vulnerable Technology</th></tr>"
            for url, tech in vulnerable_found[:15]:
                html += f"<tr><td>{url}</td><td>{tech}</td></tr>"
            html += "</table>"
        else:
            html += "<p>No obviously vulnerable versions detected.</p>"
        
        html += """
    </div>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        self.log(f"Report saved to: {output_file}", "success")


class TargetListGenerator:
    """Generate organized target lists for further testing"""
    
    def __init__(self, json_file, quiet=False):
        self.json_file = json_file
        self.quiet = quiet
        self.data = self.load_json()
    
    def log(self, message, level="info"):
        """Log messages"""
        if self.quiet and level != "error":
            return
        
        prefix = {
            "info": f"{Colors.OKBLUE}[*]{Colors.ENDC}",
            "success": f"{Colors.OKGREEN}[+]{Colors.ENDC}",
            "warning": f"{Colors.WARNING}[!]{Colors.ENDC}",
            "error": f"{Colors.FAIL}[ERROR]{Colors.ENDC}",
        }.get(level, "[*]")
        
        print(f"{prefix} {message}")
    
    def load_json(self):
        """Load JSON results"""
        results = []
        try:
            with open(self.json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            
            if not results:
                self.log("No valid JSON entries found", "error")
                sys.exit(1)
            
            return results
        except FileNotFoundError:
            self.log(f"File not found: {self.json_file}", "error")
            sys.exit(1)
    
    def generate_by_technology(self, output_dir, json_output=False):
        """Generate target lists organized by technology"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        self.log(f"Generating technology-based target lists in: {output_dir}/", "info")
        
        tech_filters = {
            'wordpress': lambda t: 'wordpress' in t.lower(),
            'joomla': lambda t: 'joomla' in t.lower(),
            'drupal': lambda t: 'drupal' in t.lower(),
            'php': lambda t: 'php' in t.lower(),
            'asp': lambda t: 'asp' in t.lower() or 'aspnet' in t.lower(),
            'nodejs': lambda t: 'node' in t.lower() or 'express' in t.lower(),
            'python': lambda t: 'python' in t.lower() or 'django' in t.lower(),
            'api': lambda t: 'api' in t.lower() or 'rest' in t.lower() or 'graphql' in t.lower(),
        }
        
        counts = {}
        for name, filter_func in tech_filters.items():
            urls = set()
            for result in self.data:
                if 'technologies' in result:
                    if any(filter_func(tech) for tech in result['technologies']):
                        urls.add(result.get('url'))
            
            if urls:
                filename = output_path / f"{name}-targets.txt"
                with open(filename, 'w') as f:
                    for url in sorted(urls):
                        f.write(f"{url}\n")
                counts[name] = len(urls)
                if not json_output:
                    print(f"  [{Colors.OKGREEN}{len(urls):3d}{Colors.ENDC}] {filename}")
        
        if json_output:
            print(json.dumps(counts, indent=2))
        
        return counts
    
    def generate_by_status(self, output_dir, json_output=False):
        """Generate target lists by HTTP status code"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        self.log(f"Generating status code based target lists in: {output_dir}/", "info")
        
        status_groups = {
            '200-success': lambda s: s == 200,
            '401-unauthorized': lambda s: s == 401,
            '403-forbidden': lambda s: s == 403,
            '500-errors': lambda s: 500 <= s < 600,
        }
        
        counts = {}
        for name, filter_func in status_groups.items():
            urls = []
            for result in self.data:
                status = result.get('status_code')
                if status and filter_func(status):
                    urls.append(result.get('url'))
            
            if urls:
                filename = output_path / f"status-{name}.txt"
                with open(filename, 'w') as f:
                    for url in urls:
                        f.write(f"{url}\n")
                counts[name] = len(urls)
                if not json_output:
                    print(f"  [{Colors.OKGREEN}{len(urls):3d}{Colors.ENDC}] {filename}")
        
        if json_output:
            print(json.dumps(counts, indent=2))
        
        return counts
    
    def generate_by_keywords(self, output_dir, json_output=False):
        """Generate target lists based on interesting keywords"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        self.log(f"Generating keyword-based target lists in: {output_dir}/", "info")
        
        keyword_groups = {
            'admin-panels': ['admin', 'panel', 'dashboard', 'console'],
            'login-pages': ['login', 'signin', 'auth'],
            'api-endpoints': ['api', 'graphql', 'rest', 'swagger'],
            'dev-staging': ['dev', 'staging', 'test', 'qa', 'uat'],
            'backup-config': ['backup', 'config', 'old', 'bak'],
        }
        
        counts = {}
        for name, keywords in keyword_groups.items():
            urls = set()
            for result in self.data:
                url = result.get('url', '').lower()
                title = result.get('title', '').lower()
                
                if any(kw in url or kw in title for kw in keywords):
                    urls.add(result.get('url'))
            
            if urls:
                filename = output_path / f"{name}.txt"
                with open(filename, 'w') as f:
                    for url in sorted(urls):
                        f.write(f"{url}\n")
                counts[name] = len(urls)
                if not json_output:
                    print(f"  [{Colors.OKGREEN}{len(urls):3d}{Colors.ENDC}] {filename}")
        
        if json_output:
            print(json.dumps(counts, indent=2))
        
        return counts


class SubdomainManager:
    """Manage and compare subdomain lists"""
    
    @staticmethod
    def compare(baseline_file, current_file, output_file=None, json_output=False, quiet=False):
        """Compare two subdomain lists"""
        def log(message, level="info"):
            if quiet and level != "error":
                return
            prefix = {
                "info": f"{Colors.OKBLUE}[*]{Colors.ENDC}",
                "success": f"{Colors.OKGREEN}[+]{Colors.ENDC}",
                "error": f"{Colors.FAIL}[ERROR]{Colors.ENDC}",
            }.get(level, "[*]")
            print(f"{prefix} {message}")
        
        try:
            with open(baseline_file, 'r') as f:
                baseline = set(line.strip() for line in f if line.strip())
            
            with open(current_file, 'r') as f:
                current = set(line.strip() for line in f if line.strip())
        except FileNotFoundError as e:
            log(f"File not found: {e}", "error")
            sys.exit(1)
        
        new_subs = current - baseline
        removed_subs = baseline - current
        
        if json_output:
            output = {
                "baseline_count": len(baseline),
                "current_count": len(current),
                "new_count": len(new_subs),
                "removed_count": len(removed_subs),
                "new_subdomains": sorted(list(new_subs)),
                "removed_subdomains": sorted(list(removed_subs))
            }
            print(json.dumps(output, indent=2))
            return new_subs, removed_subs
        
        print("\n" + Colors.BOLD + "="*70 + Colors.ENDC)
        print(Colors.BOLD + Colors.HEADER + "SUBDOMAIN COMPARISON" + Colors.ENDC)
        print(Colors.BOLD + "="*70 + Colors.ENDC)
        print(f"Baseline: {len(baseline)} subdomains")
        print(f"Current:  {len(current)} subdomains")
        print(f"{Colors.OKGREEN}New:      {len(new_subs)} subdomains{Colors.ENDC}")
        print(f"{Colors.WARNING}Removed:  {len(removed_subs)} subdomains{Colors.ENDC}")
        
        if new_subs:
            print(f"\n{Colors.OKGREEN}New Subdomains:{Colors.ENDC}")
            for sub in sorted(new_subs)[:20]:
                print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} {sub}")
            if len(new_subs) > 20:
                print(f"  {Colors.OKCYAN}... and {len(new_subs) - 20} more{Colors.ENDC}")
        
        if removed_subs:
            print(f"\n{Colors.WARNING}Removed Subdomains:{Colors.ENDC}")
            for sub in sorted(removed_subs)[:20]:
                print(f"  {Colors.WARNING}[-]{Colors.ENDC} {sub}")
            if len(removed_subs) > 20:
                print(f"  {Colors.OKCYAN}... and {len(removed_subs) - 20} more{Colors.ENDC}")
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(f"# Subdomain Comparison Report\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"## New Subdomains ({len(new_subs)})\n")
                for sub in sorted(new_subs):
                    f.write(f"{sub}\n")
                f.write(f"\n## Removed Subdomains ({len(removed_subs)})\n")
                for sub in sorted(removed_subs):
                    f.write(f"{sub}\n")
            log(f"Comparison saved to: {output_file}", "success")
        
        return new_subs, removed_subs
    
    @staticmethod
    def merge(input_files, output_file, json_output=False, quiet=False):
        """Merge multiple subdomain lists"""
        def log(message, level="info"):
            if quiet:
                return
            prefix = {
                "info": f"{Colors.OKBLUE}[*]{Colors.ENDC}",
                "success": f"{Colors.OKGREEN}[+]{Colors.ENDC}",
                "warning": f"{Colors.WARNING}[!]{Colors.ENDC}",
            }.get(level, "[*]")
            print(f"{prefix} {message}")
        
        all_subs = set()
        file_stats = {}
        
        for file in input_files:
            try:
                with open(file, 'r') as f:
                    subs = set(line.strip() for line in f if line.strip())
                    all_subs.update(subs)
                    file_stats[file] = len(subs)
                    log(f"Loaded {len(subs)} subdomains from {file}", "info")
            except FileNotFoundError:
                log(f"File '{file}' not found, skipping...", "warning")
        
        with open(output_file, 'w') as f:
            for sub in sorted(all_subs):
                f.write(f"{sub}\n")
        
        if json_output:
            output = {
                "total_unique": len(all_subs),
                "input_files": file_stats,
                "output_file": output_file
            }
            print(json.dumps(output, indent=2))
        else:
            log(f"Merged {len(all_subs)} unique subdomains to: {output_file}", "success")
        
        return all_subs


def main():
    parser = argparse.ArgumentParser(
        description='Recon Helper - Enhanced tool for analyzing subfinder/httpx results (Optimized for Claude Code)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate configuration setup
  python3 recon_helper.py validate-config

  # Get recommendations based on findings
  python3 recon_helper.py recommend results.json

  # Quick summary (fast triage)
  python3 recon_helper.py analyze results.json --summary

  # Full analysis with HTML report
  python3 recon_helper.py analyze results.json --report report.html

  # JSON output for programmatic parsing
  python3 recon_helper.py analyze results.json --json

  # Extract hosts using specific technology
  python3 recon_helper.py extract results.json --tech wordpress -o wordpress.txt

  # Generate organized target lists
  python3 recon_helper.py generate-targets results.json -o targets/

  # Compare subdomain lists with JSON output
  python3 recon_helper.py compare-subs baseline.txt current.txt --json

  # Merge multiple subdomain lists
  python3 recon_helper.py merge-subs file1.txt file2.txt -o merged.txt

Resources:
  CONFIG_TEMPLATES.md  - Configuration templates for subfinder/httpx
  WORKFLOWS.md         - Pre-built reconnaissance workflows
  WORDLISTS.md         - Comprehensive wordlist guide
        """
    )
    
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress non-essential output')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Validate config command
    validate_parser = subparsers.add_parser('validate-config', help='Validate subfinder/httpx configuration')
    
    # Recommend command
    recommend_parser = subparsers.add_parser('recommend', help='Get recommendations based on findings')
    recommend_parser.add_argument('json_file', help='Httpx JSON output file')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze httpx JSON results')
    analyze_parser.add_argument('json_file', help='Httpx JSON output file')
    analyze_parser.add_argument('--report', '-r', help='Generate HTML report')
    analyze_parser.add_argument('--summary', '-s', action='store_true', help='Quick summary only (fast triage)')
    analyze_parser.add_argument('--json', action='store_true', help='Output in JSON format for programmatic parsing')
    analyze_parser.add_argument('--tech-only', '-t', action='store_true', help='Show only technology analysis')
    analyze_parser.add_argument('--vuln-only', '-v', action='store_true', help='Show only vulnerable versions')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract hosts by technology')
    extract_parser.add_argument('json_file', help='Httpx JSON output file')
    extract_parser.add_argument('--tech', required=True, help='Technology to search for')
    extract_parser.add_argument('--output', '-o', help='Save results to file')
    extract_parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    # Generate targets command
    targets_parser = subparsers.add_parser('generate-targets', help='Generate organized target lists')
    targets_parser.add_argument('json_file', help='Httpx JSON output file')
    targets_parser.add_argument('--output-dir', '-o', default='targets', help='Output directory')
    targets_parser.add_argument('--by-tech', action='store_true', help='Generate by technology')
    targets_parser.add_argument('--by-status', action='store_true', help='Generate by status code')
    targets_parser.add_argument('--by-keywords', action='store_true', help='Generate by keywords')
    targets_parser.add_argument('--json', action='store_true', help='Output counts in JSON format')
    
    # Compare subdomains command
    compare_parser = subparsers.add_parser('compare-subs', help='Compare two subdomain lists')
    compare_parser.add_argument('baseline', help='Baseline subdomain file')
    compare_parser.add_argument('current', help='Current subdomain file')
    compare_parser.add_argument('--output', '-o', help='Save comparison to file')
    compare_parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    # Merge subdomains command
    merge_parser = subparsers.add_parser('merge-subs', help='Merge multiple subdomain lists')
    merge_parser.add_argument('files', nargs='+', help='Subdomain files to merge')
    merge_parser.add_argument('--output', '-o', required=True, help='Output file')
    merge_parser.add_argument('--json', action='store_true', help='Output stats in JSON format')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute commands
    if args.command == 'validate-config':
        ConfigValidator.validate()
    
    elif args.command == 'recommend':
        recommender = RecommendationEngine(args.json_file)
        recommender.analyze_and_recommend()
    
    elif args.command == 'analyze':
        analyzer = ReconAnalyzer(args.json_file, quiet=args.quiet)
        
        if args.summary:
            analyzer.print_summary(json_output=args.json)
        elif args.vuln_only:
            analyzer.find_vulnerable_versions(json_output=args.json)
        elif args.tech_only:
            analyzer.analyze_technologies(json_output=args.json)
        else:
            if not args.json:
                analyzer.analyze_technologies()
                analyzer.analyze_status_codes()
                analyzer.find_anomalies()
                analyzer.find_vulnerable_versions()
            else:
                # Combined JSON output for programmatic parsing
                output = {
                    "technologies": {},
                    "status_codes": {},
                    "anomalies": {},
                    "vulnerabilities": {}
                }
                # Would need to refactor to collect all data, but for now just do summary
                analyzer.print_summary(json_output=True)
        
        if args.report:
            analyzer.generate_report(args.report)
    
    elif args.command == 'extract':
        analyzer = ReconAnalyzer(args.json_file, quiet=args.quiet)
        results = analyzer.extract_by_technology(args.tech, args.output, json_output=args.json)
    
    elif args.command == 'generate-targets':
        generator = TargetListGenerator(args.json_file, quiet=args.quiet)
        
        if args.by_tech or (not args.by_tech and not args.by_status and not args.by_keywords):
            generator.generate_by_technology(args.output_dir, json_output=args.json)
        
        if args.by_status or (not args.by_tech and not args.by_status and not args.by_keywords):
            generator.generate_by_status(args.output_dir, json_output=args.json)
        
        if args.by_keywords or (not args.by_tech and not args.by_status and not args.by_keywords):
            generator.generate_by_keywords(args.output_dir, json_output=args.json)
    
    elif args.command == 'compare-subs':
        SubdomainManager.compare(args.baseline, args.current, args.output, 
                                json_output=args.json, quiet=args.quiet)
    
    elif args.command == 'merge-subs':
        SubdomainManager.merge(args.files, args.output, 
                              json_output=args.json, quiet=args.quiet)


if __name__ == '__main__':
    main()
