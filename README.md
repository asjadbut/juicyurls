# 🧃 JuicyURLs

<p align="center">
  <b>A powerful URL filtering tool for security researchers and bug bounty hunters</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg" alt="Platform">
</p>

---

## 🎯 What is JuicyURLs?

JuicyURLs is a smart URL filtering tool designed for **bug bounty hunters** and **security researchers**. It takes the massive output from tools like `waybackurls` or `gau` and filters out the noise, highlighting only the **juicy** URLs that are most likely to contain security vulnerabilities.

### The Problem

When running reconnaissance tools like `waybackurls` or `gau`, you often get thousands (or hundreds of thousands) of URLs. Most of these are static assets, duplicate pages, or other uninteresting endpoints. Finding the potentially vulnerable endpoints in this sea of noise is time-consuming and tedious.

### The Solution

JuicyURLs automatically categorizes URLs by potential vulnerability type:
- 🔴 **High**: RCE, SSTI, SQLi, IDOR, LFI/RFI, SSRF, XXE, Source Exposure
- 🟡 **Medium**: Open Redirect, XSS, File Upload, Auth endpoints, Admin panels
- 🔵 **Low**: API endpoints, Info disclosure

## ✨ Features

- 🎯 **Smart Categorization** - Automatically identifies 25+ vulnerability categories
- 🔍 **Real CVE Patterns** - Patterns based on actual CVEs (Log4j, Drupalgeddon, ProxyLogon, etc.)
- 🧠 **Confidence Scoring** - Analyzes parameter VALUES, not just names, to reduce false positives
- 🧃 **URL Intelligence** - Automatically classifies URLs as juicy/interesting/neutral/boring based on context
- 🔑 **Secret Detection** - Detects 30+ types of leaked API keys, tokens, and credentials in URLs
- 📁 **Interesting Files** - Finds backups, configs, source code leaks, .git exposure
- 🎯 **Smart Deduplication** - Groups similar URLs (e.g., `?id=1` and `?id=2`) keeping only unique patterns
- 📊 **Statistics** - Shows analysis summary and confidence levels
- 🎨 **Color Output** - Beautiful, color-coded terminal output with confidence stars (★★★)
- 🔧 **Flexible Input** - File, stdin, or direct domain scanning
- ⚡ **Fast** - Pure Python, no external dependencies
- 🔗 **Pipeline Ready** - Works seamlessly with waybackurls, gau, etc.

## 🚀 Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/asjadbut/juicyurls.git
cd juicyurls

# Install in development mode
pip install -e .

# Or install directly
pip install .
```

### Quick Install

```bash
pip install git+https://github.com/asjadbut/juicyurls.git
```

### Manual (No Install)

```bash
# Just run directly
python -m juicyurls --help
```

## 📖 Usage

### Basic Usage

```bash
# Pipe from waybackurls
echo "example.com" | waybackurls | juicyurls

# Pipe from gau
echo "example.com" | gau | juicyurls

# From a file
juicyurls -f urls.txt

# Direct domain scanning (uses gau by default)
juicyurls -d example.com

# Use waybackurls instead
juicyurls -d example.com --tool waybackurls

# Use both tools
juicyurls -d example.com --tool both
```

### Filter by Category or Severity

```bash
# Only show SQL injection and IDOR candidates
juicyurls -f urls.txt -c sqli idor

# Only show high severity
juicyurls -f urls.txt -s high

# Exclude certain categories
juicyurls -f urls.txt --exclude info_disclosure
```

### Output Options

```bash
# URLs only (for piping to other tools)
juicyurls -f urls.txt --format urls > filtered_urls.txt

# Quiet mode - URLs only, no banner/stats
juicyurls -f urls.txt -q

# No colors (for piping)
juicyurls -f urls.txt --no-color

# Verbose mode with match details
juicyurls -f urls.txt -v

# Save to file
juicyurls -f urls.txt -o results.txt
```

### Confidence Filtering

JuicyURLs analyzes parameter **values** (not just names) to calculate confidence scores:

```bash
# Only show high confidence results (recommended)
juicyurls -f urls.txt --high-confidence

# Custom minimum confidence (0.0 to 1.0)
juicyurls -f urls.txt --min-confidence 0.5

# Disable smart deduplication (keep all similar URLs)
juicyurls -f urls.txt --no-smart-dedupe

# Keep up to 5 URLs per similar pattern (default: 1)
juicyurls -f urls.txt --max-per-pattern 5
```

### Finding Interesting Files

```bash
# Find only interesting files (backups, configs, source leaks)
juicyurls -f urls.txt --interesting-files

# Find WordPress vulnerabilities only
juicyurls -f urls.txt -c wp_vulns

# Find all Java/Spring vulnerabilities (Log4j, Struts, etc.)
juicyurls -f urls.txt -c java_vulns
```

### URL Intelligence (Smart Filtering)

JuicyURLs analyzes the **entire URL context** to classify URLs automatically:

```bash
# Show intelligence classification in output
juicyurls -f urls.txt --show-intel

# Only show juicy/interesting URLs (filter out boring stuff)
juicyurls -f urls.txt --only-juicy

# Include boring URLs that are normally filtered
juicyurls -f urls.txt --show-boring

# Disable smart filtering entirely
juicyurls -f urls.txt --no-smart
```

**Classifications:**
- 🧃 **Juicy** - High-value targets (admin panels, API endpoints, auth flows, debug endpoints)
- ✨ **Interesting** - Worth investigating (upload forms, search endpoints, user data)
- ➖ **Neutral** - Standard endpoints, analyze normally
- 💤 **Boring** - Static assets, CDN, tracking pixels (filtered by default)

### Secret Detection

JuicyURLs automatically detects **leaked secrets** in URLs:

```bash
# Secret detection is enabled by default
juicyurls -f urls.txt

# Disable secret detection (faster processing)
juicyurls -f urls.txt --no-secrets

# Verbose mode shows detailed secret info
juicyurls -f urls.txt -v
```

**Detected Secret Types (30+):**
- 🔑 **API Keys**: AWS, Google, Stripe, Twilio, SendGrid, Mailgun
- 🎫 **Tokens**: JWT, GitHub, GitLab, Slack, Discord, NPM
- 🔐 **Credentials**: Private keys, passwords in URLs, Bearer tokens
- ☁️ **Cloud**: Azure, Firebase, Heroku, DigitalOcean
- 💳 **Payment**: Stripe, PayPal, Square API keys

**Example output with secrets:**
```
🔴 HIGH ★★★ (confidence: 100%) 🔑 SECRET
  URL: https://api.example.com/webhook?token=sk_live_EXAMPLE_KEY_HERE
  🔑 DETECTED SECRETS:
    ⚠️  stripe_secret: sk_live_EXAM****HERE (in param: token)
```

## 🎯 Vulnerability Categories

### Core Vulnerability Patterns

| Category | Severity | Description |
|----------|----------|-------------|
| `rce` | 🔴 High | Remote Code Execution patterns |
| `ssti` | 🔴 High | Server-Side Template Injection |
| `sqli` | 🔴 High | SQL Injection candidates |
| `idor` | 🔴 High | Insecure Direct Object References |
| `lfi_rfi` | 🔴 High | Local/Remote File Inclusion |
| `ssrf` | 🔴 High | Server-Side Request Forgery |
| `xxe` | 🔴 High | XML External Entity Injection |
| `sensitive_files` | 🔴 High | Exposed sensitive files |
| `redirect` | 🟡 Medium | Open Redirect vulnerabilities |
| `xss` | 🟡 Medium | Cross-Site Scripting candidates |
| `auth` | 🟡 Medium | Authentication/Session endpoints |
| `upload` | 🟡 Medium | File upload endpoints |
| `admin_debug` | 🟡 Medium | Admin/Debug endpoints |
| `backup` | 🟡 Medium | Backup files |
| `cloud` | 🟡 Medium | Cloud storage endpoints |
| `graphql` | 🟡 Medium | GraphQL endpoints |
| `leaked_secrets` | 🔴 High | API keys, tokens, credentials in URLs |
| `api` | 🔵 Low | API endpoints |
| `websocket` | 🔵 Low | WebSocket endpoints |
| `info_disclosure` | 🔵 Low | Information disclosure |

### Real CVE / Known Vulnerability Patterns

| Category | Severity | CVEs & Vulnerabilities |
|----------|----------|------------------------|
| `wp_vulns` | 🔴 High | WordPress: User enum (CVE-2017-5487), xmlrpc attacks, debug.log exposure, plugin vulns (CVE-2020-25213) |
| `drupal_vulns` | 🔴 High | Drupalgeddon 2/3 (CVE-2018-7600, CVE-2018-7602), user enumeration |
| `java_vulns` | 🔴 High | Apache Struts RCE (CVE-2017-5638), Log4j (CVE-2021-44228), Spring Boot Actuator, Tomcat Manager |
| `php_vulns` | 🔴 High | PHPUnit RCE (CVE-2017-9841), phpMyAdmin, Laravel debug mode, Adminer |
| `dotnet_vulns` | 🔴 High | Telerik UI (CVE-2019-18935), Exchange ProxyLogon (CVE-2021-26855), SharePoint |
| `api_vulns` | 🔴 High | OWASP API Top 10, Swagger exposure, GraphQL introspection |
| `source_exposure` | 🔴 High | .git exposure, .svn, CI/CD configs, cloud credentials, SSH keys |
| `auth_bypass` | 🔴 High | Admin panels, OAuth misconfig, JWT endpoints, SSO/SAML |
| `ssrf_vulns` | 🔴 High | Webhooks, URL fetching, PDF generators, import features |
| `interesting_files` | 🔴 High | Backups (.bak, .sql), configs (.env), source leaks (.php~) |

## 🔧 Advanced Usage

### Confidence Scoring

JuicyURLs analyzes parameter **values** to determine confidence:

```
★★★ High (70%+)   - Multiple strong indicators (suspicious values + matching paths)
★★☆ Medium (50%+) - Good indicators (API key params, numeric IDs, etc.)
★☆☆ Low (30%+)    - Basic pattern match
☆☆☆ Minimal       - Weak match, likely false positive
```

**What boosts confidence:**
- Parameter values containing `internal`, `admin`, `test`, `debug`, `secret`
- API key-like values (`sk_live_xxx`, long alphanumeric strings)
- URL values in SSRF-prone params (`?url=http://...`)
- File path values in LFI params (`?file=../etc/passwd`)
- Numeric IDs in IDOR params (`?userId=123`)

### Pipeline Examples

```bash
# Full recon pipeline with high confidence only
subfinder -d example.com | httpx | gau | juicyurls --high-confidence -o high_severity.txt

# Find all IDOR candidates and test with ffuf
juicyurls -f urls.txt -c idor --format urls | while read url; do
    ffuf -u "$url" -w ids.txt
done

# Extract SQLi candidates for sqlmap
juicyurls -f urls.txt -c sqli --format urls > sqli_candidates.txt
sqlmap -m sqli_candidates.txt --batch

# Hunt for specific CVEs
juicyurls -f urls.txt -c java_vulns  # Log4j, Struts, Spring
juicyurls -f urls.txt -c wp_vulns    # WordPress vulns
juicyurls -f urls.txt -c source_exposure  # Git exposure
```

### Combining with Other Tools

```bash
# With hakrawler
echo "https://example.com" | hakrawler | juicyurls

# With katana
katana -u https://example.com | juicyurls

# With gospider
gospider -s "https://example.com" -o output -c 10 -d 1
cat output/* | juicyurls
```

## 📊 Example Output

```
     ██╗██╗   ██╗██╗ ██████╗██╗   ██╗██╗   ██╗██████╗ ██╗     ███████╗
     ██║██║   ██║██║██╔════╝╚██╗ ██╔╝██║   ██║██╔══██╗██║     ██╔════╝
     ██║██║   ██║██║██║      ╚████╔╝ ██║   ██║██████╔╝██║     ███████╗
██   ██║██║   ██║██║██║       ╚██╔╝  ██║   ██║██╔══██╗██║     ╚════██║
╚█████╔╝╚██████╔╝██║╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗███████║
 ╚════╝  ╚═════╝ ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝

        🎯 Bug Bounty URL Analyzer - Find the Juice! 🧃


📊 Analysis Statistics
==================================================
  Total URLs processed: 1337
  Unique URLs: 892
  Matched URLs: 156
  🔑 SECRETS FOUND: 3 (check immediately!)
  Domains found: 5

  By Severity:
    HIGH: 23
    MEDIUM: 67
    LOW: 66

  By Intelligence:
    🧃 juicy: 45
    ✨ interesting: 78
    ➖ neutral: 33

🔴 HIGH (23 URLs)
------------------------------------------------------------
  🔑 ★★★ https://api.example.com/webhook?token=sk_live_xxx [leaked_secrets, auth]
       🔑 DETECTED: stripe_secret
  ★★★ https://api.example.com/v1/users?id=12345 [idor, api]
       Why: Numeric ID value; API endpoint path
  ★★☆ https://example.com/download?file=report.pdf [lfi_rfi]
       Why: File path in param
  ★★☆ https://example.com/.git/config [source_exposure]
       Why: Git repository exposed
```

## 📋 All Options

```
Usage: juicyurls [OPTIONS]

Input Options:
  -f, --file FILE          Input file containing URLs
  -d, --domain DOMAIN      Domain to gather URLs for
  --tool {waybackurls,gau,both}  External tool for URL gathering

Filter Options:
  -c, --categories CAT...  Filter by categories
  -s, --severity {high,medium,low}  Minimum severity
  --exclude CAT...         Exclude categories
  --min-confidence 0.0-1.0 Minimum confidence score
  --high-confidence        Only high confidence (≥50%)
  --no-dedupe              Keep duplicate URLs
  --no-smart-dedupe        Keep similar URLs
  --max-per-pattern N      Max URLs per pattern (default: 1)
  --interesting-files      Only interesting files

Smart Filtering (URL Intelligence):
  --no-smart               Disable URL intelligence
  --show-boring            Include boring URLs (static/CDN/tracking)
  --only-juicy             Only show juicy/interesting URLs
  --show-intel             Show intelligence classification in output
  --detect-secrets         Detect leaked secrets (default: enabled)
  --no-secrets             Disable secret detection

Output Options:
  -o, --output FILE        Output file
  --format {plain,urls}    Output format
  --no-color               Disable colors
  --no-stats               Hide statistics
  -v, --verbose            Show match details
  -q, --quiet              URLs only

Info:
  --list-categories        List all categories
  --version                Show version
  -h, --help               Show help
```

## 🤝 Contributing

Contributions are welcome! Feel free to:

- Add new vulnerability patterns
- Improve detection accuracy
- Add new output formats
- Fix bugs

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Credits

- Inspired by [tomnomnom/gf](https://github.com/tomnomnom/gf)
- Pattern ideas from [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns)
- Built for the bug bounty community

---

<p align="center">
  Made with 🧃 by security researchers, for security researchers
</p>
