# 🛡️ SawSap Security Scanner

**Professional-grade web security vulnerability scanner** with comprehensive OWASP-based testing, Cloudflare bypass, and extensive page discovery.

---

## ✨ Features

- 🔍 **16+ Security Modules** - Headers, SSL/TLS, cookies, forms, client-side, resources, and more
- 🌐 **Cloudflare Bypass** - Headless browser (Selenium) bypasses bot protection
- 🔄 **Comprehensive Crawling** - Discovers all pages via sitemap, robots.txt, links, and common paths
- ⚡ **Blazing Fast** - HTTP response caching + parallel analysis
- 🎯 **500+ Potential Findings** - Ultra-granular analysis covering every security aspect
- 💻 **Dual Interface** - Beautiful web dashboard + powerful CLI
- 📊 **OWASP Categories** - Industry-standard vulnerability taxonomy
- 📝 **Professional Reports** - Clean HTML with risk scoring and detailed remediation

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
# Activate virtual environment (if not already active)
.venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
```

### 2. Launch Web Dashboard (Recommended)
```bash
npm run dev
```
**That's it!** Opens browser at http://localhost:5000 automatically.

### 3. Or Use CLI
```bash
# Basic scan
python main.py example.com

# Comprehensive scan (100 pages)
python main.py example.com --max-pages 100

# Custom output
python main.py example.com --output my_report.html
```

Reports save to current directory.

---

## 📋 What Gets Scanned

| Category | Checks |
|----------|--------|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, 38+ header checks |
| **SSL/TLS** | Certificates, protocols, cipher suites, HTTPS enforcement |
| **Cookies** | Secure, HttpOnly, SameSite flags (per-cookie analysis) |
| **Forms** | CSRF protection, autocomplete, file uploads, password handling |
| **Resources** | Scripts, images, CSS (HTTP/HTTPS mixing, SRI, CDN analysis) |
| **Client-Side** | Exposed secrets, dangerous JS patterns, inline scripts |
| **Discovery** | robots.txt, sitemap.xml, sensitive files, admin panels |
| **Performance** | Response time, compression, caching headers |
| **Transport** | HTTPS redirect, upgrade-insecure-requests |
| **Information Disclosure** | Error messages, debug info, version exposure |

---

## 🌐 Advanced Features

### Cloudflare Protection Bypass
✅ **Automatic Cloudflare/Vercel bot detection bypass using Selenium**
- Headless Chrome browser
- Real browser fingerprinting
- Handles JavaScript-heavy sites
- Works with protected sites that block automated scanners

### Comprehensive Page Discovery
✅ **Finds ALL pages on a website through multiple methods:**
1. **Sitemap.xml parsing** - Official sitemap
2. **Robots.txt analysis** - Disallowed paths (security risk indicators)
3. **Link extraction** - Recursive crawling of internal links
4. **Common paths** - Tests 25+ common endpoints (/about, /contact, /admin, etc.)
5. **Deep crawling** - Follows links up to 10 pages deep

### Performance Optimization
✅ **3-5x faster than traditional scanners:**
- HTTP response caching (no duplicate requests)
- Shared response objects across modules
- Parallel security checks
- Efficient page discovery

---

## 📊 Sample Output

**Risk Scoring:**
- HIGH (25 pts) - Critical vulnerabilities requiring immediate action
- MEDIUM (5 pts) - Important issues to address soon
- LOW (1 pt) - Minor concerns and best practices
- INFO (0 pts) - Informational findings

**Example Comprehensive Scan:**
- 500+ total findings across 50+ pages
- 2 HIGH, 150 MEDIUM, 200 LOW, 150 INFO
- Risk Score: 950 (Critical)
- OWASP-categorized issues
- Professional HTML report with remediation steps

---

## 🔧 Advanced Usage

### CLI Options
```bash
python main.py <url> [options]

--max-pages <n>    Scan up to N pages (default: 100, set to 0 for unlimited)
--output <file>    Custom report filename
```

### Web Dashboard
```bash
# Quick start (recommended)
npm run dev

# Or manually
python launch_dashboard.py

# Or just the server
python web_server.py
```

Dashboard automatically:
- Scans up to 100 pages per site
- Uses Selenium for Cloudflare bypass
- Shows real-time progress
- Generates downloadable reports

### Web API Endpoints
```bash
POST   /api/scan                    - Start new scan
       Body: { "url": "example.com", "max_pages": 100 }

GET    /api/scan/<id>/status        - Check scan progress
GET    /api/scan/<id>/results       - Get JSON results
GET    /api/scan/<id>/report        - Download HTML report
GET    /api/scans                   - List all scans
GET    /health                      - Server health check
```

---

## 🏗️ Project Structure

```
SawSap/
├── core/                      # Core scanner engine
│   ├── scanner.py            # Main scanner with Selenium support
│   ├── page_discovery.py    # Comprehensive page crawler
│   └── report_generator.py  # HTML report generation
├── modules/                   # 16 security check modules
│   ├── security_headers.py
│   ├── ssl_checker.py
│   ├── cookie_security.py
│   ├── input_forms_security.py
│   └── ... (12 more modules)
├── templates/                 # Web dashboard UI
│   └── index.html
├── static/                    # CSS/JS assets
│   ├── css/style.css
│   └── js/app.js
├── main.py                    # CLI entry point
├── web_server.py             # Flask API server
├── launch_dashboard.py       # Quick start script
└── requirements.txt          # Python dependencies
```

---

## 📚 Documentation

- **[requirements.txt](requirements.txt)** - All Python dependencies
- **Web Dashboard** - http://localhost:5000 (after running `npm run dev`)

---

## ⚡ Performance

**Optimizations:**
- HTTP response caching (1 request per page vs 15+)
- Reduced timeouts (8s vs 10s)
- Efficient multi-page discovery

**Benchmarks:**
- Single page: ~5-8 seconds (was ~20-30s)
- 5 pages: ~30-40 seconds (was ~2+ minutes)

---

## 🎓 Example Workflow

### Web Dashboard
1. Open http://localhost:5000
2. Enter target URL (e.g., `example.com`)
3. Click "Start Scan"
4. Watch real-time progress
5. Download HTML report

### CLI
```bash
# Quick scan
python main.py gotchya.lol

# Multi-page scan
python main.py example.com --max-pages 5 --output my-scan.html

# View report
start reports\report_*.html
```

---

## 🛠️ Requirements

- **Python**: 3.8+
- **Dependencies**: Flask, requests, BeautifulSoup4, cryptography
- **OS**: Windows, Linux, macOS

Install:
```bash
pip install -r requirements.txt
```

---

## 📝 Notes

- Scanner uses responsible testing practices (User-Agent identification)
- Only scan sites you have permission to test
- Reports contain detailed remediation guidance
- No inline CSS (clean, professional reports)

---

## 🏆 Professional Grade

Matches industry scanners like:
- Mozilla Observatory
- SecurityHeaders.com
- SSL Labs

**Target**: 180+ findings per comprehensive scan

---

**Version**: 2.0 (Performance Optimized)  
**Updated**: March 2026  
**License**: For authorized security testing only

```bash
# Clone or download the project
cd Checker

# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install requests beautifulsoup4 flask flask-cors
```

---

## 🖥️ Usage

### Option 1: Terminal/CLI Mode

Run quick security scans from the terminal:

```bash
# Basic scan
python main.py https://example.com

# Scan with custom output file
python main.py https://example.com --output report.html

# Scan multiple pages
python main.py https://example.com --max-pages 20
```

**Example Output:**
```
[*] Starting security scan of: https://gotchya.lol
[*] Risk Score: 185 (High)
[*] Findings: HIGH: 2, MEDIUM: 31, LOW: 5, INFO: 16
[*] Report saved to: report.html
```

### Option 2: Web Dashboard (Recommended)

Launch the professional web interface:

```bash
# Start the web server
python web_server.py
```

Then open your browser to:
```
http://localhost:5000
```

**Web Dashboard Features:**
- Real-time scan progress tracking
- Interactive results dashboard
- Downloadable HTML reports
- Recent scans history
- Professional UI with risk visualization

---

## 📊 Understanding Results

### Risk Levels
- **Critical** (Score ≥ 150) - Immediate action required
- **High** (Score ≥ 100) - Urgent fixes needed
- **Medium** (Score ≥ 50) - Should be addressed
- **Low** (Score < 50) - Minor improvements

### Severity Breakdown
Each finding is categorized by severity:
- 🔴 **HIGH** - Exploitable vulnerabilities, immediate risk
- 🟠 **MEDIUM** - Security weaknesses, should fix soon
- 🔵 **LOW** - Best practice violations, low risk
- ⚪ **INFO** - Informational, no immediate risk

### Example Findings

**HIGH Severity:**
- CORS wildcard with credentials enabled
- Passwords transmitted over HTTP
- Weak SSL/TLS versions (SSLv3, TLSv1.0)

**MEDIUM Severity:**
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Missing CSRF protection
- Insecure cookie attributes

**LOW Severity:**
- Weak Referrer-Policy
- Missing Cross-Origin headers
- HSTS max-age too short

---

## 🔧 Architecture

### Project Structure
```
Checker/
├── main.py                      # CLI entry point
├── web_server.py                # Flask web server
├── scanner.py                   # Main scanner coordinator
├── report_generator.py          # HTML report generation
├── security_headers.py          # 30+ header checks
├── ssl_checker.py               # SSL/TLS analysis
├── transport_security.py        # HTTPS enforcement
├── form_analyzer.py             # Form security
├── cookie_session_checker.py    # Cookie analysis
├── client_side_security.py      # JavaScript security
├── info_disclosure.py           # Information leakage
├── discovery_hygiene.py         # File discovery
├── performance_availability.py  # Performance checks
├── advanced_checks.py           # HTTP methods testing
├── templates/
│   └── index.html              # Web dashboard
├── static/
│   ├── css/
│   │   └── style.css           # Professional styling
│   └── js/
│       └── app.js              # Dashboard JavaScript
├── reports/                     # Generated reports
└── requirements.txt             # Python dependencies
```

### Module Overview

**scanner.py** - Central coordinator that orchestrates all security checks
**security_headers.py** - Analyzes 30+ HTTP security headers with granular checks
**ssl_checker.py** - Deep SSL/TLS validation (certificates, ciphers, protocols)
**form_analyzer.py** - HTML form security (CSRF, passwords, validation)
**cookie_session_checker.py** - Cookie attribute analysis
**client_side_security.py** - JavaScript vulnerabilities and API key exposure
**info_disclosure.py** - Information leakage detection
**discovery_hygiene.py** - Sensitive file and configuration discovery
**performance_availability.py** - Performance metrics and optimization
**advanced_checks.py** - HTTP method testing and advanced configurations

---

## 🌐 Web API Endpoints

### Start New Scan
```http
POST /api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}

Response:
{
  "scan_id": "uuid",
  "message": "Scan started successfully"
}
```

### Check Scan Status
```http
GET /api/scan/{scan_id}/status

Response:
{
  "status": "running|completed|failed",
  "progress": 75,
  "message": "Running security checks..."
}
```

### Get Scan Results
```http
GET /api/scan/{scan_id}/results

Response:
{
  "target_url": "https://example.com",
  "risk_score": 185,
  "risk_level": "High",
  "findings_summary": {
    "HIGH": 2,
    "MEDIUM": 31,
    "LOW": 5,
    "INFO": 16
  },
  "findings": [...]
}
```

### Download HTML Report
```http
GET /api/scan/{scan_id}/report
```

### List All Scans
```http
GET /api/scans

Response: [
  {
    "scan_id": "uuid",
    "target_url": "https://example.com",
    "status": "completed",
    "risk_score": 185,
    "findings_count": 54
  }
]
```

### Health Check
```http
GET /health

Response:
{
  "status": "healthy",
  "timestamp": "2026-03-17T11:20:00",
  "active_scans": 0
}
```

---

## 🎯 Validation & Testing

Test against known vulnerable sites to validate detection:

```bash
# Test against gotchya.lol (known insecure site)
python main.py https://gotchya.lol

# Expected results: ~54 findings
# Risk Score: ~185 (High)
# HIGH: 2, MEDIUM: 31, LOW: 5, INFO: 16
```

---

## 🔐 Security Checks Reference

### Headers (30+ Checks)
- Strict-Transport-Security (HSTS)
  - max-age validation
  - includeSubDomains check
  - preload directive
- Content-Security-Policy (CSP)
  - unsafe-inline detection
  - unsafe-eval detection
  - Critical directives (default-src, script-src, object-src, base-uri)
  - form-action, frame-ancestors
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy / Feature-Policy
- X-XSS-Protection
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Resource-Policy (CORP)
- Expect-CT
- X-Permitted-Cross-Domain-Policies
- X-Download-Options
- X-DNS-Prefetch-Control
- Timing-Allow-Origin
- Access-Control-Allow-Origin (CORS)
- Clear-Site-Data

### SSL/TLS Checks
- Certificate validation
- Expiration warnings (30/90 days)
- Self-signed detection
- TLS version detection (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
- Weak cipher detection (RC4, DES, 3DES)

### Transport Security
- HTTPS enforcement
- HTTP to HTTPS redirects
- Mixed content (active vs passive)
- Upgrade-Insecure-Requests

### Form Security
- Password-over-HTTP
- GET method with passwords
- CSRF token detection
- Autocomplete on sensitive fields
- File upload enctype validation

### Cookie Security
- Secure flag
- HttpOnly flag
- SameSite attribute
- __Host- / __Secure- prefix validation
- Session cookie identification

### Client-Side Security
- API key exposure (Google, AWS, Stripe, GitHub)
- Dangerous JavaScript (eval, innerHTML, document.write)
- Inline event handlers
- Subresource Integrity (SRI)

### Information Disclosure
- Server headers
- X-Powered-By, X-AspNet-Version
- Database error messages
- HTML comments
- Email addresses
- Internal IP detection
- Version fingerprinting

### Discovery & Hygiene
- robots.txt analysis
- sitemap.xml
- Sensitive files (.git, .env, phpinfo.php, web.config)
- security.txt (RFC 9116)
- Backup files (.bak, .old, ~)

### Performance & Availability
- Response time measurement
- Compression (gzip/brotli)
- Cache-Control validation
- CDN detection

### Advanced Checks
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- OPTIONS enumeration
- Character encoding
- Additional header validations

---

## 🚀 Production Deployment

### Environment Setup
```bash
# Set production mode
export FLASK_ENV=production

# Configure host/port
python web_server.py
```

### Recommended Improvements for Production
1. **Add Database** - Replace in-memory storage with PostgreSQL/MySQL
2. **Add Authentication** - Implement user login and API keys
3. **Rate Limiting** - Prevent abuse with rate limits
4. **Queue System** - Use Celery/RQ for background scanning
5. **Caching** - Redis for scan result caching
6. **Logging** - Structured logging with ELK stack
7. **Monitoring** - Prometheus/Grafana metrics
8. **SSL/TLS** - Use HTTPS with valid certificates
9. **Reverse Proxy** - Nginx for production serving

---

## 📈 Roadmap

### Planned Features
- [ ] JavaScript rendering with Selenium/Playwright
- [ ] Automated regression testing
- [ ] API security testing
- [ ] Authentication testing
- [ ] SQL injection detection
- [ ] XSS vulnerability scanning
- [ ] SSRF detection
- [ ] Path traversal testing
- [ ] File upload vulnerabilities
- [ ] Rate limiting detection
- [ ] WAF detection and bypass
- [ ] Subdomain enumeration
- [ ] Port scanning integration
- [ ] CVE database integration
- [ ] Compliance reporting (PCI DSS, GDPR, etc.)

---

## 🤝 Contributing

This is a professional security scanning platform. When adding new checks:

1. Follow OWASP guidelines
2. Add comprehensive comments
3. Include remediation advice
4. Test against known vulnerable sites
5. Update this README

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Only scan websites you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.

---

## 📝 License

Professional Security Scanner - For authorized security testing only.

---

## 🆘 Support

### Common Issues

**Issue: Unicode errors on Windows**
- Fixed in current version with ASCII-safe output

**Issue: Connection timeouts**
- Increase timeout in scanner.py
- Check firewall/network settings

**Issue: Missing findings**
- Ensure all modules are imported in scanner.py
- Check that target site is accessible
- Review scan logs for errors

### Getting Help

For issues or questions:
1. Check this README
2. Review error messages in terminal
3. Check generated reports for details
4. Verify all dependencies are installed

---

**Built with ❤️ for security professionals**
#   F o r c e   r e b u i l d  
 