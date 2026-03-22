"""
Web Security Scanner - Main Scanner Class
Comprehensive security vulnerability scanner for websites and web applications
"""

import requests
import cloudscraper
import urllib.parse
from typing import Dict, List, Tuple
from datetime import datetime
import socket
import ssl
from collections import defaultdict
import sys

# Selenium for headless browser (bypass Cloudflare/bot protection)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Warning: Selenium not available. Install with: pip install selenium")

# Safe print function that handles encoding errors
def safe_print(text):
    """Print text with Unicode fallback for encoding issues"""
    # Proactively replace Unicode characters for Windows compatibility
    replacements = {
        '└─': '+-',
        '├─': '|-', 
        '✓': '[OK]',
        '⚠': '[!]',
        '❌': '[X]',
        '🔍': '',
        '║': '|',
        '═': '=',
        '╔': '+',
        '╗': '+',
        '╚': '+',
        '╝': '+'
    }
    
    # Replace Unicode characters before printing
    ascii_text = str(text)
    for unicode_char, ascii_char in replacements.items():
        ascii_text = ascii_text.replace(unicode_char, ascii_char)
    
    try:
        print(ascii_text, flush=True)
    except Exception:
        # Last resort fallback
        print(ascii_text.encode('ascii', errors='replace').decode('ascii'), flush=True)

class SecurityScanner:
    """Main scanner that coordinates all security checks"""
    
    def __init__(self, target_url: str, max_pages: int = 9999):
        self.target_url = target_url.rstrip('/')
        self.max_pages = max_pages
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        self.findings = []
        self.pages_scanned = []
        
        # Use cloudscraper to bypass Cloudflare/bot protection
        self.session = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'desktop': True
            }
        )
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Cache for HTTP responses to avoid duplicate requests
        self.response_cache = {}
        self.timeout = 8  # Reduced timeout for faster scans
        
        # Initialize headless browser for Cloudflare bypass
        self.driver = None
        self.selenium_enabled = SELENIUM_AVAILABLE
        if self.selenium_enabled:
            self._init_selenium_driver()
        
    def _init_selenium_driver(self):
        """Initialize Selenium headless Chrome driver with DevTools for header capture"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless=new')  # New headless mode
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Enable Performance logging to capture network headers
            chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
            
            # Use Selenium Manager (auto-downloads correct ChromeDriver version)
            # No need for webdriver-manager - Selenium 4.6+ handles this automatically
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(15)
           
            # Enable Chrome DevTools Protocol Network domain to capture HTTP headers
            self.driver.execute_cdp_cmd('Network.enable', {})
            
            safe_print("[✓] Selenium headless browser initialized (Cloudflare bypass + header capture enabled)")
        except Exception as e:
            safe_print(f"[!] Failed to initialize Selenium: {e}")
            self.selenium_enabled = False
            self.driver = None
    
    def _get_page_with_selenium(self, url):
        """Fetch page using Selenium headless browser with full HTTP header capture"""
        if not self.selenium_enabled or not self.driver:
            return None
        
        try:
            self.driver.get(url)
            # Wait for page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Extract REAL HTTP response headers from Performance logs
            real_headers = {}
            try:
                logs = self.driver.get_log('performance')
                for entry in logs:
                    import json
                    log = json.loads(entry['message'])['message']
                    
                    # Looking for Network.responseReceived events for our URL
                    if log.get('method') == 'Network.responseReceived':
                        response_url = log['params']['response']['url']
                        # Match the main page (not resources like CSS/JS)
                        if response_url == url or response_url.rstrip('/') == url.rstrip('/'):
                            # Extract HTTP headers
                            headers_dict = log['params']['response'].get('headers', {})
                            real_headers = headers_dict
                            break
            except Exception as e:
                safe_print(f"    ├─ Warning: Could not extract headers from logs: {str(e)[:50]}")
            
            # Create a mock response object that matches requests.Response interface
            class SeleniumResponse:
                def __init__(self, driver, captured_headers):
                    self.text = driver.page_source
                    self.content = self.text.encode('utf-8')
                    self.status_code = 200
                    self.url = driver.current_url
                    self.ok = True
                    self.history = []
                    
                    # Convert Selenium cookies to requests-compatible format
                    self.cookies = {}
                    try:
                        for cookie in driver.get_cookies():
                            self.cookies[cookie['name']] = cookie['value']
                    except:
                        pass
                    
                    # Use captured HTTP headers if available, otherwise fallback
                    if captured_headers:
                        self.headers = captured_headers
                    else:
                        # Fallback: Try to get content-type from JavaScript
                        self.headers = {}
                        try:
                            content_type = driver.execute_script(
                                "return document.contentType || 'text/html'"
                            )
                            self.headers['Content-Type'] = content_type
                        except:
                            self.headers['Content-Type'] = 'text/html'
                    
            response = SeleniumResponse(self.driver, real_headers)
            
            if real_headers:
                safe_print(f"    └─ ✅ Fetched with Selenium + {len(real_headers)} HTTP headers captured")
            else:
                safe_print(f"    └─ ⚠️  Selenium fetch OK but no headers captured (fallback mode)")
            
            return response
            
        except Exception as e:
            safe_print(f"    └─ Selenium error: {str(e)}")
            return None
    
    def get_cached_response(self, url, silent=False):
        """Get cached response or fetch and cache it (with Selenium fallback)
        
        Args:
            url: URL to fetch
            silent: If True, suppress warning messages (useful during discovery)
        """
        if url in self.response_cache:
            return self.response_cache[url]
        
        # Try cloudscraper first (faster)
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=True)
            if response.status_code == 200:
                self.response_cache[url] = response
                return response
            elif response.status_code == 403:
                if not silent:
                    safe_print(f"    └─ HTTP 403 (Cloudflare), trying Selenium...")
                # Fall back to Selenium for Cloudflare bypass
                selenium_response = self._get_page_with_selenium(url)
                if selenium_response:
                    self.response_cache[url] = selenium_response
                    return selenium_response
                return None
            else:
                if not silent:
                    safe_print(f"    └─ Warning: HTTP {response.status_code} for {url}")
                return None
        except requests.exceptions.SSLError:
            # Try without SSL verification
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
                if response.status_code == 200:
                    self.response_cache[url] = response
                    return response
                elif response.status_code == 403:
                    # Fall back to Selenium
                    selenium_response = self._get_page_with_selenium(url)
                    if selenium_response:
                        self.response_cache[url] = selenium_response
                        return selenium_response
            except Exception as e:
                safe_print(f"    └─ Error: {str(e)}")
                # Try Selenium as last resort
                selenium_response = self._get_page_with_selenium(url)
                if selenium_response:
                    self.response_cache[url] = selenium_response
                    return selenium_response
                return None
        except Exception as e:
            safe_print(f"    └─ Error: {str(e)}")
            # Try Selenium as last resort
            selenium_response = self._get_page_with_selenium(url)
            if selenium_response:
                self.response_cache[url] = selenium_response
                return selenium_response
            return None
        
    def add_finding(self, severity: str, category: str, title: str, 
                   description: str, url: str, remediation: str = ""):
        """Add a security finding to the results"""
        self.findings.append({
            'severity': severity,
            'category': category,
            'title': title,
            'description': description,
            'url': url,
            'remediation': remediation,
            'timestamp': datetime.now()
        })
        
    def get_risk_score(self) -> Tuple[int, str]:
        """
        Calculate risk score based on findings
        OWASP-aligned risk scoring:
        - CRITICAL: Immediate exploitation, severe impact
        - HIGH: Easy exploitation, significant impact  
        - MEDIUM: Moderate difficulty, moderate impact
        - LOW: Difficult or low impact
        - INFO: Informational only
        """
        score = 0
        severity_weights = {
            'CRITICAL': 50,  # e.g., RCE, SQLi, Auth bypass
            'HIGH': 25,      # e.g., XSS, CSRF, exposed secrets
            'MEDIUM': 5,     # e.g., Missing headers, config issues
            'LOW': 1,        # e.g., Version disclosure, minor leaks
            'INFO': 0        # e.g., Best practices, recommendations
        }
        
        for finding in self.findings:
            score += severity_weights.get(finding['severity'], 0)
        
        # OWASP Risk Rating thresholds
        if score >= 200:
            risk_level = "Critical"  # 4+ CRITICAL or 8+ HIGH
        elif score >= 100:
            risk_level = "High"      # 2+ CRITICAL or 4+ HIGH
        elif score >= 50:
            risk_level = "Medium"     # 1 CRITICAL or 2 HIGH or 10 MEDIUM
        elif score >= 10:
            risk_level = "Low"        # 2+ MEDIUM or 10+ LOW
        else:
            risk_level = "Minimal"    # Only INFO findings
            
        return score, risk_level
    
    def get_findings_summary(self) -> Dict[str, int]:
        """Get count of findings by severity"""
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in self.findings:
            severity = finding['severity']
            if severity in summary:
                summary[severity] += 1
        return summary
    
    def get_category_summary(self) -> Dict[str, int]:
        """Get count of findings by category"""
        category_counts = defaultdict(int)
        for finding in self.findings:
            category_counts[finding['category']] += 1
        return dict(category_counts)
    
    def scan(self) -> Dict:
        """Run all security scans"""
        print(f"\n[*] Starting security scan of: {self.target_url}")
        print(f"[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Discover pages to scan
        from core.page_discovery import discover_pages
        pages_to_scan = discover_pages(self)
        
        # Import all security checkers
        from modules.security_headers import check_security_headers
        from modules.ssl_checker import check_ssl_tls
        from modules.input_forms_security import check_input_forms_security
        from modules.info_disclosure import check_information_disclosure
        from modules.transport_security import check_transport_security
        from modules.cookie_session_checker import check_cookie_security
        from modules.cookie_granular import ultra_granular_cookie_scan
        from modules.resource_security import ultra_granular_resource_scan
        from modules.client_side_security import check_client_side_security
        from modules.discovery_hygiene import check_discovery_hygiene
        from modules.performance_availability import check_performance_availability
        from modules.advanced_checks import run_advanced_scans, check_server_configuration
        from modules.comprehensive_header_analysis import ultra_granular_header_scan
        from modules.technology_detection import detect_technologies
        from modules.http_security_detailed import detailed_http_analysis
        from modules.maximum_coverage import maximum_coverage_scan
        
        # NEW: Advanced data extraction and vulnerability discovery modules
        from modules.data_extraction import extract_all_data
        from modules.exposed_files_scanner import scan_exposed_files
        from modules.cloud_storage_detection import detect_cloud_storage
        from modules.database_exposure import check_database_exposure
        from modules.api_testing import discover_and_test_apis
        
        # NEW: Active exploitation testing modules (penetration testing)
        from modules.active_sql_injection import test_sql_injection
        from modules.active_xss_testing import test_xss_vulnerabilities
        from modules.active_auth_testing import test_authentication_bypass
        from modules.active_rce_testing import test_command_injection
        from modules.active_data_harvest import harvest_sensitive_data
        from modules.active_file_upload_testing import test_file_uploads
        from modules.active_session_hijacking import test_session_hijacking
        
        # Run checks on FIRST page only (for SSL, discovery, etc.)
        original_url = self.target_url
        
        print("[*] Checking transport security...")
        check_transport_security(self)
        
        print("[*] Checking SSL/TLS configuration...")
        check_ssl_tls(self)
        
        print("[*] Running discovery and hygiene checks...")
        check_discovery_hygiene(self)
        
        print("[*] Detecting technologies and frameworks...")
        detect_technologies(self)
        
        print("[*] Detailed HTTP security analysis...")
        detailed_http_analysis(self)
        
        print("[*] Testing HTTP methods and server config...")
        check_server_configuration(self)
        
        # NEW: Advanced data extraction and discovery (run once)
        print("[*] Scanning for exposed sensitive files...")
        scan_exposed_files(self)
        
        print("[*] Detecting cloud storage exposure...")
        detect_cloud_storage(self)
        
        print("[*] Checking for exposed databases...")
        check_database_exposure(self)
        
        # NEW: Active exploitation testing (penetration testing)
        print("[*] Testing for SQL injection vulnerabilities...")
        test_sql_injection(self)
        
        print("[*] Testing for XSS vulnerabilities...")
        test_xss_vulnerabilities(self)
        
        print("[*] Testing authentication and authorization...")
        test_authentication_bypass(self)
        
        print("[*] Testing for command injection and RCE...")
        test_command_injection(self)
        
        print("[*] Harvesting sensitive data and credentials...")
        harvest_sensitive_data(self)
        
        print("[*] Testing file upload vulnerabilities...")
        test_file_uploads(self)
        
        print("[*] Testing session hijacking vectors...")
        test_session_hijacking(self)
        
        # Run per-page checks on ALL discovered pages
        for page_num, page_url in enumerate(pages_to_scan, 1):
            print(f"\n[*] Scanning page {page_num}/{len(pages_to_scan)}: {page_url}")
            
            # Temporarily update target_url for this page
            self.target_url = page_url
            
            # Pre-fetch and cache response for this page (MAJOR PERFORMANCE BOOST)
            safe_print(f"    ├─ Fetching page...")
            page_response = self.get_cached_response(page_url)
            if not page_response:
                safe_print(f"    └─ Skipped (failed to fetch)")
                continue
            
            safe_print(f"    ├─ Analyzing security headers...")
            check_security_headers(self)
            
            safe_print(f"    ├─ Ultra-granular header analysis...")
            ultra_granular_header_scan(self)
            
            safe_print(f"    ├─ Cookie security...")
            check_cookie_security(self)
            ultra_granular_cookie_scan(self)
            
            safe_print(f"    ├─ Resource security...")
            ultra_granular_resource_scan(self)
            
            safe_print(f"    ├─ Form analysis...")
            check_input_forms_security(self)
            
            safe_print(f"    ├─ Deep data extraction...")
            extract_all_data(self)
            
            safe_print(f"    ├─ API endpoint discovery & testing...")
            discover_and_test_apis(self)
            
            safe_print(f"    ├─ Client-side security...")
            check_client_side_security(self)
            
            safe_print(f"    ├─ Information disclosure...")
            check_information_disclosure(self)
            
            safe_print(f"    ├─ Performance & availability...")
            check_performance_availability(self)
            
            safe_print(f"    └─ Maximum coverage scan...")
            maximum_coverage_scan(self)
            
            # Mark page as scanned
            if page_url not in self.pages_scanned:
                self.pages_scanned.append(page_url)
        
        # Advanced scans (run once)
        print("\n[*] Running advanced vulnerability scans...")
        self.target_url = original_url  # Restore original URL
        run_advanced_scans(self)
        
        # Calculate results
        risk_score, risk_level = self.get_risk_score()
        findings_summary = self.get_findings_summary()
        category_summary = self.get_category_summary()
        
        results = {
            'target_url': self.target_url,
            'scan_time': datetime.now(),
            'pages_scanned': len(self.pages_scanned),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'findings_summary': findings_summary,
            'category_summary': category_summary,
            'findings': sorted(self.findings, key=lambda x: 
                             {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}.get(x['severity'], 4))
        }
        
        print(f"\n[*] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Pages scanned: {len(self.pages_scanned)}")
        print(f"[*] Risk Score: {risk_score} ({risk_level})")
        print(f"[*] Findings: HIGH: {findings_summary['HIGH']}, MEDIUM: {findings_summary['MEDIUM']}, "
              f"LOW: {findings_summary['LOW']}, INFO: {findings_summary['INFO']}")
        
        # Cleanup Selenium driver
        self.cleanup()
        
        return results
    
    def cleanup(self):
        """Close Selenium driver and cleanup resources"""
        if self.driver:
            try:
                self.driver.quit()
                safe_print("[✓] Selenium browser closed")
            except:
                pass
