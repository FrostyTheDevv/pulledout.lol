"""
Client-Side Security Checker - State of the Art
Analyzes JavaScript, DOM, and client-side vulnerabilities
"""

import requests
import re
from bs4 import BeautifulSoup

def check_client_side_security(scanner):
    """
    Perform comprehensive client-side security analysis
    Checks for XSS vectors, exposed secrets, dangerous JavaScript patterns
    """
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # ==================== EXPOSED API KEYS/SECRETS ====================
        # Common patterns for API keys and secrets
        secret_patterns = {
            r'AIza[0-9A-Za-z\\-_]{35}': 'Google API Key',
            r'AKIA[0-9A-Z]{16}': 'AWS Access Key',
            r'sk_live_[0-9a-zA-Z]{24,}': 'Stripe Live Secret Key',
            r'pk_live_[0-9a-zA-Z]{24,}': 'Stripe Live Public Key',
            r'rk_live_[0-9a-zA-Z]{24,}': 'Stripe Restricted Key',
            r'sq0atp-[0-9A-Za-z\\-_]{22}': 'Square Access Token',
            r'sq0csp-[0-9A-Za-z\\-_]{43}': 'Square OAuth Secret',
            r'ghp_[0-9a-zA-Z]{36}': 'GitHub Personal Access Token',
            r'gho_[0-9a-zA-Z]{36}': 'GitHub OAuth Token',
            r'xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24,}': 'Slack Token',
        }
        
        for pattern, secret_type in secret_patterns.items():
            matches = re.findall(pattern, response.text)
            if matches:
                scanner.add_finding(
                    severity='HIGH',
                    category='Client-side Exposure',
                    title=f'Exposed {secret_type} in source code',
                    description=f'Found potential {secret_type} exposed in HTML/JavaScript: {matches[0][:20]}...',
                    url=scanner.target_url,
                    remediation='Remove hardcoded API keys/secrets from client-side code. Use environment variables and server-side code.'
                )
        
        # ==================== DANGEROUS JAVASCRIPT PATTERNS ====================
        # Check for dangerous functions in inline scripts
        dangerous_patterns = {
            r'eval\s*\(': 'Use of eval() function',
            r'innerHTML\s*=': 'Direct innerHTML assignment (XSS risk)',
            r'document\.write\s*\(': 'Use of document.write()',
            r'dangerouslySetInnerHTML': 'Use of dangerouslySetInnerHTML (React)',
            r'__html\s*:': 'Raw HTML injection',
        }
        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                for pattern, description in dangerous_patterns.items():
                    if re.search(pattern, script.string):
                        scanner.add_finding(
                            severity='MEDIUM',
                            category='Client-side Exposure',
                            title=f'Dangerous JavaScript pattern: {description}',
                            description=f'Found use of potentially dangerous JavaScript pattern that may lead to XSS',
                            url=scanner.target_url,
                            remediation='Avoid dangerous functions. Use safe alternatives like textContent, createElement, or sanitization libraries.'
                        )
        
        # ==================== INLINE EVENT HANDLERS ====================
        # Check for inline event handlers (CSP violation)
        inline_event_attrs = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus', 'onblur']
        elements_with_inline_events = []
        
        for tag in soup.find_all(True):
            for attr in inline_event_attrs:
                if tag.get(attr):
                    elements_with_inline_events.append(f'{tag.name}[{attr}]')
        
        if elements_with_inline_events:
            scanner.add_finding(
                severity='MEDIUM',
                category='Client-side Exposure',
                title='Inline event handlers detected',
                description=f'Found {len(elements_with_inline_events)} elements with inline event handlers (violates CSP)',
                url=scanner.target_url,
                remediation='Remove inline event handlers and use addEventListener() instead'
            )
        
        # ==================== JAVASCRIPT: PROTOCOL ====================
        javascript_links = soup.find_all('a', href=re.compile(r'^javascript:', re.I))
        if javascript_links:
            scanner.add_finding(
                severity='MEDIUM',
                category='Client-side Exposure',
                title='javascript: protocol in links',
                description=f'Found {len(javascript_links)} links using javascript: protocol (XSS vector)',
                url=scanner.target_url,
                remediation='Replace javascript: links with proper event handlers'
            )
        
        #==================== CONSOLE LOGGING ====================
        # Check for console.log statements (information disclosure)
        console_patterns = [r'console\.log', r'console\.warn', r'console\.error', r'console\.debug']
        has_console = False
        
        for script in scripts:
            if script.string:
                for pattern in console_patterns:
                    if re.search(pattern, script.string):
                        has_console = True
                        break
            if has_console:
                break
        
        if has_console:
            scanner.add_finding(
                severity='INFO',
                category='Client-side Exposure',
                title='Console logging statements in production',
                description='Console logging statements found in JavaScript (may leak sensitive information)',
                url=scanner.target_url,
                remediation='Remove console.log statements from production code or use a logger that can be disabled'
            )
        
        # ==================== SUBRESOURCE INTEGRITY (SRI) ====================
        # Check for external scripts/styles without SRI
        external_scripts = soup.find_all('script', src=True)
        external_styles = soup.find_all('link', rel='stylesheet', href=True)
        
        scripts_without_sri = []
        for script in external_scripts:
            src = script.get('src', '')
            # Check if external (not same domain)
            if src.startswith('http') and scanner.domain not in src:
                if not script.get('integrity'):
                    scripts_without_sri.append(src)
        
        if scripts_without_sri:
            scanner.add_finding(
                severity='MEDIUM',
                category='Client-side Exposure',
                title='External scripts without Subresource Integrity',
                description=f'Found {len(scripts_without_sri)} external scripts without SRI hashes',
                url=scanner.target_url,
                remediation='Add integrity attribute to external scripts/stylesheets to prevent tampering'
            )
        
        # ==================== AUTOCOMPLETE ON SENSITIVE FIELDS ====================
        # Check for sensitive inputs with autocomplete enabled
        password_inputs = soup.find_all('input', type='password')
        for pwd_input in password_inputs:
            autocomplete = pwd_input.get('autocomplete', '').lower()
            if autocomplete not in ['off', 'new-password', 'current-password']:
                scanner.add_finding(
                    severity='LOW',
                    category='Client-side Exposure',
                    title='Password field without autocomplete control',
                    description='Password input found without proper autocomplete attribute',
                    url=scanner.target_url,
                    remediation='Set autocomplete="new-password" or "current-password" on password fields'
                )
        
        # ==================== HIDDEN FORM FIELDS ====================
        # Check for hidden fields with potentially sensitive data
        hidden_inputs = soup.find_all('input', type='hidden')
        suspicious_names = ['password', 'token', 'secret', 'api_key', 'apikey', 'session']
        
        for hidden in hidden_inputs:
            name = hidden.get('name', '').lower()
            value = hidden.get('value', '')
            if any(sus in name for sus in suspicious_names) and value:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Client-side Exposure',
                    title=f'Sensitive data in hidden form field',
                    description=f'Hidden input "{name}" may contain sensitive information exposed in source',
                    url=scanner.target_url,
                    remediation='Avoid storing sensitive data in hidden form fields. Use server-side session storage.'
                )
        
        # ==================== META REFRESH ====================
        meta_refresh = soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
        if meta_refresh:
            scanner.add_finding(
                severity='INFO',
                category='Client-side Exposure',
                title='Meta refresh tag detected',
                description='Page uses meta refresh for redirection (can be used for phishing)',
                url=scanner.target_url,
                remediation='Use server-side redirects (3xx status codes) instead of meta refresh'
            )
        
    except requests.RequestException:
        pass  # Connection issues already reported elsewhere
    except Exception as e:
        # Don't fail the whole scan if parsing fails
        pass
