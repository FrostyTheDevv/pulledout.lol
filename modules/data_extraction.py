"""
Deep Data Extraction Module - Advanced Information Gathering
Extracts all possible data from target websites including forms, inputs, metadata, and sensitive information
"""

import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import base64

def extract_all_data(scanner):
    """
    Comprehensive data extraction from website
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract all forms and their details
        _extract_forms(scanner, soup, scanner.target_url)
        
        # Extract all input fields (including hidden)
        _extract_input_fields(scanner, soup)
        
        # Extract metadata
        _extract_metadata(scanner, soup)
        
        # Extract all links and endpoints
        _extract_endpoints(scanner, soup, scanner.target_url)
        
        # Extract emails and phone numbers
        _extract_contact_info(scanner, response.text)
        
        # Extract data from HTML comments
        _extract_comment_data(scanner, soup)
        
        # Extract JavaScript variables and configurations
        _extract_js_data(scanner, soup, scanner.target_url)
        
        # Extract exposed credentials/keys
        _extract_credentials(scanner, response.text)
        
        # Extract API endpoints from JavaScript
        _extract_api_endpoints(scanner, soup, response.text)
        
    except Exception as e:
        print(f"Data extraction error: {e}")

def _extract_forms(scanner, soup, base_url):
    """Extract all forms with complete details"""
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        form_url = urljoin(base_url, action) if action else base_url
        
        # Get all form inputs
        inputs = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name', ''),
                'value': input_tag.get('value', ''),
                'id': input_tag.get('id', ''),
                'required': input_tag.has_attr('required'),
                'autocomplete': input_tag.get('autocomplete', '')
            }
            inputs.append(input_data)
        
        # Check for insecure form attributes
        if method == 'GET' and any(i['type'] in ['password', 'email'] for i in inputs):
            scanner.add_finding(
                severity='HIGH',
                category='Data Extraction',
                title='Sensitive data in GET form',
                description=f'Form submits sensitive data via GET method to {form_url}',
                url=scanner.target_url,
                remediation='Use POST method for forms containing sensitive data'
            )
        
        # Check for autocomplete on sensitive fields
        password_inputs = [i for i in inputs if i['type'] == 'password' and i['autocomplete'] != 'off']
        if password_inputs:
            scanner.add_finding(
                severity='LOW',
                category='Data Extraction',
                title='Password autocomplete enabled',
                description=f'Password field allows autocomplete at {form_url}',
                url=scanner.target_url,
                remediation='Add autocomplete="off" to password inputs'
            )
        
        # Log form data
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title='Form discovered',
            description=f'Form with {len(inputs)} fields found: {method} {form_url}',
            url=scanner.target_url,
            remediation=''
        )

def _extract_input_fields(scanner, soup):
    """Extract all input fields including hidden ones"""
    hidden_inputs = soup.find_all('input', {'type': 'hidden'})
    
    for hidden in hidden_inputs:
        name = hidden.get('name', '')
        value = hidden.get('value', '')
        
        # Check for sensitive data in hidden fields
        sensitive_patterns = {
            r'password|pwd|passwd': 'Password',
            r'api[_-]?key|apikey|api_token': 'API Key',
            r'secret|token|auth': 'Authentication Token',
            r'credit[_-]?card|cc_?num|card_?number': 'Credit Card',
            r'ssn|social[_-]?security': 'Social Security Number',
            r'admin|administrator': 'Admin Reference'
        }
        
        for pattern, data_type in sensitive_patterns.items():
            if re.search(pattern, f"{name} {value}", re.IGNORECASE) and value:
                scanner.add_finding(
                    severity='HIGH',
                    category='Data Extraction',
                    title=f'Sensitive data in hidden field: {data_type}',
                    description=f'Hidden input "{name}" contains potential {data_type}: {value[:50]}...',
                    url=scanner.target_url,
                    remediation='Never store sensitive data in hidden fields. Use server-side session storage.'
                )

def _extract_metadata(scanner, soup):
    """Extract all metadata from page"""
    meta_tags = soup.find_all('meta')
    
    for meta in meta_tags:
        name = meta.get('name', '') or meta.get('property', '')
        content = meta.get('content', '')
        
        if content and len(content) > 10:
            # Check for interesting metadata
            if any(keyword in name.lower() for keyword in ['author', 'generator', 'application-name', 'framework']):
                scanner.add_finding(
                    severity='INFO',
                    category='Data Extraction',
                    title=f'Metadata discovered: {name}',
                    description=f'{name}: {content}',
                    url=scanner.target_url,
                    remediation=''
                )

def _extract_endpoints(scanner, soup, base_url):
    """Extract all links and endpoints"""
    links = soup.find_all(['a', 'link', 'script', 'img', 'iframe'])
    endpoints = set()
    
    for link in links:
        href = link.get('href') or link.get('src')
        if href:
            full_url = urljoin(base_url, href)
            endpoints.add(full_url)
    
    # Check for interesting endpoints
    api_patterns = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/admin/', '/dashboard/', '/backend/']
    
    for endpoint in endpoints:
        for pattern in api_patterns:
            if pattern in endpoint.lower():
                scanner.add_finding(
                    severity='INFO',
                    category='Data Extraction',
                    title='API/Admin endpoint discovered',
                    description=f'Potential sensitive endpoint: {endpoint}',
                    url=scanner.target_url,
                    remediation='Ensure sensitive endpoints require authentication'
                )
                break

def _extract_contact_info(scanner, text):
    """Extract email addresses and phone numbers"""
    # Email addresses
    emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))
    
    if emails:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title='Email addresses found',
            description=f'Discovered {len(emails)} email addresses: {", ".join(list(emails)[:5])}',
            url=scanner.target_url,
            remediation=''
        )
    
    # Phone numbers (basic patterns)
    phones = set(re.findall(r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b', text))
    
    if phones:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title='Phone numbers found',
            description=f'Discovered {len(phones)} phone numbers',
            url=scanner.target_url,
            remediation=''
        )

def _extract_comment_data(scanner, soup):
    """Extract data from HTML comments"""
    comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
    
    for comment in comments:
        comment_text = str(comment).strip()
        if len(comment_text) > 20:
            # Check for credentials in comments
            if any(keyword in comment_text.lower() for keyword in ['password', 'key', 'secret', 'token', 'credential']):
                scanner.add_finding(
                    severity='HIGH',
                    category='Data Extraction',
                    title='Sensitive data in HTML comments',
                    description=f'Comment contains sensitive keywords: {comment_text[:100]}...',
                    url=scanner.target_url,
                    remediation='Remove sensitive information from HTML comments'
                )

def _extract_js_data(scanner, soup, base_url):
    """Extract JavaScript variables and configuration objects"""
    scripts = soup.find_all('script')
    
    for script in scripts:
        if script.string:
            # Look for variable declarations with sensitive data
            var_patterns = [
                r'(?:var|let|const)\s+(\w*(?:key|token|secret|password|api)\w*)\s*=\s*["\']([^"\']+)["\']',
                r'(\w+)\s*:\s*["\']([a-zA-Z0-9+/=]{30,})["\']',  # Potential base64 or tokens
            ]
            
            for pattern in var_patterns:
                matches = re.findall(pattern, script.string, re.IGNORECASE)
                for var_name, var_value in matches:
                    if len(var_value) > 15:  # Ignore short values
                        scanner.add_finding(
                            severity='HIGH',
                            category='Data Extraction',
                            title='Hardcoded credentials in JavaScript',
                            description=f'Variable "{var_name}" contains potential credential: {var_value[:30]}...',
                            url=scanner.target_url,
                            remediation='Never hardcode credentials in client-side code. Use server-side API calls.'
                        )

def _extract_credentials(scanner, text):
    """Extract exposed credentials and API keys"""
    credential_patterns = {
        r'(AKIA[0-9A-Z]{16})': 'AWS Access Key ID',
        r'([a-zA-Z0-9+/]{40})': 'AWS Secret Access Key',
        r'sk_live_[a-zA-Z0-9]{24,}': 'Stripe Live Secret Key',
        r'pk_live_[a-zA-Z0-9]{24,}': 'Stripe Live Publishable Key',
        r'AIza[0-9A-Za-z\\-_]{35}': 'Google API Key',
        r'ghp_[a-zA-Z0-9]{36}': 'GitHub Personal Access Token',
        r'gho_[a-zA-Z0-9]{36}': 'GitHub OAuth Token',
        r'Bearer [a-zA-Z0-9\\-._~+/]+=*': 'Bearer Token',
        r'mongodb(\+srv)?://[^\\s]+': 'MongoDB Connection String',
        r'postgres://[^\\s]+': 'PostgreSQL Connection String',
        r'mysql://[^\\s]+': 'MySQL Connection String',
    }
    
    for pattern, cred_type in credential_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            for match in matches[:3]:  # Limit to first 3 to avoid spam
                scanner.add_finding(
                    severity='CRITICAL' if 'secret' in cred_type.lower() else 'HIGH',
                    category='Data Extraction',
                    title=f'Exposed {cred_type}',
                    description=f'Found exposed credential: {match[:40]}...',
                    url=scanner.target_url,
                    remediation='Immediately revoke exposed credentials and use environment variables.'
                )

def _extract_api_endpoints(scanner, soup, text):
    """Extract API endpoints from JavaScript"""
    # Look for API endpoint patterns
    api_patterns = [
        r'https?://[a-zA-Z0-9.-]+/api/[a-zA-Z0-9/_-]+',
        r'["\']/(api|rest|graphql|v\d)/[a-zA-Z0-9/_-]+["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.\w+\(["\']([^"\']+)["\']',
        r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']',
    ]
    
    endpoints = set()
    for pattern in api_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        endpoints.update(matches)
    
    for endpoint in endpoints:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title='API endpoint discovered in JavaScript',
            description=f'Found endpoint: {endpoint}',
            url=scanner.target_url,
            remediation='Ensure all API endpoints implement proper authentication and rate limiting'
        )
