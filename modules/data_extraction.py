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
    form_data_list = []
    
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
        
        form_info = {
            'action': form_url,
            'method': method,
            'inputs': inputs,
            'input_count': len(inputs)
        }
        form_data_list.append(form_info)
        
        # Check for insecure form attributes
        if method == 'GET' and any(i['type'] in ['password', 'email'] for i in inputs):
            scanner.add_finding(
                severity='HIGH',
                category='Data Extraction',
                title='Sensitive data in GET form',
                description=f'Form submits sensitive data via GET method to {form_url}',
                url=scanner.target_url,
                remediation='Use POST method for forms containing sensitive data',
                evidence={'form': form_info}
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
                remediation='Add autocomplete="off" to password inputs',
                evidence={'form': form_info, 'vulnerable_inputs': password_inputs}
            )
    
    # Log all forms found
    if form_data_list:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title=f'Forms discovered: {len(form_data_list)} total',
            description=f'Extracted complete details for {len(form_data_list)} forms including all input fields',
            url=scanner.target_url,
            remediation='Review all forms for proper security controls',
            evidence={
                'type': 'forms',
                'count': len(form_data_list),
                'forms': form_data_list
            }
        )

def _extract_input_fields(scanner, soup):
    """Extract all input fields including hidden ones"""
    hidden_inputs = soup.find_all('input', {'type': 'hidden'})
    hidden_fields = []
    sensitive_fields = []
    
    for hidden in hidden_inputs:
        name = hidden.get('name', '')
        value = hidden.get('value', '')
        
        hidden_fields.append({
            'name': name,
            'value': value,
            'length': len(value) if value else 0
        })
        
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
                sensitive_fields.append({
                    'name': name,
                    'value': value,
                    'type': data_type
                })
    
    # Report all hidden fields
    if hidden_fields:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title=f'Hidden input fields discovered',
            description=f'Found {len(hidden_fields)} hidden input field(s) in forms',
            url=scanner.target_url,
            remediation='Review hidden fields for sensitive data exposure',
            evidence={
                'type': 'hidden_inputs',
                'count': len(hidden_fields),
                'fields': hidden_fields
            }
        )
    
    # Report sensitive hidden fields separately
    if sensitive_fields:
        scanner.add_finding(
            severity='HIGH',
            category='Data Extraction',
            title=f'Sensitive data in hidden fields',
            description=f'Found {len(sensitive_fields)} hidden input(s) containing sensitive data',
            url=scanner.target_url,
            remediation='Never store sensitive data in hidden fields. Use server-side session storage.',
            evidence={
                'type': 'sensitive_hidden_inputs',
                'count': len(sensitive_fields),
                'fields': sensitive_fields
            }
        )

def _extract_metadata(scanner, soup):
    """Extract all metadata from page"""
    meta_tags = soup.find_all('meta')
    metadata_list = []
    
    for meta in meta_tags:
        name = meta.get('name', '') or meta.get('property', '')
        content = meta.get('content', '')
        
        if content and len(content) > 10:
            metadata_list.append({
                'name': name,
                'content': content
            })
    
    if metadata_list:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title=f'Metadata extracted',
            description=f'Discovered {len(metadata_list)} metadata tag(s) with content',
            url=scanner.target_url,
            remediation='Review metadata for sensitive information disclosure',
            evidence={
                'type': 'metadata',
                'count': len(metadata_list),
                'tags': metadata_list
            }
        )

def _extract_endpoints(scanner, soup, base_url):
    """Extract all links and resources from page"""
    links = soup.find_all(['a', 'link', 'script', 'img', 'iframe'])
    endpoints = set()
    api_endpoints = []
    
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
                api_endpoints.append(endpoint)
                break
    
    # Report all discovered links and resources
    if endpoints:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title=f'Links and resources discovered',
            description=f'Found {len(endpoints)} unique links, scripts, and resources on page',
            url=scanner.target_url,
            remediation='Review all linked resources for security implications',
            evidence={
                'type': 'discovered_links',
                'count': len(endpoints),
                'endpoints': list(endpoints)[:100]  # Limit to 100 to avoid overwhelming
            }
        )
    
    # Report sensitive API/admin endpoints separately
    if api_endpoints:
        scanner.add_finding(
            severity='MEDIUM',
            category='Data Extraction',
            title=f'API/Admin endpoints discovered',
            description=f'Found {len(api_endpoints)} potential sensitive endpoint(s)',
            url=scanner.target_url,
            remediation='Ensure sensitive endpoints require authentication and authorization',
            evidence={
                'type': 'sensitive_endpoints',
                'count': len(api_endpoints),
                'endpoints': api_endpoints
            }
        )

def _extract_contact_info(scanner, text):
    """Extract email addresses and phone numbers"""
    # Email addresses
    emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))
    
    if emails:
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title='Email addresses found',
            description=f'Discovered {len(emails)} email addresses in page source',
            url=scanner.target_url,
            remediation='Consider using contact forms instead of exposing email addresses',
            evidence={
                'type': 'emails',
                'count': len(emails),
                'items': list(emails)
            }
        )
    
    # Phone numbers (basic patterns)
    phones = set(re.findall(r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b', text))
    
    if phones:
        phone_numbers = [f"({p[0]}) {p[1]}-{p[2]}" for p in phones]
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title='Phone numbers found',
            description=f'Discovered {len(phones)} phone numbers in page source',
            url=scanner.target_url,
            remediation='Consider using callback forms to protect phone numbers from scraping',
            evidence={
                'type': 'phones',
                'count': len(phones),
                'items': phone_numbers
            }
        )

def _extract_comment_data(scanner, soup):
    """Extract data from HTML comments"""
    comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
    sensitive_comments = []
    
    for comment in comments:
        comment_text = str(comment).strip()
        if len(comment_text) > 20:
            # Check for credentials in comments
            if any(keyword in comment_text.lower() for keyword in ['password', 'key', 'secret', 'token', 'credential']):
                sensitive_comments.append(comment_text)
    
    if sensitive_comments:
        scanner.add_finding(
            severity='HIGH',
            category='Data Extraction',
            title='Sensitive data in HTML comments',
            description=f'Found {len(sensitive_comments)} HTML comments containing sensitive keywords',
            url=scanner.target_url,
            remediation='Remove sensitive information from HTML comments before deployment',
            evidence={
                'type': 'sensitive_comments',
                'count': len(sensitive_comments),
                'items': [c[:200] for c in sensitive_comments]  # Truncate long comments
            }
        )

def _extract_js_data(scanner, soup, base_url):
    """Extract JavaScript variables and configuration objects"""
    scripts = soup.find_all('script')
    js_credentials = []
    
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
                        js_credentials.append({
                            'variable': var_name,
                            'value': var_value,
                            'length': len(var_value)
                        })
    
    if js_credentials:
        scanner.add_finding(
            severity='HIGH',
            category='Data Extraction',
            title='Hardcoded credentials in JavaScript',
            description=f'Found {len(js_credentials)} hardcoded credentials/keys in JavaScript code',
            url=scanner.target_url,
            remediation='Never hardcode credentials in client-side code. Use server-side API calls and environment variables.',
            evidence={
                'type': 'javascript_credentials',
                'count': len(js_credentials),
                'credentials': js_credentials[:20]  # Show up to 20
            }
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
            scanner.add_finding(
                severity='CRITICAL' if 'secret' in cred_type.lower() else 'HIGH',
                category='Data Extraction',
                title=f'Exposed {cred_type}',
                description=f'Found {len(matches)} exposed {cred_type.lower()}(s) in page source',
                url=scanner.target_url,
                remediation='IMMEDIATELY revoke these credentials, rotate keys, and use environment variables or secrets management.',
                evidence={
                    'type': 'credentials',
                    'credential_type': cred_type,
                    'count': len(matches),
                    'tokens': list(matches)[:10]  # Show up to 10 matches
                }
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
    
    if endpoints:
        endpoint_list = list(endpoints)
        scanner.add_finding(
            severity='INFO',
            category='Data Extraction',
            title='API endpoints discovered in JavaScript',
            description=f'Found {len(endpoints)} API endpoints exposed in client-side code',
            url=scanner.target_url,
            remediation='Ensure all API endpoints implement proper authentication, authorization, and rate limiting',
            evidence={
                'type': 'api_endpoints',
                'count': len(endpoints),
                'endpoints': endpoint_list
            }
        )
