"""
API Endpoint Discovery and Testing Module
Discovers and tests API endpoints for common vulnerabilities
"""

import requests
import re
import json
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

def discover_and_test_apis(scanner):
    """
    Discover API endpoints and test for common vulnerabilities
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Discover API endpoints
        endpoints = _discover_api_endpoints(scanner, response)
        
        # Test discovered endpoints
        for endpoint in endpoints:
            _test_api_endpoint(scanner, endpoint)
        
        # Test for common API vulnerabilities
        _test_graphql_introspection(scanner)
        _test_rest_api_discovery(scanner)
        
    except Exception as e:
        print(f"API testing error: {e}")

def _discover_api_endpoints(scanner, response):
    """Discover API endpoints from JavaScript and HTML"""
    endpoints = set()
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Extract from JavaScript
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string:
            # Common API call patterns
            patterns = [
                r'["\']([/]api[^"\']*)["\']',
                r'["\']([/]rest[^"\']*)["\']',
                r'["\']([/]v\d+[^"\']*)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.\w+\(["\']([^"\']+)["\']',
                r'\$\.ajax\(["\']url["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']https?://[^"\']+/(api|rest)[^"\']*["\']',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, script.string, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match and len(match) > 3:
                        full_url = urljoin(scanner.target_url, match)
                        endpoints.add(full_url)
    
    # Look for data attributes
    for tag in soup.find_all(attrs={"data-api": True}):
        endpoint = tag.get('data-api')
        if endpoint:
            endpoints.add(urljoin(scanner.target_url, endpoint))
    
    for tag in soup.find_all(attrs={"data-url": True}):
        endpoint = tag.get('data-url')
        if endpoint and isinstance(endpoint, str) and ('api' in endpoint.lower() or 'rest' in endpoint.lower()):
            endpoints.add(urljoin(scanner.target_url, endpoint))
    
    return endpoints

def _test_api_endpoint(scanner, endpoint):
    """Test individual API endpoint for vulnerabilities"""
    try:
        # Test for lack of authentication
        response = requests.get(endpoint, timeout=10, verify=False)
        
        if response.status_code == 200:
            # Check if it returns sensitive data
            try:
                data = response.json()
                if isinstance(data, (dict, list)) and data:
                    scanner.add_finding(
                        severity='HIGH',
                        category='API Security',
                        title='Unauthenticated API endpoint',
                        description=f'API endpoint accessible without authentication: {endpoint}',
                        url=endpoint,
                        remediation='Implement authentication for all API endpoints'
                    )
            except:
                pass
        
        # Test for CORS misconfiguration
        headers = {'Origin': 'https://evil.com'}
        response = requests.get(endpoint, headers=headers, timeout=10, verify=False)
        
        if response.headers.get('Access-Control-Allow-Origin') == '*':
            scanner.add_finding(
                severity='MEDIUM',
                category='API Security',
                title='Overly permissive CORS policy',
                description=f'API allows requests from any origin: {endpoint}',
                url=endpoint,
                remediation='Restrict CORS to specific trusted domains'
            )
        
        if response.headers.get('Access-Control-Allow-Origin') == 'https://evil.com':
            scanner.add_finding(
                severity='HIGH',
                category='API Security',
                title='CORS policy reflects arbitrary origins',
                description=f'API reflects any origin in CORS header: {endpoint}',
                url=endpoint,
                remediation='Use a whitelist of allowed origins instead of reflection'
            )
        
        # Test for excessive data exposure
        if response.status_code == 200:
            sensitive_keywords = ['password', 'token', 'secret', 'api_key', 'private', 'ssn', 'credit_card']
            response_lower = response.text.lower()
            
            found_keywords = [kw for kw in sensitive_keywords if kw in response_lower]
            if found_keywords:
                scanner.add_finding(
                    severity='HIGH',
                    category='API Security',
                    title='API response contains sensitive keywords',
                    description=f'API may expose sensitive data. Keywords found: {", ".join(found_keywords)}',
                    url=endpoint,
                    remediation='Review API responses and filter sensitive data'
                )
        
        # Test for verb tampering
        _test_verb_tampering(scanner, endpoint)
        
    except Exception as e:
        pass

def _test_verb_tampering(scanner, endpoint):
    """Test if API endpoint behavior changes with different HTTP methods"""
    methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
    
    responses = {}
    for method in methods:
        try:
            response = requests.request(method, endpoint, timeout=5, verify=False)
            responses[method] = response.status_code
        except:
            responses[method] = None
    
    # Check if dangerous methods are allowed
    dangerous_allowed = []
    for method in ['PUT', 'PATCH', 'DELETE']:
        if responses.get(method) not in [None, 404, 405, 403]:
            dangerous_allowed.append(method)
    
    if dangerous_allowed:
        scanner.add_finding(
            severity='MEDIUM',
            category='API Security',
            title='Dangerous HTTP methods allowed',
            description=f'API endpoint allows: {", ".join(dangerous_allowed)} at {endpoint}',
            url=endpoint,
            remediation='Restrict HTTP methods to only those required. Implement proper authorization.'
        )

def _test_graphql_introspection(scanner):
    """Test for GraphQL introspection enabled"""
    graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/graphiql']
    
    introspection_query = {
        'query': '{ __schema { types { name } } }'
    }
    
    for path in graphql_paths:
        test_url = urljoin(scanner.target_url, path)
        try:
            response = requests.post(
                test_url,
                json=introspection_query,
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200 and '__schema' in response.text:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    types_count = len(data['data']['__schema']['types'])
                    
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='API Security',
                        title='GraphQL introspection enabled',
                        description=f'GraphQL schema exposed via introspection ({types_count} types): {test_url}',
                        url=test_url,
                        remediation='Disable GraphQL introspection in production environments'
                    )
        except:
            pass

def _test_rest_api_discovery(scanner):
    """Test for API documentation and discovery endpoints"""
    api_doc_paths = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/api/docs',
        '/api/documentation',
        '/swagger',
        '/swagger.json',
        '/swagger/v1/swagger.json',
        '/api-docs',
        '/api/swagger.json',
        '/v1/swagger.json',
        '/v2/swagger.json',
        '/openapi.json',
        '/openapi.yaml',
        '/api/openapi.json',
    ]
    
    for path in api_doc_paths:
        test_url = urljoin(scanner.target_url, path)
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                # Check if it's API documentation
                is_api_doc = False
                endpoints_found = 0
                
                if 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
                    is_api_doc = True
                    try:
                        spec = response.json()
                        if 'paths' in spec:
                            endpoints_found = len(spec['paths'])
                    except:
                        pass
                
                if is_api_doc:
                    severity = 'MEDIUM' if endpoints_found > 5 else 'LOW'
                    scanner.add_finding(
                        severity=severity,
                        category='API Security',
                        title='API documentation exposed',
                        description=f'API documentation accessible at {test_url} ({endpoints_found} endpoints documented)',
                        url=test_url,
                        remediation='Restrict API documentation to authenticated users or internal networks'
                    )
        except:
            pass

def _test_api_rate_limiting(scanner, endpoint):
    """Test if API has rate limiting"""
    try:
        # Make multiple rapid requests
        responses = []
        for _ in range(10):
            response = requests.get(endpoint, timeout=5, verify=False)
            responses.append(response.status_code)
        
        # If all requests succeed, rate limiting might not be implemented
        if all(status == 200 for status in responses):
            scanner.add_finding(
                severity='LOW',
                category='API Security',
                title='API may lack rate limiting',
                description=f'No rate limiting detected on endpoint: {endpoint}',
                url=endpoint,
                remediation='Implement rate limiting to prevent abuse and DoS attacks'
            )
        
        # Check for rate limit headers
        response = requests.get(endpoint, timeout=5, verify=False)
        rate_headers = ['X-RateLimit-Limit', 'X-Rate-Limit', 'RateLimit-Limit']
        
        has_rate_headers = any(header in response.headers for header in rate_headers)
        if not has_rate_headers:
            scanner.add_finding(
                severity='INFO',
                category='API Security',
                title='No rate limit headers detected',
                description=f'API does not expose rate limit information: {endpoint}',
                url=endpoint,
                remediation='Consider adding rate limit headers for transparency'
            )
        
    except:
        pass
