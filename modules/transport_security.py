"""
Transport Security Checker Module - State of the Art
Comprehensive transport-level security analysis
"""

import requests
import urllib.parse
import re
from bs4 import BeautifulSoup

def check_transport_security(scanner):
    """
    Perform comprehensive transport security checks
    Analyzes HTTPS usage, redirects, mixed content, and protocol security
    """
    
    parsed_url = urllib.parse.urlparse(scanner.target_url)
    
    # ==================== HTTPS USAGE ====================
    if parsed_url.scheme == 'http':
        # Try to access HTTPS version
        https_url = scanner.target_url.replace('http://', 'https://', 1)
        try:
            https_response = scanner.session.get(https_url, timeout=5, allow_redirects=False, verify=True)
            if https_response.status_code < 400:
                scanner.add_finding(
                    severity='HIGH',
                    category='Transport Security',
                    title='HTTPS available but not enforced',
                    description='Site is accessible over HTTP but HTTPS is available. All traffic should be encrypted.',
                    url=scanner.target_url,
                    remediation='Configure server to redirect all HTTP traffic to HTTPS with a 301 or 308 redirect'
                )
        except requests.exceptions.SSLError:
            scanner.add_finding(
                severity='HIGH',
                category='Transport Security',
                title='HTTPS has SSL/TLS errors',
                description='HTTPS is available but has certificate or TLS configuration errors',
                url=scanner.target_url,
                remediation='Fix SSL/TLS configuration and certificate issues'
            )
        except:
            scanner.add_finding(
                severity='HIGH',
                category='Transport Security',
                title='HTTPS not available',
                description='Site is only accessible over insecure HTTP. All traffic is unencrypted.',
                url=scanner.target_url,
                remediation='Enable HTTPS with a valid SSL/TLS certificate from a trusted CA'
            )
    else:
        # Site uses HTTPS
        scanner.add_finding(
            severity='INFO',
            category='Transport Security',
            title='HTTPS is enabled',
            description='Site is accessed over HTTPS',
            url=scanner.target_url,
            remediation=''
        )
    
    # ==================== HTTP TO HTTPS REDIRECT ====================
    if parsed_url.scheme == 'http':
        try:
            redirect_response = scanner.session.get(scanner.target_url, allow_redirects=False, timeout=5)
            if redirect_response.status_code in [301, 302, 303, 307, 308]:
                location = redirect_response.headers.get('Location', '')
                if location.startswith('https://'):
                    redirect_type = 'permanent' if redirect_response.status_code in [301, 308] else 'temporary'
                    scanner.add_finding(
                        severity='INFO',
                        category='Transport Security',
                        title=f'HTTP to HTTPS redirect ({redirect_type})',
                        description=f'HTTP properly redirects to HTTPS with {redirect_response.status_code} redirect',
                        url=scanner.target_url,
                        remediation='Ensure redirect is permanent (301 or 308) not temporary'
                    )
                else:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Transport Security',
                        title='HTTP redirects but not to HTTPS',
                        description=f'HTTP redirects to {location} (not HTTPS)',
                        url=scanner.target_url,
                        remediation='Redirect should target HTTPS URL'
                    )
            else:
                scanner.add_finding(
                    severity='HIGH',
                    category='Transport Security',
                    title='HTTP does not redirect to HTTPS',
                    description='HTTP version does not redirect to HTTPS, allowing insecure access',
                    url=scanner.target_url,
                    remediation='Configure HTTP to HTTPS redirect (301 permanent redirect recommended)'
                )
        except:
            pass
    
    # ==================== MIXED CONTENT ====================
    try:
        response = scanner.session.get(scanner.target_url, timeout=10, allow_redirects=True)
        
        if parsed_url.scheme == 'https' or response.url.startswith('https://'):
            # Look for HTTP resources loaded from HTTPS page
            http_matches = re.findall(r'http://[^"\'\s<>]+', response.text, re.IGNORECASE)
            
            if http_matches:
                unique_http = list(set(http_matches))[:10]  # Limit to 10 examples
                
                # Categorize mixed content
                passive_content = [url for url in unique_http if any(ext in url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.ttf'])]
                active_content = [url for url in unique_http if any(ext in url.lower() for ext in ['.js', '.swf'])]
                
                if active_content:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Transport Security',
                        title='Active mixed content detected',
                        description=f'HTTPS page loads JavaScript/active content over HTTP: {active_content[0]}',
                        url=scanner.target_url,
                        remediation='Load all scripts and active content over HTTPS'
                    )
                
                if passive_content:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Transport Security',
                        title='Passive mixed content detected',
                        description=f'HTTPS page loads images/styles over HTTP: {passive_content[0]} - Can be rewritten by attackers',
                        url=scanner.target_url,
                        remediation='Load all resources over HTTPS or use protocol-relative URLs'
                    )
                
                if not active_content and not passive_content and unique_http:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Transport Security',
                        title='Mixed content detected',
                        description=f'HTTPS page references HTTP resources: {unique_http[0]} - CRITICAL security risk',
                        url=scanner.target_url,
                        remediation='Ensure all resources are loaded over HTTPS'
                    )
        
        # ==================== INSECURE EXTERNAL LINKS ====================
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', href=True)
        insecure_external_links = []
        
        for link in links:
            href = link['href']
            if href.startswith('http://') and scanner.domain not in href:
                insecure_external_links.append(href)
        
        if insecure_external_links and len(insecure_external_links) > 5:
            scanner.add_finding(
                severity='LOW',
                category='Transport Security',
                title='Multiple insecure external links',
                description=f'Page contains {len(insecure_external_links)} links to external HTTP resources',
                url=scanner.target_url,
                remediation='Update external links to use HTTPS where possible'
            )
        
        # ==================== UPGRADE-INSECURE-REQUESTS ====================
        if parsed_url.scheme == 'https':
            # Check if CSP upgrade-insecure-requests is used
            csp_header = response.headers.get('Content-Security-Policy', '').lower()
            if 'upgrade-insecure-requests' not in csp_header:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Transport Security',
                    title='upgrade-insecure-requests directive not used',
                    description='CSP does not include upgrade-insecure-requests to auto-upgrade HTTP to HTTPS',
                    url=scanner.target_url,
                    remediation='Add "upgrade-insecure-requests" directive to Content-Security-Policy'
                )
        
        # ==================== HSTS MAX-AGE ANALYSIS ====================
        hsts_header = response.headers.get('Strict-Transport-Security', '')
        if hsts_header:
            # Parse max-age value
            max_age_match = re.search(r'max-age=(\d+)', hsts_header, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                
                # Check if max-age is too short (less than 1 year = 31536000 seconds)
                if max_age < 31536000:
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Transport Security',
                        title='HSTS max-age too short',
                        description=f'HSTS max-age is {max_age} seconds ({max_age // 86400} days). Recommended minimum is 31536000 seconds (1 year).',
                        url=scanner.target_url,
                        remediation='Increase HSTS max-age to at least 31536000 (1 year), ideally 63072000 (2 years)'
                    )
                
                # Check for very short max-age (less than 30 days)
                if max_age < 2592000:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Transport Security',
                        title='HSTS max-age critically short',
                        description=f'HSTS max-age is only {max_age // 86400} days. This provides insufficient protection against SSL stripping attacks.',
                        url=scanner.target_url,
                        remediation='CRITICAL: Increase HSTS max-age to at least 31536000 (1 year)'
                    )
        
        # ==================== REDIRECT CHAIN ANALYSIS ====================
        # Check for multiple redirects (performance and security issue)
        try:
            redirect_response = scanner.session.get(scanner.target_url, allow_redirects=True, timeout=5)
            if hasattr(redirect_response, 'history') and len(redirect_response.history) > 1:
                scanner.add_finding(
                    severity='LOW',
                    category='Transport Security',
                    title='Multiple redirects detected',
                    description=f'URL goes through {len(redirect_response.history)} redirects before reaching final destination. This may slow down page load and create attack opportunities.',
                    url=scanner.target_url,
                    remediation='Reduce redirect chain to a single 301/308 redirect from HTTP to HTTPS'
                )
        except:
            pass
        
    except requests.RequestException:
        pass  # Connection errors reported elsewhere
    except Exception as e:
        pass
