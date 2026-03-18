"""
Cookie and Session Security Checker - State of the Art
Comprehensive cookie security analysis
"""

import requests
from http.cookies import SimpleCookie

def check_cookie_security(scanner):
    """
    Perform comprehensive cookie security analysis
    Checks for Secure, HttpOnly, SameSite, and other cookie attributes
    """
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Get all Set-Cookie headers (response.cookies only gets parsed cookies)
        set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
        
        # Also check the raw header if get_list doesn't work
        if not set_cookie_headers and 'Set-Cookie' in response.headers:
            set_cookie_value = response.headers.get('Set-Cookie', '')
            if set_cookie_value:
                set_cookie_headers = [set_cookie_value]
        
        if not set_cookie_headers and not response.cookies:
            # No cookies set - this is actually secure!
            return
        
        # Analyze each cookie
        all_cookies = []
        
        # From response.cookies
        for cookie_name, cookie_value in response.cookies.items():
            cookie_obj = response.cookies.get(cookie_name)
            all_cookies.append({
                'name': cookie_name,
                'secure': cookie_obj.secure if hasattr(cookie_obj, 'secure') else False,
                'httponly': cookie_obj.has_nonstandard_attr('HttpOnly') if hasattr(cookie_obj, 'has_nonstandard_attr') else False,
                'samesite': cookie_obj.get('samesite', None) if hasattr(cookie_obj, 'get') else None,
                'domain': cookie_obj.domain if hasattr(cookie_obj, 'domain') else None,
                'path': cookie_obj.path if hasattr(cookie_obj, 'path') else None,
            })
        
        # Analyze cookies from Set-Cookie headers
        for cookie_header in set_cookie_headers:
            cookie_header_lower = cookie_header.lower()
            
            # Extract cookie name
            cookie_name = cookie_header.split('=')[0].strip() if '=' in cookie_header else 'unknown'
            
            # Check security attributes
            has_secure = 'secure' in cookie_header_lower
            has_httponly = 'httponly' in cookie_header_lower
            has_samesite = 'samesite' in cookie_header_lower
            
            # Cookie missing Secure flag
            if not has_secure:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" missing Secure flag',
                    description=f'Cookie "{cookie_name}" does not have the Secure flag and can be transmitted over unencrypted connections',
                    url=scanner.target_url,
                    remediation='Add Secure flag to all cookies, especially session cookies'
                )
            
            # Cookie missing HttpOnly flag
            if not has_httponly:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" missing HttpOnly flag',
                    description=f'Cookie "{cookie_name}" does not have the HttpOnly flag and can be accessed via JavaScript (XSS risk)',
                    url=scanner.target_url,
                    remediation='Add HttpOnly flag to session and authentication cookies'
                )
            
            # Cookie missing SameSite attribute
            if not has_samesite:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" missing SameSite attribute',
                    description=f'Cookie "{cookie_name}" does not have the SameSite attribute, making it vulnerable to CSRF attacks',
                    url=scanner.target_url,
                    remediation='Add SameSite=Strict or SameSite=Lax attribute to cookies'
                )
            else:
                # Check if SameSite is set to None
                if 'samesite=none' in cookie_header_lower:
                    scanner.add_finding(
                        severity='LOW',
                        category='Session / Cookies',
                        title=f'Cookie "{cookie_name}" has SameSite=None',
                        description=f'Cookie "{cookie_name}" uses SameSite=None which disables CSRF protection',
                        url=scanner.target_url,
                        remediation='Use SameSite=Strict or SameSite=Lax unless cross-site usage is absolutely required'
                    )
            
            # Check for __Host- prefix
            if cookie_name.startswith('__Host-'):
                # __Host- cookies must have specific attributes
                if not has_secure:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Session / Cookies',
                        title=f'__Host- prefixed cookie without Secure flag',
                        description=f'Cookie "{cookie_name}" uses __Host- prefix but lacks required Secure flag',
                        url=scanner.target_url,
                        remediation='Ensure __Host- prefixed cookies have Secure flag, Path=/, and no Domain attribute'
                    )
            
            # Check for __Secure- prefix
            if cookie_name.startswith('__Secure-'):
                if not has_secure:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Session / Cookies',
                        title=f'__Secure- prefixed cookie without Secure flag',
                        description=f'Cookie "{cookie_name}" uses __Secure- prefix but lacks required Secure flag',
                        url=scanner.target_url,
                        remediation='Ensure __Secure- prefixed cookies have the Secure flag'
                    )
        
        # Check for session cookie detection
        suspicious_cookie_names = ['session', 'sess', 'phpsessid', 'jsessionid', 'asp.net_sessionid', 'token', 'auth']
        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split('=')[0].strip().lower() if '=' in cookie_header else ''
            if any(name in cookie_name for name in suspicious_cookie_names):
                cookie_header_lower = cookie_header.lower()
                if 'secure' not in cookie_header_lower or 'httponly' not in cookie_header_lower:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Session / Cookies',
                        title=f'Session cookie "{cookie_name}" lacks security flags',
                        description=f'Session/authentication cookie appears to be missing critical security flags',
                        url=scanner.target_url,
                        remediation='Session cookies must have Secure and HttpOnly flags at minimum'
                    )
        
    except requests.RequestException as e:
        pass  # Connection issues already reported elsewhere
