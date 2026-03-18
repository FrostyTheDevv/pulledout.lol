"""
SawSap - Ultra-Granular Cookie Analysis
Every cookie and every cookie attribute gets individual security findings
Target: 5-10 findings per cookie
"""

import requests

def ultra_granular_cookie_scan(scanner):
    """
    Analyze every single cookie individually
    Each cookie attribute (Secure, HttpOnly, SameSite, Domain, Path, Expires) = separate finding
    """
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Get all cookies (both from Set-Cookie headers and session)
        cookies = {}
        
        # From response headers
        if 'Set-Cookie' in response.headers:
            set_cookie_headers = response.headers.get('Set-Cookie')
            if isinstance(set_cookie_headers, str):
                set_cookie_headers = [set_cookie_headers]
            
            for cookie_header in set_cookie_headers:
                parts = cookie_header.split(';')
                if parts:
                    name_value = parts[0].strip()
                    if '=' in name_value:
                        cookie_name = name_value.split('=')[0].strip()
                        cookies[cookie_name] = cookie_header
        
        # From session cookies
        for cookie in scanner.session.cookies:
            if cookie.name not in cookies:
                cookie_str = f"{cookie.name}={cookie.value}"
                if cookie.secure:
                    cookie_str += "; Secure"
                if cookie.has_nonstandard_attr('HttpOnly'):
                    cookie_str += "; HttpOnly"
                cookies[cookie.name] = cookie_str
        
        if not cookies:
            scanner.add_finding(
                severity='INFO',
                category='Session / Cookies',
                title='No cookies detected',
                description='No cookies set by this page',
                url=scanner.target_url,
                remediation=''
            )
            return
        
        # Analyze each cookie individually
        for cookie_name, cookie_value in cookies.items():
            cookie_lower = cookie_value.lower()
            
            # Determine if cookie appears to be a session cookie
            is_session_cookie = any(keyword in cookie_name.lower() for keyword in [
                'session', 'sess', 'sid', 'token', 'auth', 'login', 'user', 'jwt'
            ])
            
            # Check 1: Missing Secure flag (MEDIUM for session, LOW for others)
            if 'secure' not in cookie_lower:
                severity = 'MEDIUM' if is_session_cookie else 'LOW'
                scanner.add_finding(
                    severity=severity,
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" missing Secure flag',
                    description=f'Cookie can be transmitted over unencrypted HTTP connections',
                    url=scanner.target_url,
                    remediation='Add Secure flag to ensure cookie is only sent over HTTPS'
                )
            
            # Check 2: Missing HttpOnly flag (MEDIUM for session, LOW for others)
            if 'httponly' not in cookie_lower:
                severity = 'MEDIUM' if is_session_cookie else 'LOW'
                scanner.add_finding(
                    severity=severity,
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" missing HttpOnly flag',
                    description=f'Cookie accessible via JavaScript - vulnerable to XSS theft',
                    url=scanner.target_url,
                    remediation='Add HttpOnly flag to prevent JavaScript access'
                )
            
            # Check 3: Missing SameSite attribute (MEDIUM)
            if 'samesite' not in cookie_lower:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" missing SameSite attribute',
                    description=f'Cookie vulnerable to CSRF attacks without SameSite protection',
                    url=scanner.target_url,
                    remediation='Add SameSite=Strict or SameSite=Lax attribute'
                )
            else:
                # Check SameSite value
                if 'samesite=none' in cookie_lower:
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Session / Cookies',
                        title=f'Cookie "{cookie_name}" uses SameSite=None',
                        description=f'Cookie explicitly allows cross-site usage - CSRF risk',
                        url=scanner.target_url,
                        remediation='Use SameSite=Strict or SameSite=Lax if possible'
                    )
            
            # Check 4: Missing expiration (INFO for non-session cookies)
            if not is_session_cookie and 'expires' not in cookie_lower and 'max-age' not in cookie_lower:
                scanner.add_finding(
                    severity='INFO',
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" has no expiration',
                    description=f'Cookie will persist as a session cookie',
                    url=scanner.target_url,
                    remediation='Consider adding Expires or Max-Age for persistent cookies'
                )
            
            # Check 5: Long expiration for session cookies (MEDIUM)
            if is_session_cookie:
                if 'max-age' in cookie_lower:
                    try:
                        max_age_part = [p for p in cookie_value.split(';') if 'max-age' in p.lower()][0]
                        max_age = int(max_age_part.split('=')[1].strip())
                        # More than 24 hours (86400 seconds)
                        if max_age > 86400:
                            scanner.add_finding(
                                severity='LOW',
                                category='Session / Cookies',
                                title=f'Session cookie "{cookie_name}" has long expiration',
                                description=f'Session cookie expires in {max_age // 3600} hours (recommended: < 24 hours)',
                                url=scanner.target_url,
                                remediation='Reduce session cookie lifetime for better security'
                            )
                    except:
                        pass
            
            # Check 6: Overly broad Domain (LOW)
            if 'domain=' in cookie_lower:
                try:
                    domain_part = [p for p in cookie_value.split(';') if 'domain=' in p.lower()][0]
                    domain = domain_part.split('=')[1].strip()
                    if domain.startswith('.'):
                        scanner.add_finding(
                            severity='LOW',
                            category='Session / Cookies',
                            title=f'Cookie "{cookie_name}" uses broad domain scope',
                            description=f'Cookie domain "{domain}" applies to all subdomains',
                            url=scanner.target_url,
                            remediation='Limit cookie scope to specific domain if possible'
                        )
                except:
                    pass
            
            # Check 7: Overly broad Path (INFO)
            if 'path=/' in cookie_lower:
                scanner.add_finding(
                    severity='INFO',
                    category='Session / Cookies',
                    title=f'Cookie "{cookie_name}" uses broad path scope',
                    description=f'Cookie applies to entire site (path=/)',
                    url=scanner.target_url,
                    remediation='Consider limiting cookie to specific paths if appropriate'
                )
            
            # Check 8: Cookie name reveals technology (INFO)
            tech_patterns = {
                'phpsessid': 'PHP',
                'jsessionid': 'Java/JSP',
                'asp.net_sessionid': 'ASP.NET',
                'cfid': 'ColdFusion',
                'cftoken': 'ColdFusion',
            }
            
            for pattern, tech in tech_patterns.items():
                if pattern in cookie_name.lower():
                    scanner.add_finding(
                        severity='INFO',
                        category='Session / Cookies',
                        title=f'Cookie name reveals technology: {tech}',
                        description=f'Cookie "{cookie_name}" indicates server uses {tech}',
                        url=scanner.target_url,
                        remediation='Consider renaming session cookies to avoid revealing technology stack'
                    )
                    break
    
    except Exception as e:
        pass  # Silently fail on cookie analysis errors
