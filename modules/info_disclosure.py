"""
Information Disclosure Checker Module - State of the Art
Comprehensive information leakage and sensitive data exposure detection
"""

import requests
from bs4 import BeautifulSoup
import re

def check_information_disclosure(scanner):
    """
    Perform comprehensive information disclosure checks
    Detects server headers, error messages, comments, emails, and version information
    """
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Note: Server header and other technology disclosure headers (X-Powered-By, etc.)
        # are now checked in comprehensive_header_analysis.py to avoid duplicates
        
        # ==================== CLOUDFLARE DETECTION ====================
        if 'cf-ray' in headers or 'cloudflare' in headers.get('server', '').lower():
            scanner.add_finding(
                severity='INFO',
                category='Information Disclosure',
                title='Cloudflare CDN detected',
                description='Site is using Cloudflare CDN/protection',
                url=scanner.target_url,
                remediation=''
            )
        
        # ==================== DIRECTORY LISTING ====================
        directory_patterns = [
            r'<title>Index of /',
            r'Directory listing for',
            r'<h1>Index of',
            r'Parent Directory</a>',
            r'<pre>',  # Common in default directory listings
        ]
        
        for pattern in directory_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Information Disclosure',
                    title='Directory listing may be enabled',
                    description='Server appears to show directory contents',
                    url=scanner.target_url,
                    remediation='Disable directory listing in web server configuration'
                )
                break
        
        # ==================== ERROR MESSAGES ====================
        error_patterns = {
            r'MySQL.*(error|warning)': 'MySQL error message',
            r'PostgreSQL.*error': 'PostgreSQL error message',
            r'ORA-\d{5}': 'Oracle database error',
            r'Microsoft SQL (Native Client|Server)': 'MSSQL error message',
            r'SQLite.*error': 'SQLite error message',
            r'Warning:.*mysqli?_': 'PHP MySQL warning',
            r'Fatal error:.*in\s+\S+\s+on line \d+': 'PHP fatal error with file path',
            r'Warning:.*in\s+\S+\s+on line \d+': 'PHP warning with file path',
            r'Notice:.*in\s+\S+\s+on line \d+': 'PHP notice with file path',
            r'Stack trace:': 'Stack trace exposed',
            r'Exception in thread': 'Java exception exposed',
            r'Traceback \(most recent call last\):': 'Python traceback exposed',
            r'at\s+[\w\\.]+\([\w\\.]+:\d+\)': 'Stack trace with line numbers',
            r'SQLSTATE\[\w+\]': 'SQL error state exposed',
        }
        
        for pattern, description in error_patterns.items():
            if re.search(pattern, response.text, re.IGNORECASE):
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Information Disclosure',
                    title='Error message disclosure',
                    description=f'{description} found in response',
                    url=scanner.target_url,
                    remediation='Configure custom error pages. Display generic errors to users, log details server-side.'
                )
                break
        
        # ==================== HTML COMMENTS ====================
        soup = BeautifulSoup(response.content, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, type('')) and text.strip().startswith('<!--'))
        
        sensitive_comment_patterns = {
            r'password': 'Password reference',
            r'TODO|FIXME|HACK|XXX|BUG': 'Developer notes',
            r'api[_-]?key|secret[_-]?key': 'API key reference',
            r'admin|administrator': 'Admin reference',
            r'username|user[_-]?name': 'Username reference',
            r'debug|test|staging': 'Debug/test reference',
        }
        
        found_comment_issues = []
        for comment in comments:
            comment_text = str(comment).strip()
            for pattern, description in sensitive_comment_patterns.items():
                if re.search(pattern, comment_text, re.IGNORECASE):
                    found_comment_issues.append({
                        'type': description,
                        'comment': comment_text[:200]  # Truncate to 200 chars
                    })
                    break
        
        if found_comment_issues:
            scanner.add_finding(
                severity='LOW',
                category='Information Disclosure',
                title='Sensitive information in HTML comments',
                description=f'Found {len(found_comment_issues)} HTML comments with sensitive information',
                url=scanner.target_url,
                remediation='Remove sensitive comments before deploying to production',
                evidence={
                    'type': 'html_comments',
                    'count': len(found_comment_issues),
                    'comments': found_comment_issues
                }
            )
        
        # ==================== EMAIL HARVESTING ====================
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, response.text)
        
        if emails:
            unique_emails = list(set(emails))
            scanner.add_finding(
                severity='INFO',
                category='Information Disclosure',
                title='Email addresses exposed in source',
                description=f'Found {len(unique_emails)} unique email address(es) exposed in HTML source',
                url=scanner.target_url,
                remediation='Consider obfuscating email addresses or using contact forms to prevent harvesting by bots',
                evidence={
                    'type': 'emails',
                    'count': len(unique_emails),
                    'emails': unique_emails
                }
            )
        
        # ==================== INTERNAL IP ADDRESSES ====================
        internal_ip_patterns = [
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b',
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            r'\blocalhost\b',
            r'\b127\.0\.0\.1\b'
        ]
        
        found_ips = []
        for pattern in internal_ip_patterns:
            matches = re.findall(pattern, response.text)
            found_ips.extend(matches)
        
        if found_ips:
            unique_ips = list(set(found_ips))
            scanner.add_finding(
                severity='LOW',
                category='Information Disclosure',
                title='Internal IP addresses exposed',
                description=f'Found {len(unique_ips)} internal IP address(es) or localhost references in content',
                url=scanner.target_url,
                remediation='Remove references to internal IP addresses and hostnames from production code',
                evidence={
                    'type': 'internal_ips',
                    'count': len(unique_ips),
                    'ips': unique_ips
                }
            )
        
        # ==================== VERSION DETECTION ====================
        version_patterns = {
            r'wordpress[/\s-]+([\d\.]+)': 'WordPress',
            r'drupal[/\s-]+([\d\.]+)': 'Drupal',
            r'joomla[/\s-]+([\d\.]+)': 'Joomla',
            r'jquery[-/]([\d\.]+)': 'jQuery',
            r'angular[-/]([\d\.]+)': 'Angular',
            r'react[-/]([\d\.]+)': 'React',
        }
        
        found_versions = []
        for pattern, tech_name in version_patterns.items():
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                found_versions.append({
                    'technology': tech_name,
                    'version': matches[0]
                })
        
        if found_versions:
            scanner.add_finding(
                severity='INFO',
                category='Information Disclosure',
                title=f'Technology versions detected',
                description=f'Found {len(found_versions)} technology version(s) exposed in source code',
                url=scanner.target_url,
                remediation='Keep software up to date and consider removing version information to reduce attack surface',
                evidence={
                    'type': 'technology_versions',
                    'count': len(found_versions),
                    'versions': found_versions
                }
            )
        
    except requests.RequestException:
        pass  # Connection errors already reported
    except Exception as e:
        pass  # Don't fail scan on parsing errors
