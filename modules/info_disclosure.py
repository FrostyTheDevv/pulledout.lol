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
        
        found_comment_issues = set()
        for comment in comments:
            comment_text = str(comment).lower()
            for pattern, description in  sensitive_comment_patterns.items():
                if re.search(pattern, comment_text, re.IGNORECASE) and description not in found_comment_issues:
                    scanner.add_finding(
                        severity='LOW',
                        category='Information Disclosure',
                        title='Sensitive information in HTML comments',
                        description=f'{description} found in HTML comments',
                        url=scanner.target_url,
                        remediation='Remove sensitive comments before deploying to production'
                    )
                    found_comment_issues.add(description)
        
        # ==================== EMAIL HARVESTING ====================
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, response.text)
        
        if emails:
            unique_emails = list(set(emails))[:5]  # Limit to 5 examples
            scanner.add_finding(
                severity='INFO',
                category='Information Disclosure',
                title='Email addresses exposed in source',
                description=f'Found {len(unique_emails)} email address(es) in HTML: {", ".join(unique_emails[:3])}',
                url=scanner.target_url,
                remediation='Consider obfuscating email addresses to prevent harvesting by bots'
            )
        
        # ==================== INTERNAL IP ADDRESSES ====================
        internal_ip_patterns = [
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b',
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            r'\b127\.0\.0\.1\b',
            r'\blocalhost\b',
        ]
        
        for pattern in internal_ip_patterns:
            matches = re.findall(pattern, response.text)
            if matches:
                scanner.add_finding(
                    severity='LOW',
                    category='Information Disclosure',
                    title='Internal IP address exposed',
                    description=f'Internal IP address found in content: {matches[0]}',
                    url=scanner.target_url,
                    remediation='Remove references to internal IP addresses and hostnames'
                )
                break
        
        # ==================== VERSION STRINGS ====================
        version_patterns = {
            r'wordpress[/\s-]+([\d\.]+)': 'WordPress version',
            r'drupal[/\s-]+([\d\.]+)': 'Drupal version',
            r'joomla[/\s-]+([\d\.]+)': 'Joomla version',
            r'jquery[-/]([\d\.]+)': 'jQuery version',
            r'angular[-/]([\d\.]+)': 'Angular version',
            r'react[-/]([\d\.]+)': 'React version',
        }
        
        for pattern, tech_name in version_patterns.items():
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                scanner.add_finding(
                    severity='INFO',
                    category='Information Disclosure',
                    title=f'{tech_name} detected',
                    description=f'{tech_name} {matches[0]} identified in source',
                    url=scanner.target_url,
                    remediation='Keep software up to date and consider removing version information'
                )
                break
        
    except requests.RequestException:
        pass  # Connection errors already reported
    except Exception as e:
        pass  # Don't fail scan on parsing errors
