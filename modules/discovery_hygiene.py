"""
Discovery and Hygiene Checker - State of the Art
Checks for robots.txt, sitemaps, common files, and technology fingerprinting
"""

import requests

def check_discovery_hygiene(scanner):
    """
    Perform discovery and hygiene checks
    Tests for robots.txt, sitemap.xml, common sensitive files
    """
    
    base_url = scanner.base_url
    
    # ==================== ROBOTS.TXT ====================
    try:
        robots_url = f"{base_url}/robots.txt"
        response = scanner.session.get(robots_url, timeout=5)
        
        if response.status_code == 200:
            scanner.add_finding(
                severity='INFO',
                category='Discovery / Hygiene',
                title='robots.txt found',
                description='robots.txt exists and is accessible',
                url=robots_url,
                remediation='Ensure robots.txt does not disclose sensitive paths'
            )
            
            # Check for sensitive paths disclosed in robots.txt
            sensitive_keywords = ['admin', 'backup', 'private', 'internal', 'secret', 'config', '/api/', 'staging']
            robots_content_lower = response.text.lower()
            
            for keyword in sensitive_keywords:
                if keyword in robots_content_lower:
                    scanner.add_finding(
                        severity='LOW',
                        category='Discovery / Hygiene',
                        title='robots.txt may reveal sensitive paths',
                        description=f'robots.txt contains references to potentially sensitive paths (keyword: {keyword})',
                        url=robots_url,
                        remediation='Avoid listing sensitive directories in robots.txt - use proper access controls instead'
                    )
                    break
        else:
            scanner.add_finding(
                severity='INFO',
                category='Discovery / Hygiene',
                title='robots.txt not found',
                description='No robots.txt file found (optional but recommended for SEO)',
                url=robots_url,
                remediation='Consider adding robots.txt to control crawler access'
            )
    except requests.RequestException:
        pass
    
    # ==================== SITEMAP.XML ====================
    try:
        sitemap_url = f"{base_url}/sitemap.xml"
        response = scanner.session.get(sitemap_url, timeout=5)
        
        if response.status_code == 200:
            scanner.add_finding(
                severity='INFO',
                category='Discovery / Hygiene',
                title='sitemap.xml found',
                description='sitemap.xml exists and is accessible',
                url=sitemap_url,
                remediation='Ensure sitemap.xml does not list non-public pages'
            )
    except requests.RequestException:
        pass
    
    # ==================== COMMON SENSITIVE FILES ====================
    sensitive_files = [
        '.git/config',
        '.env',
        '.DS_Store',
        'web.config',
        'phpinfo.php',
        '.htaccess',
        'composer.json',
        'package.json',
        'yarn.lock',
        'Gemfile.lock',
        'WEB-INF/web.xml',
        'crossdomain.xml',
        'clientaccesspolicy.xml',
    ]
    
    for file_path in sensitive_files:
        try:
            file_url = f"{base_url}/{file_path}"
            response = scanner.session.get(file_url, timeout=3)
            
            if response.status_code == 200:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Information Disclosure',
                    title=f'Sensitive file accessible: {file_path}',
                    description=f'Sensitive file {file_path} is publicly accessible',
                    url=file_url,
                    remediation=f'Block access to {file_path} or remove from web root'
                )
        except requests.RequestException:
            pass
    
    # ==================== SECURITY.TXT ====================
    try:
        security_txt_url = f"{base_url}/.well-known/security.txt"
        response = scanner.session.get(security_txt_url, timeout=5)
        
        if response.status_code == 200:
            scanner.add_finding(
                severity='INFO',
                category='Discovery / Hygiene',
                title='security.txt found',
                description= 'security.txt file exists (good practice for responsible disclosure)',
                url=security_txt_url,
                remediation='Ensure contact information is current and monitored'
            )
        else:
            scanner.add_finding(
                severity='INFO',
                category='Discovery / Hygiene',
                title='security.txt not found',
                description='No security.txt file found. Recommended for vulnerability reporting.',
                url=security_txt_url,
                remediation='Consider adding security.txt as per RFC 9116'
            )
    except requests.RequestException:
        pass
    
    # ==================== COMMON BACKUP FILES ====================
    # Check for backup files (only for the target page name)
    if scanner.parsed_url.path and scanner.parsed_url.path != '/':
        path_parts = scanner.parsed_url.path.rsplit('/', 1)
        if len(path_parts) == 2:
            page_name = path_parts[1]
            if page_name:
                backup_extensions = ['.bak', '.old', '.backup', '~', '.swp', '.save']
                for ext in backup_extensions:
                    try:
                        backup_url = f"{base_url}{scanner.parsed_url.path}{ext}"
                        response = scanner.session.get(backup_url, timeout=3)
                        
                        if response.status_code == 200:
                            scanner.add_finding(
                                severity='MEDIUM',
                                category='Information Disclosure',
                                title=f'Backup file accessible',
                                description=f'Backup file found: {page_name}{ext}',
                                url=backup_url,
                                remediation='Remove backup files from web-accessible directories'
                            )
                    except requests.RequestException:
                        pass
