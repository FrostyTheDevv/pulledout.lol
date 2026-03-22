"""
Exposed Files Scanner Module - Advanced File Discovery
Tests for exposed sensitive files, backups, version control, and configuration files
"""

import requests
from urllib.parse import urljoin
import re

def scan_exposed_files(scanner):
    """
    Comprehensive scan for exposed sensitive files
    """
    try:
        base_url = scanner.target_url.rstrip('/')
        
        # Test for exposed sensitive files
        _test_version_control(scanner, base_url)
        _test_backup_files(scanner, base_url)
        _test_config_files(scanner, base_url)
        _test_common_sensitive(scanner, base_url)
        _test_documentation(scanner, base_url)
        _test_server_files(scanner, base_url)
        
    except Exception as e:
        print(f"Exposed files scan error: {e}")

def _test_version_control(scanner, base_url):
    """Test for exposed version control directories"""
    vcs_paths = [
        '.git/config',
        '.git/HEAD',
        '.git/index',
        '.git/logs/HEAD',
        '.svn/entries',
        '.svn/wc.db',
        '.hg/requires',
        '.bzr/branch-format',
        'CVS/Entries',
        '.gitignore',
        '.gitconfig',
    ]
    
    for path in vcs_paths:
        test_url = urljoin(base_url + '/', path)
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=False, verify=False)
            
            if response.status_code == 200:
                vcs_type = path.split('/')[0]
                scanner.add_finding(
                    severity='CRITICAL',
                    category='Exposed Files',
                    title=f'Exposed {vcs_type} directory detected',
                    description=f'Version control file accessible: {test_url}',
                    url=test_url,
                    remediation=f'Block access to {vcs_type} directories immediately. Add deny rules in web server config.'
                )
                break  # Don't spam if one is found
        except:
            pass

def _test_backup_files(scanner, base_url):
    """Test for backup files and archives"""
    
    # Get the current page name
    parsed = scanner.target_url.rstrip('/').split('/')
    page_name = parsed[-1] if '.' in parsed[-1] else 'index'
    
    backup_patterns = [
        'backup.zip',
        'backup.tar.gz',
        'backup.sql',
        'db_backup.sql',
        'database.sql',
        'dump.sql',
        'site_backup.zip',
        'www.zip',
        'wwwroot.zip',
        'public_html.zip',
        f'{page_name}.bak',
        f'{page_name}.old',
        f'{page_name}.backup',
        f'{page_name}~',
        f'{page_name}.tmp',
        'config.bak',
        'config.old',
        '.DS_Store',
        'Thumbs.db',
    ]
    
    for backup_file in backup_patterns:
        test_url = urljoin(base_url + '/', backup_file)
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=False, verify=False)
            
            if response.status_code == 200 and len(response.content) > 100:
                scanner.add_finding(
                    severity='HIGH',
                    category='Exposed Files',
                    title=f'Backup file exposed: {backup_file}',
                    description=f'Publicly accessible backup file: {test_url}',
                    url=test_url,
                    remediation='Remove backup files from web root or block access via .htaccess/web.config'
                )
        except:
            pass

def _test_config_files(scanner, base_url):
    """Test for exposed configuration files"""
    config_files = [
        '.env',
        '.env.local',
        '.env.production',
        '.env.development',
        'config.json',
        'config.yml',
        'config.yaml',
        'configuration.json',
        'settings.json',
        'settings.php',
        'config.php',
        'config.inc.php',
        'database.yml',
        'db.json',
        'wp-config.php',
        'wp-config.php.bak',
        'web.config',
        'app.config',
        '.htaccess',
        '.htpasswd',
        'composer.json',
        'package.json',
        'package-lock.json',
        'yarn.lock',
        '.npmrc',
        'Dockerfile',
        'docker-compose.yml',
        '.dockerignore',
    ]
    
    for config_file in config_files:
        test_url = urljoin(base_url + '/', config_file)
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=False, verify=False)
            
            if response.status_code == 200:
                # Check if it's actually a config file (not a 404 page)
                is_config = any(keyword in response.text.lower() for keyword in [
                    'password', 'database', 'api_key', 'secret', 'token', 'mysql', 'mongodb', 'redis'
                ])
                
                severity = 'CRITICAL' if '.env' in config_file or 'config' in config_file else 'HIGH'
                
                if is_config or len(response.content) < 5000:  # Config files are usually small
                    scanner.add_finding(
                        severity=severity,
                        category='Exposed Files',
                        title=f'Configuration file exposed: {config_file}',
                        description=f'Sensitive configuration file accessible: {test_url}',
                        url=test_url,
                        remediation='Move configuration files outside web root or block access via server config'
                    )
        except:
            pass

def _test_common_sensitive(scanner, base_url):
    """Test for common sensitive files"""
    sensitive_files = [
        'phpinfo.php',
        'info.php',
        'test.php',
        'admin.php',
        'login.php',
        'console/',
        'adminer.php',
        'phpmyadmin/',
        'pma/',
        'mysql/',
        'myadmin/',
        'sql/',
        'dbadmin/',
        'admin/login',
        'admin/index',
        'administrator/',
        'wp-admin/',
        'user/login',
        'users/login',
        'auth/login',
        'cms/admin',
        'panel/',
        'cpanel/',
        'controlpanel/',
        'README.md',
        'CHANGELOG.md',
        'LICENSE',
        'TODO.md',
        'notes.txt',
        'passwords.txt',
        'credentials.txt',
    ]
    
    for sensitive_file in sensitive_files:
        test_url = urljoin(base_url + '/', sensitive_file)
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=False, verify=False)
            
            if response.status_code == 200:
                # Determine severity based on file type
                if 'phpinfo' in sensitive_file or 'console' in sensitive_file:
                    severity = 'HIGH'
                    title = 'Exposed development/debug file'
                elif 'admin' in sensitive_file or 'login' in sensitive_file:
                    severity = 'MEDIUM'
                    title = 'Admin/login panel accessible'
                else:
                    severity = 'LOW'
                    title = 'Potentially sensitive file exposed'
                
                scanner.add_finding(
                    severity=severity,
                    category='Exposed Files',
                    title=f'{title}: {sensitive_file}',
                    description=f'Accessible at: {test_url}',
                    url=test_url,
                    remediation='Remove development files from production or restrict access'
                )
        except:
            pass

def _test_documentation(scanner, base_url):
    """Test for exposed documentation"""
    doc_paths = [
        'docs/',
        'documentation/',
        'api-docs/',
        'swagger/',
        'swagger-ui/',
        'api/',
        'apidocs/',
        '/graphql',
        '/graphiql',
    ]
    
    for doc_path in doc_paths:
        test_url = urljoin(base_url + '/', doc_path)
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=True, verify=False)
            
            if response.status_code == 200 and len(response.content) > 500:
                # Check if it looks like API documentation
                if any(keyword in response.text.lower() for keyword in ['swagger', 'api', 'endpoint', 'graphql', 'documentation']):
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Exposed Files',
                        title='API documentation exposed',
                        description=f'Publicly accessible documentation: {test_url}',
                        url=test_url,
                        remediation='Restrict documentation access to authenticated users or internal networks'
                    )
        except:
            pass

def _test_server_files(scanner, base_url):
    """Test for server-specific files"""
    server_files = [
        'server-status',
        'server-info',
        '/status',
        '/.well-known/security.txt',
        '/robots.txt',
        '/sitemap.xml',
        '/crossdomain.xml',
        '/clientaccesspolicy.xml',
    ]
    
    for server_file in server_files:
        test_url = urljoin(base_url + '/', server_file.lstrip('/'))
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=False, verify=False)
            
            if response.status_code == 200:
                # Check for sensitive server info
                if 'server-status' in server_file or 'server-info' in server_file:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Exposed Files',
                        title='Server status page exposed',
                        description=f'Apache server status accessible: {test_url}',
                        url=test_url,
                        remediation='Restrict access to server status pages'
                    )
                elif 'robots.txt' in server_file:
                    # Parse robots.txt for interesting disallowed paths
                    disallowed = re.findall(r'Disallow:\s*(.+)', response.text)
                    if disallowed:
                        scanner.add_finding(
                            severity='INFO',
                            category='Exposed Files',
                            title='Robots.txt reveals hidden paths',
                            description=f'Disallowed paths: {", ".join(disallowed[:5])}',
                            url=test_url,
                            remediation='Be aware that robots.txt is publicly accessible'
                        )
        except:
            pass
