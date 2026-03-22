"""
Sensitive Data Harvester Module
Actively extracts and categorizes sensitive data from target websites
Shows user exactly what data is exposed and how attackers would steal it
"""

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import json
import base64

def harvest_sensitive_data(scanner):
    """
    Actively extract and demonstrate sensitive data exposure
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Extract and demonstrate different types of sensitive data
        _extract_credentials(scanner, response)
        _extract_api_keys(scanner, response)
        _extract_tokens(scanner, response)
        _extract_database_info(scanner, response)
        _extract_internal_paths(scanner, response)
        _extract_user_data(scanner, response)
        _extract_financial_data(scanner, response)
        _extract_source_maps(scanner, response)
        
    except Exception as e:
        print(f"Data harvesting error: {e}")

def _extract_credentials(scanner, response):
    """Extract exposed credentials with proof"""
    text = response.text
    
    # Patterns for credentials
    credential_patterns = {
        'AWS Access Key': (r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', 'CRITICAL'),
        'AWS Secret Key': (r'(?i)aws(.{0,20})?(?-i)[\'"\s]*[0-9a-zA-Z/+]{40}', 'CRITICAL'),
        'Stripe API Key': (r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}', 'CRITICAL'),
        'GitHub Token': (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', 'CRITICAL'),
        'Google API Key': (r'AIza[0-9A-Za-z\\-_]{35}', 'HIGH'),
        'Slack Token': (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}', 'HIGH'),
        'Slack Webhook': (r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}', 'HIGH'),
        'Twilio API Key': (r'SK[a-z0-9]{32}', 'HIGH'),
        'SendGrid API Key': (r'SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-FZ0-9_-]{43}', 'HIGH'),
        'MailChimp API Key': (r'[a-f0-9]{32}-us[0-9]{1,2}', 'MEDIUM'),
        'PayPal/Braintree Access Token': (r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}', 'CRITICAL'),
        'Square Access Token': (r'sq0atp-[0-9A-Za-z\\-_]{22}', 'HIGH'),
        'Square OAuth Secret': (r'sq0csp-[0-9A-Za-z\\-_]{43}', 'CRITICAL'),
        'Picatic API Key': (r'sk_live_[0-9a-z]{32}', 'HIGH'),
        'Generic API Key': (r'(?i)(api[_-]?key|apikey|api[_-]?token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\\-]{20,})["\']', 'MEDIUM'),
        'Database Connection String': (r'(?i)(mongodb|mysql|postgres|redis)://[^\\s\'"<>]+', 'CRITICAL'),
        'Private Key': (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'CRITICAL'),
        'JSON Web Token': (r'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+', 'MEDIUM'),
    }
    
    for cred_type, (pattern, severity) in credential_patterns.items():
        matches = re.findall(pattern, text)
        
        if matches:
            # Get unique matches
            unique_matches = list(set(matches))[:5]  # Limit to 5 to avoid spam
            
            for match in unique_matches:
                # Extract actual value from tuple if needed
                if isinstance(match, tuple) and len(match) > 0:
                    value = match[1] if len(match) > 1 else match[0]
                else:
                    value = match if match else ""
                
                # Mask middle part but show enough to prove it's real
                masked_value = _mask_sensitive(str(value))
                
                scanner.add_finding(
                    severity=severity,
                    category='Sensitive Data Exposure',
                    title=f'EXPOSED: {cred_type}',
                    description=f'**🚨 ACTIVE CREDENTIAL EXPOSURE 🚨**\n\n'
                              f'**Type:** {cred_type}\n'
                              f'**Value:** `{masked_value}`\n'
                              f'**Location:** Found in HTML/JavaScript source\n\n'
                              f'**IMMEDIATE DANGER:**\n'
                              f'- Attackers can view page source (Ctrl+U)\n'
                              f'- This credential is publicly accessible\n'
                              f'- Can be used to compromise your account\n\n'
                              f'**How Attacker Steals This:**\n'
                              f'```bash\n'
                              f'# Step 1: View source code\n'
                              f'curl {scanner.target_url} | grep -i "{cred_type.split()[0]}"\n\n'
                              f'# Step 2: Extract credential\n'
                              f'# Step 3: Use credential for unauthorized access\n'
                              f'```\n\n'
                              f'**What They Can Do:**\n'
                              f'{_get_credential_impact(cred_type)}',
                    url=scanner.target_url,
                    remediation=f'**URGENT ACTIONS REQUIRED:**\n\n'
                              f'1. **REVOKE THIS CREDENTIAL IMMEDIATELY**\n'
                              f'2. Rotate all API keys and secrets\n'
                              f'3. Check logs for unauthorized access\n'
                              f'4. Move credentials to environment variables\n'
                              f'5. Never commit credentials to source code\n'
                              f'6. Use secret management (AWS Secrets Manager, HashiCorp Vault)\n'
                              f'7. Implement .gitignore for config files\n'
                              f'8. Use .env files (and add to .gitignore)\n\n'
                              f'**Prevention Code:**\n'
                              f'```javascript\n'
                              f'// WRONG:\n'
                              f'const API_KEY = "abc123...";\n\n'
                              f'// CORRECT:\n'
                              f'const API_KEY = process.env.API_KEY;\n'
                              f'// Then set in environment, not in code\n'
                              f'```'
                )

def _extract_api_keys(scanner, response):
    """Extract API keys with exploitation proof"""
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Check for API keys in meta tags
    meta_tags = soup.find_all('meta')
    for meta in meta_tags:
        content = meta.get('content', '')
        name = meta.get('name', '') or meta.get('property', '')
        
        # Look for API key patterns
        if any(keyword in str(name).lower() + str(content).lower() for keyword in ['api', 'key', 'token']):
            if len(str(content)) > 15 and re.match(r'[a-zA-Z0-9_-]{20,}', str(content)):
                scanner.add_finding(
                    severity='HIGH',
                    category='Sensitive Data Exposure',
                    title=f'API Key in Meta Tag: {name}',
                    description=f'**API KEY EXPOSED IN META TAG**\n\n'
                              f'Meta Name: {name}\n'
                              f'Value: {_mask_sensitive(str(content))}\n\n'
                              f'**Proof of Concept:**\n'
                              f'```html\n'
                              f'<meta name="{name}" content="{_mask_sensitive(str(content))}">\n'
                              f'```\n\n'
                              f'**How to Steal:**\n'
                              f'```javascript\n'
                              f'document.querySelector(\'meta[name="{name}"]\').content\n'
                              f'```',
                    url=scanner.target_url,
                    remediation='Remove API keys from HTML meta tags. Use server-side code only.'
                )

def _extract_tokens(scanner, response):
    """Extract authentication tokens"""
    # Look for Bearer tokens, session tokens, etc.
    auth_pattern = r'(?i)(authorization|bearer|token)[\"\']?\s*[:=]\s*[\"\']([a-zA-Z0-9_\\-\\.]{20,})[\"\']'
    
    matches = re.findall(auth_pattern, response.text)
    
    for match in matches:
        token_type, token_value = match
        
        scanner.add_finding(
            severity='HIGH',
            category='Sensitive Data Exposure',
            title=f'Authentication Token Exposed: {token_type}',
            description=f'**EXPOSED AUTHENTICATION TOKEN**\n\n'
                      f'Token Type: {token_type}\n'
                      f'Value: {_mask_sensitive(token_value)}\n\n'
                      f'**Attack Vector:**\n'
                      f'```javascript\n'
                      f'// Attacker extracts token from source:\n'
                      f'fetch("https://api.site.com/user/data", {{\n'
                      f'  headers: {{"Authorization": "Bearer {_mask_sensitive(token_value)}"}}\n'
                      f'}})\n'
                      f'// Now has access to user account!\n'
                      f'```',
            url=scanner.target_url,
            remediation='Never expose authentication tokens in client-side code'
        )

def _extract_database_info(scanner, response):
    """Extract database connection information"""
    # Database connection strings
    db_patterns = {
        'MongoDB': r'mongodb(?:\+srv)?://([^@]+@)?([^/\\s\'"]+)',
        'MySQL': r'mysql://([^@]+@)?([^/\\s\'"]+)',
        'PostgreSQL': r'postgres(?:ql)?://([^@]+@)?([^/\\s\'"]+)',
        'Redis': r'redis://([^@]+@)?([^/\\s\'"]+)',
    }
    
    for db_type, pattern in db_patterns.items():
        matches = re.findall(pattern, response.text)
        
        for match in matches:
            connection_str = ''.join(match)
            
            scanner.add_finding(
                severity='CRITICAL',
                category='Sensitive Data Exposure',
                title=f'{db_type} Connection String Exposed',
                description=f'**🚨 DATABASE CONNECTION EXPOSED 🚨**\n\n'
                          f'**Database Type:** {db_type}\n'
                          f'**Connection Info:** {_mask_sensitive(connection_str)}\n\n'
                          f'**EXTREME DANGER:**\n'
                          f'Attacker can:\n'
                          f'1. Connect directly to your database\n'
                          f'2. Steal ALL customer data\n'
                          f'3. Delete or modify records\n'
                          f'4. Inject malware\n'
                          f'5. Hold data for ransom\n\n'
                          f'**Attack Example:**\n'
                          f'```bash\n'
                          f'# Attacker extracts connection string from your source\n'
                          f'# Then connects directly:\n'
                          f'{db_type.lower()} "mongodb://[extracted-from-your-code]"\n'
                          f'# Now has full database access!\n'
                          f'```',
                url=scanner.target_url,
                remediation='**CRITICAL:**\n'
                          '1. Change database password IMMEDIATELY\n'
                          '2. Restrict database access by IP\n'
                          '3. Never expose connection strings\n'
                          '4. Use environment variables server-side only'
            )

def _extract_internal_paths(scanner, response):
    """Extract internal file paths and system info"""
    path_patterns = [
        r'(?i)(c:\\\\|/home/|/var/|/usr/|/etc/)[^\s<>"\'\\)]+',
        r'(?i)(?:file|path|dir)[\"\']?\s*[:=]\s*[\"\']([a-zA-Z]:[\\\\][^\"\'<>]+|/[^\"\'<>\\s]+)[\"\']',
    ]
    
    for pattern in path_patterns:
        matches = re.findall(pattern, response.text)
        
        for match in matches:
            path = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]
            
            if len(path) > 10:  # Reasonable path length
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Sensitive Data Exposure',
                    title='Internal File Paths Exposed',
                    description=f'**Internal System Path Revealed**\n\n'
                              f'Path: `{path}`\n\n'
                              f'**Information Leak:**\n'
                              f'- Reveals server directory structure\n'
                              f'- Shows operating system type\n'
                              f'- Helps attackers map internal file system\n'
                              f'- May reveal usernames or application structure',
                    url=scanner.target_url,
                    remediation='Remove internal paths from client-side code and error messages'
                )
                break  # Only report once per page

def _extract_user_data(scanner, response):
    """Extract exposed user data (emails, phones, SSN, etc.)"""
    # Email addresses
    emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text))
    
    if len(emails) > 10:  # Many emails might indicate user list
        scanner.add_finding(
            severity='MEDIUM',
            category='Sensitive Data Exposure',
            title=f'Multiple Email Addresses Exposed ({len(emails)} found)',
            description=f'**BULK EMAIL EXPOSURE**\n\n'
                      f'Found {len(emails)} email addresses in page source\n'
                      f'Sample: {", ".join(list(emails)[:5])}\n\n'
                      f'**Attack Potential:**\n'
                      f'- Spam/phishing campaigns\n'
                      f'- Social engineering attacks\n'
                      f'- User enumeration\n'
                      f'- Credential stuffing attempts',
            url=scanner.target_url,
            remediation='Avoid exposing user emails. Use contact forms instead of direct email links'
        )
    
    # Phone numbers
    phones = re.findall(r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b', response.text)
    
    if len(phones) > 5:
        scanner.add_finding(
            severity='MEDIUM',
            category='Sensitive Data Exposure',
            title=f'Multiple Phone Numbers Exposed ({len(phones)} found)',
            description=f'Bulk phone number exposure detected\n'
                      f'Could be used for spam or social engineering',
            url=scanner.target_url,
            remediation='Limit phone number exposure or use click-to-call functionality'
        )

def _extract_financial_data(scanner, response):
    """Look for exposed financial data patterns"""
    financial_patterns = {
        'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        'SSN': r'\b(?!000|666)[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b',
        'Bank Account': r'\b[0-9]{8,17}\b',
    }
    
    for data_type, pattern in financial_patterns.items():
        matches = re.findall(pattern, response.text)
        
        if matches:
            scanner.add_finding(
                severity='CRITICAL',
                category='Sensitive Data Exposure',
                title=f'Possible {data_type} Exposed',
                description=f'**CRITICAL: FINANCIAL DATA EXPOSURE**\n\n'
                          f'Pattern matching {data_type} detected\n'
                          f'Found {len(matches)} potential matches\n\n'
                          f'**If real:** PCI-DSS violation, legal liability, identity theft risk',
                url=scanner.target_url,
                remediation='NEVER expose financial data. Immediately remove and investigate data breach'
            )

def _extract_source_maps(scanner, response):
    """Check for source map exposure"""
    if '.map' in response.text or 'sourceMappingURL' in response.text:
        map_urls = re.findall(r'sourceMappingURL=([^\s]+\.map)', response.text)
        
        for map_url in map_urls:
            scanner.add_finding(
                severity='MEDIUM',
                category='Sensitive Data Exposure',
                title='Source Map Files Exposed',
                description=f'**SOURCE CODE EXPOSURE**\n\n'
                          f'Source map: {map_url}\n\n'
                          f'**Risk:**\n'
                          f'- Exposes original unminified source code\n'
                          f'- Reveals business logic\n'
                          f'- Shows API endpoints and secrets in code\n'
                          f'- Helps attackers understand application structure',
                url=scanner.target_url,
                remediation='Disable source maps in production builds'
            )

def _mask_sensitive(value):
    """Mask sensitive value but show it exists"""
    value_str = str(value)
    if len(value_str) <= 8:
        return '*' * len(value_str)
    else:
        # Show first 4 and last 4 characters
        return value_str[:4] + ('*' * (len(value_str) - 8)) + value_str[-4:]

def _get_credential_impact(cred_type):
    """Get specific impact for credential type"""
    impacts = {
        'AWS': '- Full access to your AWS account\n- Spin up expensive EC2 instances\n- Access S3 buckets with customer data\n- Modify or delete cloud infrastructure\n- Potential bill of thousands of dollars',
        'Stripe': '- Access customer payment information\n- Process unauthorized refunds\n- Steal customer credit card data\n- Create fraudulent charges\n- Massive financial and legal liability',
        'GitHub': '- Access private repositories\n- Steal proprietary code\n- Inject malware into codebase\n- Access organization secrets\n- Compromise entire development pipeline',
        'Google': '- Access Google Cloud resources\n- Use API quotas (expensive)\n- Access associated services\n- Potential data access depending on permissions',
        'Database': '- Complete database access\n- Steal all customer data\n- Delete or modify records\n- SQL injection attacks\n- Data breach with millions in liability',
    }
    
    for key, impact in impacts.items():
        if key.lower() in cred_type.lower():
            return impact
    
    return '- Unauthorized access to services\n- Potential data breach\n- Account compromise\n- Financial and reputational damage'
