"""
Cloud Storage Detection Module
Detects exposed cloud storage buckets (AWS S3, Azure, GCP, DigitalOcean Spaces, etc.)
"""

import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def detect_cloud_storage(scanner, progress_callback=None):
    """
    Scan for exposed cloud storage resources
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Search in HTML, JavaScript, and response headers
        full_content = response.text
        
        # Extract all URLs from page
        soup = BeautifulSoup(response.content, 'html.parser')
        all_urls = set()
        
        for tag in soup.find_all(['a', 'img', 'script', 'link', 'source', 'video', 'audio']):
            url = tag.get('href') or tag.get('src')
            if url:
                all_urls.add(url)
        
        # Also search text content for URLs
        url_pattern = r'https?://[^\s<>"]+(?:amazonaws\.com|cloudfront\.net|blob\.core\.windows\.net|storage\.googleapis\.com|digitaloceanspaces\.com|backblazeb2\.com|r2\.dev)[^\s<>"]*'
        text_urls = re.findall(url_pattern, full_content)
        all_urls.update(text_urls)
        
        # Phase 1: Detect AWS S3 buckets (20%)
        if progress_callback:
            progress_callback('s3', 20, 'Scanning for AWS S3 buckets...')
        _detect_s3_buckets(scanner, all_urls, full_content)
        
        # Phase 2: Detect Azure Blob Storage (40%)
        if progress_callback:
            progress_callback('azure', 40, 'Testing Azure Blob Storage...')
        _detect_azure_storage(scanner, all_urls, full_content)
        
        # Phase 3: Detect Google Cloud Storage (60%)
        if progress_callback:
            progress_callback('gcp', 60, 'Scanning Google Cloud Storage...')
        _detect_gcp_storage(scanner, all_urls, full_content)
        
        # Phase 4: Detect DigitalOcean Spaces (80%)
        if progress_callback:
            progress_callback('do', 80, 'Analyzing DigitalOcean Spaces...')
        _detect_do_spaces(scanner, all_urls, full_content)
        
        # Phase 5: Detect Cloudflare R2 and Backblaze (90%)
        if progress_callback:
            progress_callback('other', 90, 'Detecting Backblaze B2 and other storage...')
        _detect_cloudflare_r2(scanner, all_urls, full_content)
        
    except Exception as e:
        print(f"Cloud storage detection error: {e}")

def _detect_s3_buckets(scanner, urls, content):
    """Detect AWS S3 buckets"""
    # S3 URL patterns
    s3_patterns = [
        r'https?://([a-z0-9.-]+)\.s3\.amazonaws\.com',
        r'https?://([a-z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com',
        r'https?://s3\.amazonaws\.com/([a-z0-9.-]+)',
        r'https?://s3-([a-z0-9-]+)\.amazonaws\.com/([a-z0-9.-]+)',
    ]
    
    s3_buckets = set()
    
    for pattern in s3_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            bucket_name = match if isinstance(match, str) else match[0]
            s3_buckets.add(bucket_name)
    
    # Check URLs for S3
    for url in urls:
        if 's3.amazonaws.com' in url or 's3-' in url:
            parsed = urlparse(url)
            if '.s3.' in parsed.netloc:
                bucket = parsed.netloc.split('.s3.')[0]
                s3_buckets.add(bucket)
    
    # Test S3 buckets for public access
    for bucket in s3_buckets:
        _test_s3_bucket(scanner, bucket)

def _test_s3_bucket(scanner, bucket_name):
    """Test S3 bucket for public access"""
    test_urls = [
        f'https://{bucket_name}.s3.amazonaws.com/',
        f'https://s3.amazonaws.com/{bucket_name}/',
    ]
    
    for url in test_urls:
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                # Check if bucket listing is enabled
                if '<ListBucketResult' in response.text or 'Contents' in response.text:
                    # Count files
                    file_count = len(re.findall(r'<Key>', response.text))
                    
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Cloud Storage',
                        title='Publicly accessible S3 bucket with listing enabled',
                        description=f'S3 bucket "{bucket_name}" is publicly readable with ~{file_count} files exposed',
                        url=url,
                        remediation='Immediately restrict S3 bucket access. Disable public listing and set proper IAM policies.'
                    )
                else:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cloud Storage',
                        title='Publicly accessible S3 bucket detected',
                        description=f'S3 bucket "{bucket_name}" is publicly accessible',
                        url=url,
                        remediation='Review and restrict S3 bucket permissions'
                    )
                break
            elif response.status_code == 403:
                scanner.add_finding(
                    severity='INFO',
                    category='Cloud Storage',
                    title='S3 bucket detected (access denied)',
                    description=f'S3 bucket "{bucket_name}" exists but access is denied (good security)',
                    url=url,
                    remediation=''
                )
                break
        except:
            pass

def _detect_azure_storage(scanner, urls, content):
    """Detect Azure Blob Storage"""
    azure_pattern = r'https?://([a-z0-9]+)\.blob\.core\.windows\.net'
    
    storage_accounts = set()
    
    # Find Azure storage URLs
    matches = re.findall(azure_pattern, content, re.IGNORECASE)
    storage_accounts.update(matches)
    
    for url in urls:
        if 'blob.core.windows.net' in url:
            parsed = urlparse(url)
            account = parsed.netloc.split('.blob.')[0]
            storage_accounts.add(account)
    
    for account in storage_accounts:
        scanner.add_finding(
            severity='MEDIUM',
            category='Cloud Storage',
            title='Azure Blob Storage detected',
            description=f'Azure storage account: {account}.blob.core.windows.net',
            url=f'https://{account}.blob.core.windows.net',
            remediation='Ensure Azure storage has proper access controls configured'
        )

def _detect_gcp_storage(scanner, urls, content):
    """Detect Google Cloud Storage"""
    gcp_pattern = r'https?://storage\.googleapis\.com/([a-z0-9._-]+)'
    
    buckets = set(re.findall(gcp_pattern, content, re.IGNORECASE))
    
    for url in urls:
        if 'storage.googleapis.com' in url:
            parsed = urlparse(url)
            parts = parsed.path.strip('/').split('/')
            if parts:
                buckets.add(parts[0])
    
    for bucket in buckets:
        test_url = f'https://storage.googleapis.com/{bucket}/'
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 200 and '<?xml' in response.text:
                file_count = len(re.findall(r'<Name>', response.text))
                
                scanner.add_finding(
                    severity='CRITICAL',
                    category='Cloud Storage',
                    title='Publicly accessible GCP bucket',
                    description=f'Google Cloud Storage bucket "{bucket}" is publicly readable with ~{file_count} files',
                    url=test_url,
                    remediation='Set proper IAM permissions on GCP bucket to restrict public access'
                )
            else:
                scanner.add_finding(
                    severity='INFO',
                    category='Cloud Storage',
                    title='GCP Storage bucket detected',
                    description=f'Google Cloud Storage bucket: {bucket}',
                    url=test_url,
                    remediation=''
                )
        except:
            scanner.add_finding(
                severity='INFO',
                category='Cloud Storage',
                title='GCP Storage bucket detected',
                description=f'Google Cloud Storage bucket: {bucket}',
                url=test_url,
                remediation=''
            )

def _detect_do_spaces(scanner, urls, content):
    """Detect DigitalOcean Spaces"""
    do_pattern = r'https?://([a-z0-9.-]+)\.([a-z0-9-]+)\.digitaloceanspaces\.com'
    
    spaces = set(re.findall(do_pattern, content, re.IGNORECASE))
    
    for url in urls:
        if 'digitaloceanspaces.com' in url:
            parsed = urlparse(url)
            parts = parsed.netloc.split('.')
            if len(parts) >= 4:
                space_name = parts[0]
                region = parts[1]
                spaces.add((space_name, region))
    
    for space_name, region in spaces:
        scanner.add_finding(
            severity='MEDIUM',
            category='Cloud Storage',
            title='DigitalOcean Space detected',
            description=f'DigitalOcean Space: {space_name} (region: {region})',
            url=f'https://{space_name}.{region}.digitaloceanspaces.com',
            remediation='Ensure DigitalOcean Space has proper access controls'
        )

def _detect_cloudflare_r2(scanner, urls, content):
    """Detect Cloudflare R2 storage"""
    r2_pattern = r'https?://([a-z0-9.-]+)\.r2\.dev'
    
    buckets = set(re.findall(r2_pattern, content, re.IGNORECASE))
    
    for url in urls:
        if '.r2.dev' in url:
            parsed = urlparse(url)
            bucket = parsed.netloc.split('.r2.dev')[0]
            buckets.add(bucket)
    
    for bucket in buckets:
        scanner.add_finding(
            severity='MEDIUM',
            category='Cloud Storage',
            title='Cloudflare R2 bucket detected',
            description=f'Cloudflare R2 bucket: {bucket}.r2.dev',
            url=f'https://{bucket}.r2.dev',
            remediation='Verify Cloudflare R2 bucket permissions are properly configured'
        )

def _detect_cdn_urls(scanner, urls, content):
    """Detect CDN usage which might reveal storage"""
    cdn_patterns = {
        'cloudfront.net': 'AWS CloudFront',
        'azureedge.net': 'Azure CDN',
        'cloudflare.com': 'Cloudflare CDN',
        'fastly.net': 'Fastly CDN',
        'akamai.net': 'Akamai CDN',
    }
    
    for url in urls:
        for cdn_domain, cdn_name in cdn_patterns.items():
            if cdn_domain in url:
                scanner.add_finding(
                    severity='INFO',
                    category='Cloud Storage',
                    title=f'{cdn_name} detected',
                    description=f'Site uses {cdn_name}: {url}',
                    url=url,
                    remediation=''
                )
                break
