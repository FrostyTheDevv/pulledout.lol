"""
SawSap - Page Discovery and Crawler
Discovers pages to scan via sitemap.xml, robots.txt, and internal links
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import xml.etree.ElementTree as ET
import re

def discover_pages(scanner):
    """
    Comprehensive page discovery using multiple strategies
    Returns list of ALL discovered URLs (up to max_pages if set)
    """
    discovered_urls = set()
    crawled_urls = set()  # Track which pages we've already crawled for links
    
    # Always include the main URL first
    discovered_urls.add(scanner.target_url)
    
    max_display = scanner.max_pages if scanner.max_pages < 9999 else "unlimited"
    print(f"[*] Discovering pages to scan (max: {max_display})...")
    
    # Strategy 1: Parse sitemap.xml
    sitemap_urls = discover_from_sitemap(scanner)
    discovered_urls.update(sitemap_urls)
    if len(sitemap_urls) > 0:
        print(f"    Found {len(sitemap_urls)} URLs from sitemap.xml")
    
    # Strategy 2: Parse robots.txt
    robots_urls = discover_from_robots(scanner)
    discovered_urls.update(robots_urls)
    if len(robots_urls) > 0:
        print(f"    Found {len(robots_urls)} URLs from robots.txt")
    
    # Strategy 3: Try common paths
    common_paths = discover_common_paths(scanner)
    discovered_urls.update(common_paths)
    if len(common_paths) > 0:
        print(f"    Found {len(common_paths)} URLs from common paths")
    
    # Strategy 4: RECURSIVE link crawling - crawl ALL discovered pages
    print(f"    Recursively crawling internal links...")
    to_crawl = list(discovered_urls)
    
    while to_crawl and len(discovered_urls) < scanner.max_pages:
        current_url = to_crawl.pop(0)
        
        # Skip if already crawled
        if current_url in crawled_urls:
            continue
            
        crawled_urls.add(current_url)
        
        # Extract all links from this page
        new_links = discover_from_links(scanner, current_url)
        
        # Add new links to discovered set and crawl queue
        for link in new_links:
            if link not in discovered_urls and len(discovered_urls) < scanner.max_pages:
                discovered_urls.add(link)
                to_crawl.append(link)
        
        # Progress update every 10 pages crawled
        if len(crawled_urls) % 10 == 0:
            print(f"    Crawled {len(crawled_urls)} pages, found {len(discovered_urls)} total URLs...")
    
    print(f"    Finished crawling {len(crawled_urls)} pages, discovered {len(discovered_urls)} total URLs")
    
    # Filter to same domain and normalize
    filtered_urls = []
    target_normalized = scanner.target_url.rstrip('/')
    
    # Add target URL first
    if target_normalized not in filtered_urls:
        filtered_urls.append(target_normalized)
    
    # Then add other discovered URLs
    for url in discovered_urls:
        if len(filtered_urls) >= scanner.max_pages:
            break
        
        parsed = urlparse(url)
        if parsed.netloc == scanner.domain:
            # Normalize URL (remove fragments, trailing slashes, but keep path)
            path = parsed.path if parsed.path else '/'
            normalized = f"{parsed.scheme}://{parsed.netloc}{path.rstrip('/')}"
            if normalized and normalized != target_normalized and normalized not in filtered_urls:
                filtered_urls.append(normalized)
    
    print(f"[*] Will scan {len(filtered_urls)} page(s)\n")
    return filtered_urls


def discover_from_sitemap(scanner):
    """Discover URLs from sitemap.xml"""
    urls = set()
    
    sitemap_locations = [
        f"{scanner.base_url}/sitemap.xml",
        f"{scanner.base_url}/sitemap_index.xml",
        f"{scanner.base_url}/sitemap1.xml",
    ]
    
    for sitemap_url in sitemap_locations:
        try:
            response = scanner.get_cached_response(sitemap_url)
            if response and response.status_code == 200:
                try:
                    root = ET.fromstring(response.content)
                    
                    # Handle sitemap namespace
                    ns = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                    
                    # Check if it's a sitemap index
                    sitemaps = root.findall('.//ns:sitemap/ns:loc', ns)
                    if sitemaps:
                        # It's a sitemap index, fetch child sitemaps
                        for sitemap_elem in sitemaps[:3]:  # Limit to 3 child sitemaps
                            child_url = sitemap_elem.text
                            try:
                                child_response = scanner.get_cached_response(child_url)
                                if child_response and child_response.status_code == 200:
                                    child_root = ET.fromstring(child_response.content)
                                    locs = child_root.findall('.//ns:url/ns:loc', ns)
                                    for loc in locs:
                                        urls.add(loc.text)
                            except:
                                pass
                    else:
                        # Regular sitemap
                        locs = root.findall('.//ns:url/ns:loc', ns)
                        for loc in locs:
                            urls.add(loc.text)
                    
                    if urls:
                        break  # Found sitemap, stop searching
                except ET.ParseError:
                    # Not valid XML, skip
                    pass
        except:
            pass
    
    return list(urls)


def discover_from_robots(scanner):
    """Discover URLs from robots.txt"""
    urls = set()
    
    try:
        robots_url = f"{scanner.base_url}/robots.txt"
        response = scanner.get_cached_response(robots_url)
        
        if response and response.status_code == 200:
            lines = response.text.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Look for Disallow, Allow, Sitemap directives
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/' and not path.startswith('*'):
                        # Convert to full URL
                        full_url = urljoin(scanner.base_url, path)
                        urls.add(full_url)
                
                elif line.startswith('Sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    # Parse this sitemap
                    sitemap_urls = parse_sitemap_url(scanner, sitemap_url)
                    urls.update(sitemap_urls)
    except:
        pass
    
    return list(urls)


def parse_sitemap_url(scanner, sitemap_url):
    """Parse a specific sitemap URL"""
    urls = set()
    
    try:
        response = scanner.get_cached_response(sitemap_url)
        if response and response.status_code == 200:
            try:
                root = ET.fromstring(response.content)
                ns = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                locs = root.findall('.//ns:url/ns:loc', ns)
                for loc in locs:
                    urls.add(loc.text)
            except:
                pass
    except:
        pass
    
    return urls


def discover_from_links(scanner, page_url):
    """Discover URLs from internal links on a page - extracts ALL internal links"""
    urls = set()
    
    try:
        response = scanner.get_cached_response(page_url)
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all <a> tags
            links = soup.find_all('a', href=True)
            
            for link in links:
                href = link['href']
                
                # Convert to absolute URL
                absolute_url = urljoin(page_url, href)
                parsed = urlparse(absolute_url)
                
                # Only include same-domain links
                if parsed.netloc == scanner.domain:
                    # Skip non-HTML resources
                    if not any(absolute_url.lower().endswith(ext) for ext in [
                        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                        '.css', '.js', '.pdf', '.zip', '.xml', '.json',
                        '.txt', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
                        '.avi', '.mov', '.wmv', '.flv', '.webm', '.webp'
                    ]):
                        # Remove query params and fragments for deduplication
                        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
                        urls.add(clean_url)
    except Exception as e:
        # Silently fail but could log for debugging
        pass
    
    return list(urls)


def discover_common_paths(scanner):
    """Try common website paths to discover pages"""
    urls = set()
    
    common_paths = [
        '/about', '/about-us', '/about.html',
        '/contact', '/contact-us', '/contact.html',
        '/services', '/products',
        '/blog', '/news', '/articles',
        '/team', '/careers', '/jobs',
        '/faq', '/help', '/support',
        '/privacy', '/terms', '/legal',
        '/sitemap', '/site-map',
        '/portfolio', '/work', '/projects',
        '/pricing', '/plans',
        '/login', '/signin', '/signup', '/register',
        '/dashboard', '/account', '/profile'
    ]
    
    for path in common_paths:
        url = f"{scanner.base_url}{path}"
        try:
            # Quick check if page exists (with Selenium fallback)
            response = scanner.get_cached_response(url)
            if response and response.status_code == 200:
                # Check if it's a real page (not a redirect to homepage)
                if hasattr(response, 'url'):
                    # Avoid adding if redirected back to homepage
                    if response.url.rstrip('/') != scanner.target_url.rstrip('/'):
                        urls.add(url)
                else:
                    urls.add(url)
                
                # Limit discovery
                if len(urls) >= 10:
                    break
        except:
            pass
    
    return list(urls)
