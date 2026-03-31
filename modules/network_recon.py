"""
Network Reconnaissance and Subdomain Enumeration
Performs DNS analysis, subdomain discovery, and port scanning
"""

import requests
import socket
import dns.resolver  # type: ignore[import]
import dns.zone  # type: ignore[import]
import dns.query  # type: ignore[import]
from urllib.parse import urlparse
import concurrent.futures
from typing import List, Set
import itertools

# Common subdomains to test
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
    'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'm', 'mobile', 'dev', 'developer',    
    'api', 'app', 'admin', 'administrator', 'test', 'testing', 'stage', 'staging', 'qa',
    'prod', 'production', 'demo', 'beta', 'alpha', 'cdn', 'assets', 'static', 'media',
    'images', 'img', 'blog', 'shop', 'store', 'forum', 'support', 'help', 'wiki',
    'portal', 'vpn', 'remote', 'git', 'svn', 'jenkins', 'ci', 'cd', 'monitoring',
    'grafana', 'prometheus', 'kibana', 'elastic', 'status', 'health', 'docs', 'documentation',
    'sso', 'auth', 'login', 'signin', 'signup', 'register', 'account', 'dashboard',
    'console', 'panel', 'control', 'manage', 'management', 'backup', 'db', 'database',
    'mysql', 'postgres', 'mongodb', 'redis', 'cache', 'queue', 'worker', 'jobs',
    'internal', 'intranet', 'extranet', 'partner', 'partners', 'vendor', 'vendors',
    'cloud', 'aws', 'azure', 'gcp', 'k8s', 'kubernetes', 'docker', 'rancher',
    'old', 'legacy', 'archive', 'backup', 'temp', 'tmp', 'sandbox', 'preview',
]

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
    3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017, 27018, 28017
]

# Critical ports that should NEVER be exposed
CRITICAL_PORTS = {
    22: 'SSH',
    23: 'Telnet',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
    28017: 'MongoDB HTTP',
}

def perform_network_recon(scanner, url):
    """Main function for network reconnaissance"""
    findings = []
    
    # Parse domain
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]  # Remove port if present
    
    scanner.add_finding(
        severity='INFO',
        category='Network Reconnaissance',
        title=f'🔍 Starting Network Scan for {domain}',
        description=f'Performing comprehensive network reconnaissance...',
        url=url
    )
    
    # 1. DNS Analysis
    findings.extend(_perform_dns_analysis(scanner, domain))
    
    # 2. Subdomain Enumeration
    findings.extend(_enumerate_subdomains(scanner, domain))
    
    # 3. Port Scanning
    findings.extend(_perform_port_scan(scanner, domain))
    
    # 4. Zone Transfer Attempt
    findings.extend(_attempt_zone_transfer(scanner, domain))
    
    return findings

def _perform_dns_analysis(scanner, domain):
    """Analyze DNS records"""
    findings = []
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                pass
        
        if dns_records:
            # Check for sensitive info in TXT records
            if 'TXT' in dns_records:
                for txt in dns_records['TXT']:
                    if any(keyword in txt.lower() for keyword in ['spf', 'dkim', 'dmarc', 'v=spf1', 'verification']):
                        continue  # Normal records
                    
                    # Potentially sensitive TXT record
                    if any(keyword in txt.lower() for keyword in ['password', 'key', 'secret', 'token', 'api']):
                        scanner.add_finding(
                            severity='HIGH',
                            category='Information Disclosure',
                            title='🔍 Sensitive Data in DNS TXT Record',
                            description=f'''**SENSITIVE INFORMATION IN DNS**\n\n'''
                                      f'''TXT Record: `{txt}`\n\n'''
                                      f'''This may contain credentials or API keys!''',
                            url=f'dns://{domain}',
                            remediation='Remove sensitive data from public DNS records'
                        )
                        findings.append(True)
            
            # Log DNS info
            dns_info = '\n'.join([f'{k}: {", ".join(v)}' for k, v in dns_records.items()])
            scanner.add_finding(
                severity='INFO',
                category='DNS Analysis',
                title=f'📋 DNS Records for {domain}',
                description=f'''**DNS RECORDS DISCOVERED:**\n\n```\n{dns_info}\n```''',
                url=f'dns://{domain}'
            )
    
    except Exception as e:
        pass
    
    return findings

def _enumerate_subdomains(scanner, domain):
    """Enumerate subdomains"""
    findings = []
    discovered_subdomains = set()
    
    def check_subdomain(subdomain):
        """Check if subdomain exists"""
        full_domain = f"{subdomain}.{domain}"
        try:
            # Try to resolve
            socket.gethostbyname(full_domain)
            
            # Try HTTP/HTTPS
            for protocol in ['https', 'http']:
                try:
                    response = requests.get(f'{protocol}://{full_domain}', timeout=3, verify=False)
                    return full_domain, protocol, response.status_code
                except:
                    pass
            
            return full_domain, None, None
        except:
            return None, None, None
    
    # Use thread pool for faster scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain, sub): sub 
            for sub in COMMON_SUBDOMAINS
        }
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            subdomain_result, protocol, status = future.result()
            if subdomain_result:
                discovered_subdomains.add((subdomain_result, protocol, status))
    
    if discovered_subdomains:
        subdomain_list = '\n'.join([
            f"- {sub} ({protocol or 'DNS only'}{f' - {status}' if status else ''})"
            for sub, protocol, status in sorted(discovered_subdomains)
        ])
        
        scanner.add_finding(
            severity='MEDIUM' if len(discovered_subdomains) > 10 else 'INFO',
            category='Subdomain Enumeration',
            title=f'🌐 Discovered {len(discovered_subdomains)} Subdomains',
            description=f'''**SUBDOMAINS FOUND:**\n\n```\n{subdomain_list}\n```\n\n'''
                      f'''**ATTACK SURFACE:**\n'''
                      f'''Each subdomain is a potential entry point.\n'''
                      f'''Check each for vulnerabilities separately.\n\n'''
                      f'''**AUTOMATED SCANNING:**\n'''
                      f'''```bash\n'''
                      f'''# Scan all subdomains:\n'''
                      f'''for sub in {" ".join([s[0] for s in list(discovered_subdomains)[:5]])}; do\n'''
                      f'''    echo "[+] Scanning $sub"\n'''
                      f'''    nmap -sV $sub\n'''
                      f'''    nikto -h https://$sub\n'''
                      f'''done\n'''
                      f'''```''',
            url=f'dns://{domain}',
            remediation='Minimize public subdomains. Use internal DNS for internal services.'
        )
        findings.append(True)
    
    return findings

def _perform_port_scan(scanner, domain):
    """Scan common ports"""
    findings = []
    
    try:
        # Resolve domain to IP
        ip_address = socket.gethostbyname(domain)
        
        def scan_port(port):
            """Scan a single port"""
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return port if result == 0 else None
        
        # Scan ports in parallel
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in COMMON_PORTS}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future.result()
                if port:
                    open_ports.append(port)
        
        if open_ports:
            # Check for critical exposed ports
            critical_open = [p for p in open_ports if p in CRITICAL_PORTS]
            
            if critical_open:
                critical_list = '\n'.join([
                    f"- Port {port}: {CRITICAL_PORTS[port]}"
                    for port in critical_open
                ])
                
                scanner.add_finding(
                    severity='CRITICAL',
                    category='Network Security',
                    title=f'🚨 CRITICAL Ports Exposed: {len(critical_open)} Database/Admin Services',
                    description=f'''**CRITICAL SERVICES EXPOSED TO INTERNET**\n\n'''
                              f'''IP: {ip_address}\n'''
                              f'''Open critical ports:\n```\n{critical_list}\n```\n\n'''
                              f'''**IMMEDIATE EXPLOITATION:**\n'''
                              f'''```bash\n'''
                              f'''# These services should NEVER be public!\n'''
                              + '\n'.join([
                                  f'''# {CRITICAL_PORTS[p]}: telnet {ip_address} {p}'''
                                  for p in critical_open[:3]
                              ]) +
                              f'''\n```\n\n'''
                              f'''**AUTOMATED ATTACK:**\n'''
                              f'''```bash\n'''
                              f'''# Brute force exposed services:\n'''
                              f'''hydra -L users.txt -P passwords.txt {ip_address} ssh\n'''
                              f'''nmap --script mongodb-brute {ip_address} -p 27017\n'''
                              f'''```''',
                    url=f'tcp://{ip_address}',
                    remediation='''**URGENT:**\n1. Close these ports immediately\n2. Use firewall to block external access\n3. Only allow from VPN/trusted IPs\n4. Enable authentication on all services'''
                )
                findings.append(True)
            
            # Report all open ports
            port_list = ', '.join([f"{p}{f' ({CRITICAL_PORTS[p]})' if p in CRITICAL_PORTS else ''}" for p in sorted(open_ports)])
            
            scanner.add_finding(
                severity='MEDIUM' if critical_open else 'INFO',
                category='Port Scanning',
                title=f'🔍 Found {len(open_ports)} Open Ports',
                description=f'''**OPEN PORTS:**\n```\n{port_list}\n```\n\n'''
                          f'''IP Address: {ip_address}''',
                url=f'tcp://{ip_address}'
            )
    
    except Exception as e:
        pass
    
    return findings

def _attempt_zone_transfer(scanner, domain):
    """Attempt DNS zone transfer"""
    findings = []
    
    try:
        # Get nameservers
        ns_records = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns) for ns in ns_records]
        
        for ns in nameservers:
            try:
                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                
                if zone:
                    # Zone transfer succeeded - CRITICAL vulnerability!
                    zone_data = []
                    for name, node in zone.nodes.items():
                        zone_data.append(str(name))
                    
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='DNS Security',
                        title='🚨 DNS ZONE TRANSFER ALLOWED - Full Domain Exposure!',
                        description=f'''**DNS ZONE TRANSFER VULNERABILITY**\n\n'''
                                  f'''Nameserver: {ns}\n'''
                                  f'''Discovered {len(zone_data)} DNS records!\n\n'''
                                  f'''**FULL DOMAIN ENUMERATION:**\n'''
                                  f'''```bash\n'''
                                  f'''# Anyone can download your entire DNS zone:\n'''
                                  f'''dig @{ns} {domain} AXFR\n\n'''
                                  f'''# Sample records discovered:\n'''
                                  + '\n'.join(zone_data[:20]) +
                                  f'''\n```\n\n'''
                                  f'''This reveals:\n'''
                                  f'''- ALL subdomains (including internal ones)\n'''
                                  f'''- Server IPs\n'''
                                  f'''- Mail servers\n'''
                                  f'''- Internal infrastructure\n\n'''
                                  f'''**ATTACKER POV:**\n'''
                                  f'''"Perfect! Now I know your entire network topology and can target specific internal systems."''',
                        url=f'dns://{ns}',
                        remediation='**URGENT:** Configure nameservers to deny zone transfers to untrusted hosts. Only allow from secondary nameservers.'
                    )
                    findings.append(True)
                    break  # Found one, stop checking
                    
            except:
                pass  # Zone transfer denied (expected)
    
    except Exception:
        pass
    
    return findings
