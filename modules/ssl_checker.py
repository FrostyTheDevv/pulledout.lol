"""
SSL/TLS Security Checker Module - State of the Art
Comprehensive SSL/TLS configuration and cryptography analysis
"""

import socket
import ssl
from datetime import datetime
import urllib.parse

def check_ssl_tls(scanner):
    """
    Perform comprehensive SSL/TLS security checks
    Analyzes certificates, TLS versions, cipher suites, and configuration
    """
    
    parsed_url = urllib.parse.urlparse(scanner.target_url)
    
    # Only check HTTPS sites
    if parsed_url.scheme != 'https':
        return  # Transport security module handles non-HTTPS
    
    hostname = parsed_url.hostname
    port = parsed_url.port or 443
    
    try:
        # ==================== CREATE SSL CONTEXT AND CONNECT ====================
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # ==================== CERTIFICATE EXPIRATION ====================
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %GMT')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %GMT')
                days_until_expiry = (not_after - datetime.now()).days
                
                if days_until_expiry < 0:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cryptography / TLS',
                        title='SSL certificate expired',
                        description=f'SSL certificate expired {abs(days_until_expiry)} days ago on {not_after.strftime("%Y-%m-%d")}',
                        url=scanner.target_url,
                        remediation='Renew the SSL certificate immediately'
                    )
                elif days_until_expiry < 30:
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Cryptography / TLS',
                        title='SSL certificate expiring soon',
                        description=f'SSL certificate expires in {days_until_expiry} days ({not_after.strftime("%Y-%m-%d")})',
                        url=scanner.target_url,
                        remediation='Renew the SSL certificate before expiration'
                    )
                elif days_until_expiry < 90:
                    scanner.add_finding(
                        severity='LOW',
                        category='Cryptography / TLS',
                        title='SSL certificate expires within 90 days',
                        description=f'Certificate expires in {days_until_expiry} days ({not_after.strftime("%Y-%m-%d")})',
                        url=scanner.target_url,
                        remediation='Consider renewing the certificate soon'
                    )
                else:
                    # Certificate is valid for more than 90 days - report as INFO
                    scanner.add_finding(
                        severity='INFO',
                        category='Cryptography / TLS',
                        title='SSL certificate valid',
                        description=f'Certificate is valid until {not_after.strftime("%Y-%m-%d")} ({days_until_expiry} days remaining)',
                        url=scanner.target_url,
                        remediation=''
                    )
                
                # ==================== TLS VERSION ====================
                if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cryptography / TLS',
                        title=f'Insecure TLS version: {version}',
                        description=f'Server uses {version} which has known critical vulnerabilities',
                        url=scanner.target_url,
                        remediation='Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1. Use only TLSv1.2 and TLSv1.3'
                    )
                elif version == 'TLSv1.2':
                    scanner.add_finding(
                        severity='INFO',
                        category='Cryptography / TLS',
                        title=f'TLS version: {version}',
                        description='Server uses TLSv1.2 (acceptable, but TLSv1.3 is preferred)',
                        url=scanner.target_url,
                        remediation='Consider enabling TLSv1.3 for improved security and performance'
                    )
                elif version == 'TLSv1.3':
                    scanner.add_finding(
                        severity='INFO',
                        category='Cryptography / TLS',
                        title=f'TLS version: {version}',
                        description='Server uses TLSv1.3 (latest and most secure)',
                        url=scanner.target_url,
                        remediation=''
                    )
                
                # ==================== CIPHER SUITE ====================
                cipher_name, cipher_version, cipher_bits = cipher
                
                # Check for weak ciphers
                weak_cipher_patterns = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                if any(pattern in cipher_name.upper() for pattern in weak_cipher_patterns):
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cryptography / TLS',
                        title='Weak cipher suite detected',
                        description=f'Server uses weak cipher: {cipher_name}',
                        url=scanner.target_url,
                        remediation='Disable weak ciphers. Use only strong ciphers (AES-GCM, ChaCha20-Poly1305)'
                    )
                
                # Check cipher strength
                if cipher_bits < 128:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cryptography / TLS',
                        title='Weak encryption strength',
                        description=f'Cipher uses only {cipher_bits} bits (minimum should be 128 bits)',
                        url=scanner.target_url,
                        remediation='Use ciphers with at least 128-bit encryption'
                    )
                
                # ==================== CERTIFICATE VALIDATION ====================
                # Check for common name/SAN
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject.get('commonName', '')
                
                san_list = []
                if 'subjectAltName' in cert:
                    san_list = [entry[1] for entry in cert['subjectAltName']]
                
                # Check if hostname matches certificate
                hostname_match = (hostname == common_name or 
                                hostname in san_list or 
                                any(san.startswith('*.') and hostname.endswith(san[1:]) for san in san_list))
                
                if not hostname_match:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cryptography / TLS',
                        title='Certificate hostname mismatch',
                        description=f'Certificate CN/SAN does not match hostname {hostname}',
                        url=scanner.target_url,
                        remediation='Ensure certificate is issued for the correct hostname'
                    )
                
                # ==================== CERTIFICATE ISSUER ====================
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_cn = issuer.get('commonName', 'Unknown')
                
                # Check for self-signed (issuer == subject)
                if issuer.get('commonName') == subject.get('commonName'):
                    scanner.add_finding(
                        severity='HIGH',
                        category='Cryptography / TLS',
                        title='Self-signed certificate detected',
                        description='Certificate is self-signed and not from a trusted CA',
                        url=scanner.target_url,
                        remediation='Obtain certificate from a trusted Certificate Authority'
                    )
                
    except ssl.SSLError as e:
        scanner.add_finding(
            severity='HIGH',
            category='Cryptography / TLS',
            title='SSL/TLS error',
            description=f'SSL/TLS connection error: {str(e)}',
            url=scanner.target_url,
            remediation='Fix SSL/TLS configuration issues'
        )
    except socket.timeout:
        scanner.add_finding(
            severity='MEDIUM',
            category='Availability / Performance',
            title='SSL/TLS connection timeout',
            description='Connection to server timed out during SSL/TLS handshake',
            url=scanner.target_url,
            remediation ='Check server availability and network connectivity'
        )
    except Exception as e:
        # Report when SSL checks cannot be performed
        scanner.add_finding(
            severity='INFO',
            category='Cryptography / TLS',
            title='SSL/TLS check skipped',
            description=f'Unable to perform detailed SSL/TLS analysis: {str(e)[:100]}',
            url=scanner.target_url,
            remediation='Ensure server is accessible and supports standard SSL/TLS connections'
        )
