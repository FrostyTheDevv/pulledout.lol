"""
Database Exposure Checker Module
Tests for exposed databases and database management interfaces
"""

import requests
import socket
import re
from urllib.parse import urljoin

def check_database_exposure(scanner):
    """
    Check for exposed databases and database interfaces
    """
    try:
        base_url = scanner.target_url.rstrip('/')
        domain = scanner.target_url.split('//')[1].split('/')[0].split(':')[0]
        
        # Test for exposed database interfaces
        _test_db_interfaces(scanner, base_url)
        
        # Test for database ports
        _test_db_ports(scanner, domain)
        
        # Test for database connection strings in responses
        _test_connection_strings(scanner)
        
        # Test for exposed MongoDB
        _test_mongodb_exposure(scanner, domain)
        
    except Exception as e:
        print(f"Database exposure check error: {e}")

def _test_db_interfaces(scanner, base_url):
    """Test for exposed database management interfaces"""
    db_interfaces = [
        # phpMyAdmin
        ('phpmyadmin/', 'phpMyAdmin'),
        ('pma/', 'phpMyAdmin'),
        ('myadmin/', 'phpMyAdmin'),
        ('mysql/', 'phpMyAdmin'),
        ('dbadmin/', 'phpMyAdmin'),
        ('phpMyAdmin/', 'phpMyAdmin'),
        ('PMA/', 'phpMyAdmin'),
        
        # Adminer
        ('adminer/', 'Adminer'),
        ('adminer.php', 'Adminer'),
        
        # PostgreSQL
        ('pgadmin/', 'pgAdmin'),
        ('phppgadmin/', 'phpPgAdmin'),
        
        # MongoDB
        ('mongo-express/', 'mongo-express'),
        ('mongoexpress/', 'mongo-express'),
        
        # Redis
        ('redis-commander/', 'Redis Commander'),
        ('phpredmin/', 'phpRedmin'),
        
        # General DB tools
        ('sqladmin/', 'SQL Admin'),
        ('database/', 'Database Interface'),
        ('db/', 'Database Interface'),
    ]
    
    for path, interface_name in db_interfaces:
        test_url = urljoin(base_url + '/', path)
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=True, verify=False)
            
            if response.status_code == 200:
                # Check if it's actually the database interface
                interface_indicators = {
                    'phpMyAdmin': ['phpmyadmin', 'pma_username', 'pma_password'],
                    'Adminer': ['adminer', 'database system', 'login'],
                    'pgAdmin': ['pgadmin', 'postgresql'],
                    'mongo-express': ['mongo', 'mongodb', 'mongo-express'],
                    'Redis Commander': ['redis', 'commander'],
                }
                
                indicators = interface_indicators.get(interface_name, [interface_name.lower()])
                if any(indicator in response.text.lower() for indicator in indicators):
                    severity = 'CRITICAL' if response.status_code == 200 else 'HIGH'
                    
                    scanner.add_finding(
                        severity=severity,
                        category='Database Exposure',
                        title=f'Exposed {interface_name} interface',
                        description=f'Database management interface accessible at: {test_url}',
                        url=test_url,
                        remediation=f'Restrict {interface_name} access to internal network or require strong authentication'
                    )
                    break  # Don't spam if multiple paths lead to same interface
        except:
            pass

def _test_db_ports(scanner, domain):
    """Test for open database ports"""
    db_ports = {
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        1433: 'Microsoft SQL Server',
        1521: 'Oracle',
        5984: 'CouchDB',
        9200: 'Elasticsearch',
        5000: 'Flask/DB (common dev)',
        8086: 'InfluxDB',
        28015: 'RethinkDB',
        7000: 'Cassandra',
        7001: 'Cassandra',
        9042: 'Cassandra',
    }
    
    for port, db_name in db_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((domain, port))
            sock.close()
            
            if result == 0:
                scanner.add_finding(
                    severity='CRITICAL',
                    category='Database Exposure',
                    title=f'Open {db_name} port detected',
                    description=f'{db_name} port {port} is accessible from the internet',
                    url=f'{domain}:{port}',
                    remediation=f'Restrict {db_name} access to internal network only. Use firewall rules or security groups.'
                )
        except:
            pass

def _test_connection_strings(scanner):
    """Test for database connection strings in responses"""
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        connection_patterns = {
            r'mongodb(\+srv)?://[^\s\'"]+': 'MongoDB',
            r'mysql://[^\s\'"]+': 'MySQL',
            r'postgres://[^\s\'"]+': 'PostgreSQL',
            r'redis://[^\s\'"]+': 'Redis',
            r'Server=.+;Database=.+;': 'SQL Server',
            r'Data Source=.+;Initial Catalog=.+;': 'SQL Server',
            r'host=.+dbname=.+user=.+password=': 'PostgreSQL',
        }
        
        for pattern, db_type in connection_patterns.items():
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                for match in matches[:2]:  # Limit to first 2
                    # Mask sensitive parts
                    masked = re.sub(r'password[=:][^\s;]+', 'password=***', match, flags=re.IGNORECASE)
                    
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Database Exposure',
                        title=f'{db_type} connection string exposed',
                        description=f'Database connection string found in page: {masked[:100]}...',
                        url=scanner.target_url,
                        remediation='Never expose database connection strings in client-side code. Move to server-side environment variables.'
                    )
    except Exception as e:
        print(f"Connection string test error: {e}")

def _test_mongodb_exposure(scanner, domain):
    """Specific tests for MongoDB exposure"""
    # Test MongoDB HTTP interface (if enabled)
    try:
        response = requests.get(f'http://{domain}:28017/', timeout=5, verify=False)
        if response.status_code == 200 and 'mongo' in response.text.lower():
            scanner.add_finding(
                severity='CRITICAL',
                category='Database Exposure',
                title='MongoDB HTTP interface exposed',
                description='MongoDB administrative HTTP interface is publicly accessible',
                url=f'http://{domain}:28017/',
                remediation='Disable MongoDB HTTP interface and restrict database access'
            )
    except:
        pass
    
    # Test for common MongoDB connection strings in page
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if response:
            # Look for MongoDB Atlas connection strings
            atlas_pattern = r'mongodb\+srv://[^@]+@([a-z0-9.-]+\.mongodb\.net)'
            atlas_matches = re.findall(atlas_pattern, response.text, re.IGNORECASE)
            
            for cluster in set(atlas_matches):
                scanner.add_finding(
                    severity='HIGH',
                    category='Database Exposure',
                    title='MongoDB Atlas cluster detected',
                    description=f'MongoDB Atlas cluster: {cluster}',
                    url=scanner.target_url,
                    remediation='Ensure MongoDB Atlas has IP whitelist and strong authentication'
                )
    except:
        pass

def _test_elasticsearch_exposure(scanner, domain):
    """Test for exposed Elasticsearch"""
    try:
        response = requests.get(f'http://{domain}:9200/', timeout=5, verify=False)
        if response.status_code == 200:
            data = response.json()
            if 'cluster_name' in data:
                scanner.add_finding(
                    severity='CRITICAL',
                    category='Database Exposure',
                    title='Exposed Elasticsearch instance',
                    description=f'Elasticsearch cluster "{data.get("cluster_name")}" is publicly accessible',
                    url=f'http://{domain}:9200/',
                    remediation='Restrict Elasticsearch access and enable authentication (X-Pack Security)'
                )
    except:
        pass
