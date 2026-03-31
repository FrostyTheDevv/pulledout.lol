"""
Database Explorer Module
Connects to exposed databases and extracts real data to prove vulnerability
Only accesses unauthenticated/openly accessible databases
"""

import socket
import requests
import json
import pymongo  # type: ignore
import redis  # type: ignore
from urllib.parse import urlparse

def explore_exposed_databases(scanner):
    """
    Connect to exposed databases and extract real data
    Returns structured data for UI display
    """
    results = {
        'mongodb': [],
        'redis': [],
        'elasticsearch': [],
        'couchdb': [],
        'exposed': False
    }
    
    try:
        domain = urlparse(scanner.target_url).netloc.split(':')[0]
        
        # Test MongoDB
        mongo_data = _explore_mongodb(scanner, domain)
        if mongo_data:
            results['mongodb'] = mongo_data
            results['exposed'] = True
        
        # Test Redis
        redis_data = _explore_redis(scanner, domain)
        if redis_data:
            results['redis'] = redis_data
            results['exposed'] = True
        
        # Test Elasticsearch
        es_data = _explore_elasticsearch(scanner, domain)
        if es_data:
            results['elasticsearch'] = es_data
            results['exposed'] = True
        
        # Test CouchDB
        couch_data = _explore_couchdb(scanner, domain)
        if couch_data:
            results['couchdb'] = couch_data
            results['exposed'] = True
        
        return results
        
    except Exception as e:
        print(f"Database exploration error: {e}")
        return results

def _explore_mongodb(scanner, domain):
    """
    Connect to MongoDB and extract real data
    """
    try:
        # Try to connect without authentication
        client = pymongo.MongoClient(f'mongodb://{domain}:27017/', serverSelectionTimeoutMS=3000, connectTimeoutMS=3000)
        
        # Test connection by listing databases
        try:
            db_list = client.list_database_names()
        except Exception:
            return None
        
        if not db_list:
            return None
        
        mongo_data = {
            'accessible': True,
            'host': f'{domain}:27017',
            'databases': []
        }
        
        # Explore each database
        for db_name in db_list[:5]:  # Limit to first 5 DBs
            if db_name in ['admin', 'local', 'config']:
                continue
            
            db = client[db_name]
            collections = db.list_collection_names()
            
            db_info = {
                'name': db_name,
                'collections': []
            }
            
            # Get sample data from each collection
            for coll_name in collections[:10]:  # Limit to 10 collections
                try:
                    collection = db[coll_name]
                    count = collection.count_documents({})
                    
                    # Get sample documents
                    sample_docs = list(collection.find().limit(5))
                    
                    # Convert ObjectId to string for JSON serialization
                    for doc in sample_docs:
                        if '_id' in doc:
                            doc['_id'] = str(doc['_id'])
                    
                    db_info['collections'].append({
                        'name': coll_name,
                        'document_count': count,
                        'sample_data': sample_docs
                    })
                except Exception as e:
                    continue
            
            mongo_data['databases'].append(db_info)
        
        # Add finding with real data proof
        scanner.add_finding(
            severity='CRITICAL',
            category='Database Exposure',
            title='🔥 LIVE MONGODB DATA EXTRACTED - COMPLETE DATABASE BREACH',
            description=f'**ACTIVE DATABASE BREACH CONFIRMED**\n\n'
                      f'Successfully connected to MongoDB at {domain}:27017 without authentication!\n\n'
                      f'**EXTRACTED REAL DATA:**\n\n'
                      f'Found {len(mongo_data["databases"])} accessible databases:\n'
                      f'```json\n{json.dumps([db["name"] for db in mongo_data["databases"]], indent=2)}\n```\n\n'
                      f'**Total Collections:** {sum(len(db["collections"]) for db in mongo_data["databases"])}\n\n'
                      f'**PROOF - Sample Data Extracted:**\n'
                      f'```json\n{json.dumps(sample_docs[0] if sample_docs else {}, indent=2)}\n```\n\n'
                      f'This is REAL DATA from your database. An attacker can:\n'
                      f'- Download all {sum(coll["document_count"] for db in mongo_data["databases"] for coll in db["collections"])} documents\n'
                      f'- Modify or delete data\n'
                      f'- Hold data for ransom\n'
                      f'- Sell on dark web\n\n'
                      f'**FIX IMMEDIATELY:** Enable authentication and firewall MongoDB!',
            url=f'mongodb://{domain}:27017'
        )
        
        return mongo_data
        
    except Exception as e:
        return None

def _explore_redis(scanner, domain):
    """
    Connect to Redis and extract cached data
    """
    try:
        # Try to connect without password
        r = redis.Redis(host=domain, port=6379, socket_timeout=3, socket_connect_timeout=3, decode_responses=True)
        
        # Test connection
        try:
            r.ping()
        except Exception:
            return None
        
        redis_data = {
            'accessible': True,
            'host': f'{domain}:6379',
            'keys': []
        }
        
        # Get all keys
        try:
            keys = r.keys('*')[:100]  # Limit to 100 keys
        except Exception:
            return None
        
        # Get values for each key
        for key in keys[:20]:  # Show first 20
            try:
                key_type = r.type(key)
                value = None
                
                if key_type == 'string':
                    value = r.get(key)
                elif key_type == 'list':
                    value = r.lrange(key, 0, 4)
                elif key_type == 'set':
                    value = list(r.smembers(key))[:5]
                elif key_type == 'hash':
                    value = r.hgetall(key)
                
                redis_data['keys'].append({
                    'key': key,
                    'type': key_type,
                    'value': value
                })
            except Exception:
                continue
        
        # Add finding with real data
        scanner.add_finding(
            severity='CRITICAL',
            category='Cache Exposure',
            title='🔥 LIVE REDIS DATA EXTRACTED - SESSION HIJACKING POSSIBLE',
            description=f'**ACTIVE REDIS CACHE BREACH**\n\n'
                      f'Successfully connected to Redis at {domain}:6379 without password!\n\n'
                      f'**EXTRACTED REAL CACHE DATA:**\n\n'
                      f'Found {len(keys)} cache keys. Sample data:\n'
                      f'```json\n{json.dumps(redis_data["keys"][:5], indent=2)}\n```\n\n'
                      f'This cache likely contains:\n'
                      f'- Session tokens (for account hijacking)\n'
                      f'- User credentials\n'
                      f'- API keys and secrets\n'
                      f'- Temporary passwords\n\n'
                      f'**EXPLOITATION:** Steal session tokens to hijack user accounts!\n\n'
                      f'**FIX IMMEDIATELY:** Set requirepass in redis.conf and firewall port 6379!',
            url=f'redis://{domain}:6379'
        )
        
        return redis_data
        
    except Exception:
        return None

def _explore_elasticsearch(scanner, domain):
    """
    Connect to Elasticsearch and extract indices
    """
    try:
        # Try HTTP API access
        response = requests.get(f'http://{domain}:9200/_cat/indices?format=json', timeout=5)
        
        if response.status_code != 200:
            return None
        
        indices = response.json()
        
        es_data = {
            'accessible': True,
            'host': f'{domain}:9200',
            'indices': []
        }
        
        # Get sample data from each index
        for index in indices[:10]:  # Limit to 10 indices
            index_name = index.get('index', '')
            
            # Skip system indices
            if index_name.startswith('.'):
                continue
            
            try:
                # Get sample documents
                search_response = requests.get(
                    f'http://{domain}:9200/{index_name}/_search?size=5',
                    timeout=5
                )
                
                if search_response.status_code == 200:
                    search_data = search_response.json()
                    hits = search_data.get('hits', {}).get('hits', [])
                    
                    sample_docs = [hit.get('_source', {}) for hit in hits]
                    
                    es_data['indices'].append({
                        'name': index_name,
                        'doc_count': index.get('docs.count', 0),
                        'size': index.get('store.size', '0'),
                        'sample_data': sample_docs
                    })
            except Exception:
                continue
        
        if es_data['indices']:
            scanner.add_finding(
                severity='CRITICAL',
                category='Search Engine Exposure',
                title='🔥 LIVE ELASTICSEARCH DATA EXTRACTED - MASS DATA LEAK',
                description=f'**ELASTICSEARCH BREACH CONFIRMED**\n\n'
                          f'Successfully accessed Elasticsearch at {domain}:9200 without authentication!\n\n'
                          f'**EXTRACTED INDICES:**\n\n'
                          f'```json\n{json.dumps([idx["name"] for idx in es_data["indices"]], indent=2)}\n```\n\n'
                          f'**Total Documents:** {sum(idx["doc_count"] for idx in es_data["indices"])}\n\n'
                          f'**SAMPLE DATA EXTRACTED:**\n'
                          f'```json\n{json.dumps(es_data["indices"][0]["sample_data"][0] if es_data["indices"] and es_data["indices"][0]["sample_data"] else {}, indent=2)}\n```\n\n'
                          f'**ATTACKER CAN:**\n'
                          f'- Dump all data using elasticdump\n'
                          f'- Search for sensitive information\n'
                          f'- Modify or delete indices\n\n'
                          f'**FIX:** Enable X-Pack security and firewall port 9200!',
                url=f'http://{domain}:9200'
            )
        
        return es_data
        
    except Exception:
        return None

def _explore_couchdb(scanner, domain):
    """
    Connect to CouchDB and extract databases
    """
    try:
        # Try to access CouchDB HTTP API
        response = requests.get(f'http://{domain}:5984/_all_dbs', timeout=5)
        
        if response.status_code != 200:
            return None
        
        databases = response.json()
        
        couch_data = {
            'accessible': True,
            'host': f'{domain}:5984',
            'databases': []
        }
        
        # Get sample data from each database
        for db_name in databases[:10]:
            if db_name.startswith('_'):
                continue
            
            try:
                # Get database info
                db_response = requests.get(f'http://{domain}:5984/{db_name}', timeout=5)
                if db_response.status_code == 200:
                    db_info = db_response.json()
                    
                    # Get sample documents
                    docs_response = requests.get(f'http://{domain}:5984/{db_name}/_all_docs?limit=5&include_docs=true', timeout=5)
                    if docs_response.status_code == 200:
                        docs_data = docs_response.json()
                        sample_docs = [row.get('doc', {}) for row in docs_data.get('rows', [])]
                        
                        couch_data['databases'].append({
                            'name': db_name,
                            'doc_count': db_info.get('doc_count', 0),
                            'sample_data': sample_docs
                        })
            except Exception:
                continue
        
        if couch_data['databases']:
            scanner.add_finding(
                severity='CRITICAL',
                category='Database Exposure',
                title='🔥 LIVE COUCHDB DATA EXTRACTED - FULL DATABASE ACCESS',
                description=f'**COUCHDB BREACH CONFIRMED**\n\n'
                          f'Successfully accessed CouchDB at {domain}:5984 without authentication!\n\n'
                          f'**EXTRACTED DATABASES:**\n\n'
                          f'```json\n{json.dumps([db["name"] for db in couch_data["databases"]], indent=2)}\n```\n\n'
                          f'**SAMPLE DOCUMENTS:**\n'
                          f'```json\n{json.dumps(couch_data["databases"][0]["sample_data"][0] if couch_data["databases"] and couch_data["databases"][0]["sample_data"] else {}, indent=2)}\n```\n\n'
                          f'**FIX:** Enable authentication in local.ini and firewall port 5984!',
                url=f'http://{domain}:5984'
            )
        
        return couch_data
        
    except Exception:
        return None
