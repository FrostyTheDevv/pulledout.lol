#!/usr/bin/env python3
import hashlib
import base64
import os

files = [
    'static/css/style.css',
    'static/css/auth.css',
    'static/css/legal.css'
]

for filepath in files:
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            content = f.read()
            hash_digest = hashlib.sha384(content).digest()
            sri_hash = base64.b64encode(hash_digest).decode()
            print(f'{filepath}: sha384-{sri_hash}')
    else:
        print(f'{filepath}: FILE NOT FOUND')
