import { useState, useEffect } from 'react';
import axios from 'axios';

interface DatabaseExplorerProps {
  scanId: string;
}

export default function DatabaseExplorer({ scanId }: DatabaseExplorerProps) {
  const [dbData, setDbData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDatabaseData();
  }, [scanId]);

  const fetchDatabaseData = async () => {
    try {
      const response = await axios.get(`/api/tools/${scanId}/database-explorer`);
      setDbData(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch database data:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-neutral-800 rounded w-1/4"></div>
          <div className="h-4 bg-neutral-800 rounded"></div>
          <div className="h-4 bg-neutral-800 rounded w-3/4"></div>
        </div>
      </div>
    );
  }

  if (!dbData || !dbData.exposed) {
    return null;
  }

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-red-900/20 to-orange-900/20 border-2 border-red-500 rounded-lg p-6">
        <div className="flex items-start space-x-4">
          <div className="flex-shrink-0">
            <div className="w-12 h-12 bg-red-500 rounded-lg flex items-center justify-center">
              <svg className="w-7 h-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
          <div className="flex-1">
            <h3 className="text-2xl font-bold text-red-400 mb-2">
              🔥 LIVE DATABASE BREACH CONFIRMED
            </h3>
            <p className="text-white text-lg mb-4">
              Successfully extracted REAL DATA from exposed databases without authentication!
            </p>
            <div className="bg-black/50 rounded-lg p-4">
              <p className="text-red-300 font-semibold mb-2">⚠️ CRITICAL SECURITY BREACH</p>
              <p className="text-gray-300 text-sm">
                The data displayed below is LIVE and was actually extracted from your database servers.
                This proves anyone on the internet can access this data right now.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* MongoDB Explorer */}
      {dbData.mongodb && dbData.mongodb.length > 0 && (
        <div className="bg-neutral-900 border border-red-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-green-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
                <path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z" />
                <path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">MongoDB - LIVE DATA EXTRACTED</h4>
              <p className="text-sm text-gray-400">Host: {dbData.mongodb[0].host}</p>
            </div>
          </div>

          {dbData.mongodb[0].databases.map((db: any, dbIdx: number) => (
            <div key={dbIdx} className="mb-6 bg-neutral-950 rounded-lg p-4 border border-neutral-800">
              <div className="flex items-center justify-between mb-4">
                <h5 className="text-lg font-bold text-green-400">📁 Database: {db.name}</h5>
                <span className="text-sm text-gray-400">{db.collections.length} collections</span>
              </div>

              {db.collections.map((coll: any, collIdx: number) => (
                <div key={collIdx} className="mb-4">
                  <div className="bg-neutral-900 rounded-lg p-3 mb-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-white">📄 {coll.name}</span>
                      <span className="text-sm text-gray-400">{coll.document_count} documents</span>
                    </div>
                  </div>

                  {coll.sample_data && coll.sample_data.length > 0 && (
                    <div className="ml-4">
                      <p className="text-xs text-red-400 mb-2">⚠️ LIVE DATA FROM YOUR DATABASE:</p>
                      <div className="bg-black rounded-lg p-4 overflow-x-auto">
                        <pre className="text-green-400 text-xs font-mono">
                          {JSON.stringify(coll.sample_data, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ))}

          <div className="mt-4 bg-red-900/20 border border-red-500 rounded-lg p-4">
            <p className="text-red-300 font-semibold mb-2">💀 EXPLOITATION COMMANDS:</p>
            <div className="bg-black rounded p-3">
              <pre className="text-green-400 text-xs font-mono">
{`# Connect to MongoDB (No password needed!)
mongo ${dbData.mongodb[0].host}

# Dump entire database
mongodump --host ${dbData.mongodb[0].host} --out ./stolen_data/

# This extracts ALL your data to attacker's computer!`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Redis Explorer */}
      {dbData.redis && dbData.redis.length > 0 && (
        <div className="bg-neutral-900 border border-red-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-red-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">Redis Cache - SESSION TOKENS EXPOSED</h4>
              <p className="text-sm text-gray-400">Host: {dbData.redis[0].host}</p>
            </div>
          </div>

          <div className="bg-neutral-950 rounded-lg p-4 border border-neutral-800">
            <p className="text-sm text-yellow-400 mb-3">🔑 {dbData.redis[0].keys.length} cache keys found - Likely contains session tokens!</p>
            
            {dbData.redis[0].keys.slice(0, 10).map((key: any, idx: number) => (
              <div key={idx} className="mb-3 bg-neutral-900 rounded p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-white font-mono text-sm">{key.key}</span>
                  <span className="text-xs text-gray-400 uppercase">{key.type}</span>
                </div>
                <div className="bg-black rounded p-2">
                  <pre className="text-green-400 text-xs font-mono overflow-x-auto">
                    {typeof key.value === 'object' ? JSON.stringify(key.value, null, 2) : String(key.value)}
                  </pre>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 bg-red-900/20 border border-red-500 rounded-lg p-4">
            <p className="text-red-300 font-semibold mb-2">🎯 SESSION HIJACKING:</p>
            <div className="bg-black rounded p-3">
              <pre className="text-green-400 text-xs font-mono">
{`# Connect to Redis
redis-cli -h ${dbData.redis[0].host.split(':')[0]}

# Get all keys (session tokens, passwords, etc.)
KEYS *

# Steal session token
GET session:user:12345

# Now attacker can hijack that user's account!`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Elasticsearch Explorer */}
      {dbData.elasticsearch && dbData.elasticsearch.length > 0 && (
        <div className="bg-neutral-900 border border-red-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-yellow-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">Elasticsearch - MASS DATA DUMP</h4>
              <p className="text-sm text-gray-400">Host: {dbData.elasticsearch[0].host}</p>
            </div>
          </div>

          {dbData.elasticsearch[0].indices.map((index: any, idx: number) => (
            <div key={idx} className="mb-4 bg-neutral-950 rounded-lg p-4 border border-neutral-800">
              <div className="flex items-center justify-between mb-3">
                <h5 className="text-lg font-bold text-yellow-400">📊 Index: {index.name}</h5>
                <div className="text-sm text-gray-400">
                  <span>{index.doc_count} docs</span>
                  <span className="ml-3">{index.size}</span>
                </div>
              </div>

              {index.sample_data && index.sample_data.length > 0 && (
                <div>
                  <p className="text-xs text-red-400 mb-2">⚠️ REAL ELASTICSEARCH DATA:</p>
                  <div className="bg-black rounded-lg p-4 overflow-x-auto">
                    <pre className="text-green-400 text-xs font-mono">
                      {JSON.stringify(index.sample_data[0], null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ))}

          <div className="mt-4 bg-red-900/20 border border-red-500 rounded-lg p-4">
            <p className="text-red-300 font-semibold mb-2">💾 MASS DATA EXTRACTION:</p>
            <div className="bg-black rounded p-3">
              <pre className="text-green-400 text-xs font-mono">
{`# Install elasticdump
npm install -g elasticdump

# Dump ALL data from Elasticsearch
elasticdump --input=http://${dbData.elasticsearch[0].host} --output=stolen_data.json

# Attacker now has your entire search index!`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* CouchDB Explorer */}
      {dbData.couchdb && dbData.couchdb.length > 0 && (
        <div className="bg-neutral-900 border border-red-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-orange-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">CouchDB - COMPLETE ACCESS</h4>
              <p className="text-sm text-gray-400">Host: {dbData.couchdb[0].host}</p>
            </div>
          </div>

          {dbData.couchdb[0].databases.map((db: any, idx: number) => (
            <div key={idx} className="mb-4 bg-neutral-950 rounded-lg p-4 border border-neutral-800">
              <div className="flex items-center justify-between mb-3">
                <h5 className="text-lg font-bold text-orange-400">📁 {db.name}</h5>
                <span className="text-sm text-gray-400">{db.doc_count} documents</span>
              </div>

              {db.sample_data && db.sample_data.length > 0 && (
                <div className="bg-black rounded-lg p-4 overflow-x-auto">
                  <pre className="text-green-400 text-xs font-mono">
                    {JSON.stringify(db.sample_data[0], null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Fix Instructions */}
      <div className="bg-red-900/10 border-2 border-red-500 rounded-lg p-6">
        <h4 className="text-xl font-bold text-red-400 mb-4">🚨 IMMEDIATE FIX REQUIRED</h4>
        <div className="space-y-3 text-white">
          <p className="font-semibold">Your databases are COMPLETELY open to the internet!</p>
          <ol className="list-decimal list-inside space-y-2 text-sm">
            <li>Enable authentication on ALL database servers</li>
            <li>Configure firewall rules to block public database ports</li>
            <li>Use VPN or private network for database access</li>
            <li>Rotate ALL credentials and API keys immediately</li>
            <li>Audit access logs for unauthorized connections</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
