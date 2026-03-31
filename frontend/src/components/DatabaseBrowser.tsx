import { useState, useEffect } from 'react';
import axios from 'axios';

interface DatabaseBrowserProps {
  scanId: string;
}

export default function DatabaseBrowser({ scanId }: DatabaseBrowserProps) {
  const [dbData, setDbData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedDb, setSelectedDb] = useState<string>('');
  const [selectedCollection, setSelectedCollection] = useState<string>('');
  const [documents, setDocuments] = useState<any[]>([]);
  const [queryLimit, setQueryLimit] = useState(20);
  const [queryFilter, setQueryFilter] = useState('{}');

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

  const handleDatabaseSelect = (dbName: string) => {
    setSelectedDb(dbName);
    setSelectedCollection('');
    setDocuments([]);
  };

  const handleCollectionSelect = (collName: string, sampleData: any[]) => {
    setSelectedCollection(collName);
    setDocuments(sampleData || []);
  };

  const handleQuery = async () => {
    try {
      const response = await axios.post(`/api/tools/${scanId}/query-database`, {
        database: selectedDb,
        collection: selectedCollection,
        filter: queryFilter,
        limit: queryLimit
      });
      setDocuments(response.data.documents || []);
    } catch (error) {
      console.error('Query failed:', error);
    }
  };

  if (loading) {
    return (
      <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-neutral-800 rounded w-1/4"></div>
          <div className="h-4 bg-neutral-800 rounded"></div>
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
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
              </svg>
            </div>
          </div>
          <div className="flex-1">
            <h3 className="text-2xl font-bold text-red-400 mb-2">
              🔥 INTERACTIVE DATABASE BROWSER
            </h3>
            <p className="text-white text-lg mb-4">
              Browse and query live database data in real-time. All data shown below is ACTUALLY from your databases!
            </p>
            <div className="bg-black/50 rounded-lg p-4">
              <p className="text-red-300 font-semibold mb-2">⚠️ FULL DATABASE ACCESS</p>
              <p className="text-gray-300 text-sm">
                You can now browse through databases, collections, and documents just like an attacker would. Use the controls below to query data.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* MongoDB Browser */}
      {dbData.mongodb && dbData.mongodb.length > 0 && (
        <div className="bg-neutral-900 border border-green-500/50 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-green-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
                <path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z" />
                <path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z" />
              </svg>
            </div>
            <div>
              <h4 className="text-xl font-bold text-white">MongoDB Database Browser</h4>
              <p className="text-sm text-gray-400">Host: {dbData.mongodb[0].host}</p>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4">
            {/* Left Sidebar - Database & Collection Tree */}
            <div className="col-span-3 space-y-2">
              <h5 className="text-sm font-bold text-white mb-3">Databases & Collections</h5>
              {dbData.mongodb[0].databases.map((db: any, dbIdx: number) => (
                <div key={dbIdx} className="bg-neutral-950 rounded-lg overflow-hidden">
                  <button
                    onClick={() => handleDatabaseSelect(db.name)}
                    className={`w-full px-3 py-2 text-left font-semibold transition ${
                      selectedDb === db.name
                        ? 'bg-green-600 text-white'
                        : 'bg-neutral-900 text-gray-300 hover:bg-neutral-800'
                    }`}
                  >
                    📁 {db.name}
                  </button>
                  
                  {selectedDb === db.name && (
                    <div className="bg-neutral-950 p-2 space-y-1">
                      {db.collections.map((coll: any, collIdx: number) => (
                        <button
                          key={collIdx}
                          onClick={() => handleCollectionSelect(coll.name, coll.sample_data)}
                          className={`w-full px-3 py-1.5 text-left text-sm rounded transition ${
                            selectedCollection === coll.name
                              ? 'bg-green-700 text-white'
                              : 'text-gray-400 hover:bg-neutral-900 hover:text-white'
                          }`}
                        >
                          📄 {coll.name}
                          <span className="text-xs ml-2">({coll.document_count})</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Right Panel - Data Viewer */}
            <div className="col-span-9 space-y-4">
              {!selectedCollection ? (
                <div className="bg-neutral-950 rounded-lg p-8 text-center">
                  <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-gray-400 text-lg">Select a database and collection to view data</p>
                </div>
              ) : (
                <>
                  {/* Query Builder */}
                  <div className="bg-neutral-950 rounded-lg p-4">
                    <h5 className="text-sm font-bold text-white mb-3">Query Builder</h5>
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Filter (JSON)</label>
                        <input
                          type="text"
                          value={queryFilter}
                          onChange={(e) => setQueryFilter(e.target.value)}
                          placeholder='{"status": "active"}'
                          className="w-full bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-white text-sm font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Limit</label>
                        <div className="flex space-x-2">
                          <input
                            type="number"
                            value={queryLimit}
                            onChange={(e) => setQueryLimit(parseInt(e.target.value))}
                            className="flex-1 bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-white text-sm"
                            aria-label="Query limit"
                          />
                          <button
                            onClick={handleQuery}
                            className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded font-semibold"
                          >
                            Query
                          </button>
                        </div>
                      </div>
                    </div>
                    <p className="text-xs text-gray-500">
                      💡 Try: {`{}`} for all, {`{"field": "value"}`} to filter, or {`{"field": {"$gt": 100}}`} for operators
                    </p>
                  </div>

                  {/* Document List */}
                  <div className="bg-neutral-950 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h5 className="text-sm font-bold text-white">
                        Documents ({documents.length})
                      </h5>
                      <span className="text-xs text-gray-400">
                        Collection: {selectedDb}.{selectedCollection}
                      </span>
                    </div>

                    <div className="space-y-3 max-h-[600px] overflow-y-auto">
                      {documents.map((doc, idx) => (
                        <div key={idx} className="bg-neutral-900 rounded-lg p-3 border border-neutral-800">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs text-gray-400">Document #{idx + 1}</span>
                            {doc._id && (
                              <span className="text-xs font-mono text-gray-500">
                                ID: {String(doc._id).substring(0, 16)}...
                              </span>
                            )}
                          </div>
                          <div className="bg-black rounded p-3 overflow-x-auto">
                            <pre className="text-green-400 text-xs font-mono">
                              {JSON.stringify(doc, null, 2)}
                            </pre>
                          </div>
                        </div>
                      ))}

                      {documents.length === 0 && (
                        <div className="text-center py-8 text-gray-500">
                          No documents found. Try adjusting your query filter.
                        </div>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* CLI Connection Instructions */}
          <div className="mt-6 bg-red-900/20 border border-red-500 rounded-lg p-4">
            <p className="text-red-300 font-semibold mb-2">🔧 Connect with CLI:</p>
            <div className="bg-black rounded p-3">
              <pre className="text-green-400 text-xs font-mono">
{`# Install MongoDB shell
npm install -g mongosh

# Connect to database
mongosh "mongodb://${dbData.mongodb[0].host}"

# List databases
show dbs

# Use database
use ${selectedDb || 'database_name'}

# List collections
show collections

# Query collection
db.${selectedCollection || 'collection_name'}.find().limit(20)

# Export all data
mongodump --host ${dbData.mongodb[0].host} --out ./dump/`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Fix Instructions */}
      <div className="bg-red-900/10 border-2 border-red-500 rounded-lg p-6">
        <h4 className="text-xl font-bold text-red-400 mb-4">🚨 IMMEDIATELY SECURE YOUR DATABASE</h4>
        <div className="space-y-3 text-white text-sm">
          <p className="font-semibold">Your database has NO AUTHENTICATION!</p>
          <ol className="list-decimal list-inside space-y-2">
            <li><strong>Enable Authentication:</strong> Create admin user and require authentication</li>
            <li><strong>Bind to Localhost:</strong> Change bind_ip to 127.0.0.1 (local only)</li>
            <li><strong>Use Firewall:</strong> Block database ports from public internet</li>
            <li><strong>Enable TLS/SSL:</strong> Encrypt all database connections</li>
            <li><strong>Regular Backups:</strong> Assume data is compromised, restore from clean backup</li>
            <li><strong>Audit Logs:</strong> Check connection logs for unauthorized access</li>
          </ol>
          
          <div className="mt-4 bg-black rounded p-3">
            <p className="text-gray-400 text-xs mb-2">MongoDB Security Config:</p>
            <pre className="text-green-400 text-xs font-mono">
{`# /etc/mongod.conf
security:
  authorization: enabled

net:
  bindIp: 127.0.0.1
  port: 27017

# Create admin user:
# mongosh
# use admin
# db.createUser({
#   user: "admin",
#   pwd: "strong_password_here",
#   roles: ["root"]
# })`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
