import { useState, useEffect } from 'react';
import axios from 'axios';

interface ExposedFilesViewerProps {
  scanId: string;
}

export default function ExposedFilesViewer({ scanId }: ExposedFilesViewerProps) {
  const [filesData, setFilesData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);

  useEffect(() => {
    fetchFilesData();
  }, [scanId]);

  const fetchFilesData = async () => {
    try {
      const response = await axios.get(`/api/tools/${scanId}/exposed-files-viewer`);
      setFilesData(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch files data:', error);
      setLoading(false);
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

  if (!filesData || !filesData.files_found) {
    return null;
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-600';
      case 'HIGH': return 'bg-orange-600';
      case 'MEDIUM': return 'bg-yellow-600';
      case 'LOW': return 'bg-blue-600';
      default: return 'bg-gray-600';
    }
  };

  const getFileIcon = (filename: string) => {
    if (filename.endsWith('.env') || filename.endsWith('.config')) return '🔐';
    if (filename.endsWith('.sql') || filename.endsWith('.db')) return '🗄️';
    if (filename.endsWith('.log')) return '📋';
    if (filename.endsWith('.json') || filename.endsWith('.xml')) return '📄';
    if (filename.endsWith('.zip') || filename.endsWith('.tar')) return '📦';
    if (filename.endsWith('.git')) return '🌿';
    return '📁';
  };

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-yellow-900/20 to-red-900/20 border-2 border-yellow-500 rounded-lg p-6">
        <div className="flex items-start space-x-4">
          <div className="flex-shrink-0">
            <div className="w-12 h-12 bg-yellow-500 rounded-lg flex items-center justify-center">
              <svg className="w-7 h-7 text-white" fill="none" viewBox="0 0 24024" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
          </div>
          <div className="flex-1">
            <h3 className="text-2xl font-bold text-yellow-400 mb-2">
              📂 SENSITIVE FILES PUBLICLY ACCESSIBLE
            </h3>
            <p className="text-white text-lg mb-4">
              Found {filesData.total_files} exposed files containing sensitive data!
            </p>
            <div className="bg-black/50 rounded-lg p-4">
              <p className="text-yellow-300 font-semibold mb-2">⚠️ DATA EXPOSURE</p>
              <p className="text-gray-300 text-sm">
                These files are accessible without authentication. Attackers can download configuration files, credentials, and sensitive data.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* File Categories */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {filesData.categories && Object.entries(filesData.categories).map(([category, count]: [string, any]) => (
          <div key={category} className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-white mb-1">{count}</div>
            <div className="text-sm text-gray-400 capitalize">{category.replace('_', ' ')}</div>
          </div>
        ))}
      </div>

      {/* Exposed Files List */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
        <h4 className="text-xl font-bold text-white mb-4">📂 Exposed Files</h4>
        <div className="space-y-3">
          {filesData.files && filesData.files.map((file: any, idx: number) => (
            <div key={idx} className="bg-neutral-950 border border-neutral-800 rounded-lg overflow-hidden">
              <button
                onClick={() => setSelectedFile(selectedFile === file.url ? null : file.url)}
                className="w-full px-4 py-3 flex items-center justify-between hover:bg-neutral-900 transition"
              >
                <div className="flex items-center space-x-3">
                  <span className="text-2xl">{getFileIcon(file.name)}</span>
                  <div className="text-left">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-white text-sm">{file.name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded text-white font-semibold ${getSeverityColor(file.severity)}`}>
                        {file.severity}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">{file.url}</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-xs text-gray-400">{file.size}</span>
                  <svg
                    className={`w-5 h-5 text-gray-400 transition-transform ${
                      selectedFile === file.url ? 'rotate-180' : ''
                    }`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </button>

              {selectedFile === file.url && (
                <div className="px-4 pb-4 border-t border-neutral-800 pt-4">
                  {/* File Details */}
                  <div className="mb-4">
                    <h5 className="text-sm font-semibold text-white mb-2">File Details:</h5>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-gray-400">Type:</span>
                        <span className="text-white ml-2">{file.type}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Found:</span>
                        <span className="text-white ml-2">{file.discovered_at}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Status Code:</span>
                        <span className="text-green-400 ml-2">{file.status_code}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Content-Type:</span>
                        <span className="text-white ml-2">{file.content_type}</span>
                      </div>
                    </div>
                  </div>

                  {/* File Content Preview */}
                  {file.content && (
                    <div className="mb-4">
                      <h5 className="text-sm font-semibold text-red-400 mb-2">⚠️ ACTUAL FILE CONTENT:</h5>
                      <div className="bg-black rounded-lg p-3 overflow-x-auto max-h-96">
                        <pre className="text-green-400 text-xs font-mono">
                          {file.content}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* Sensitive Data Found */}
                  {file.sensitive_data && file.sensitive_data.length > 0 && (
                    <div className="mb-4 bg-red-900/20 border border-red-500 rounded-lg p-3">
                      <h5 className="text-sm font-semibold text-red-400 mb-2">🔑 Sensitive Data Found:</h5>
                      <ul className="space-y-1">
                        {file.sensitive_data.map((data: any, didx: number) => (
                          <li key={didx} className="text-xs text-red-300">
                            • <span className="font-semibold">{data.type}:</span> {data.value}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Download Command */}
                  <div className="bg-neutral-900 border border-neutral-700 rounded-lg p-3">
                    <p className="text-xs text-gray-400 mb-2">💀 Attacker Download Command:</p>
                    <div className="bg-black rounded p-2">
                      <code className="text-green-400 text-xs font-mono">
                        wget {file.url} -O {file.name}
                      </code>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Fix Instructions */}
      <div className="bg-red-900/10 border-2 border-red-500 rounded-lg p-6">
        <h4 className="text-xl font-bold text-red-400 mb-4">🔒 How to Fix</h4>
        <div className="space-y-3 text-white text-sm">
          <ol className="list-decimal list-inside space-y-2">
            <li><strong>.env files:</strong> Never commit to version control, use environment variables</li>
            <li><strong>.git folder:</strong> Block access in web server config (nginx/apache)</li>
            <li><strong>Config files:</strong> Move outside web root or protect with .htaccess</li>
            <li><strong>Backup files:</strong> Delete .bak, .old, .backup files from server</li>
            <li><strong>Log files:</strong> Store logs outside web root, rotate regularly</li>
            <li><strong>Database dumps:</strong> Never store SQL dumps in web-accessible directories</li>
          </ol>
          
          <div className="mt-4 bg-black rounded p-3">
            <p className="text-gray-400 text-xs mb-2">Add to .htaccess or nginx config:</p>
            <pre className="text-green-400 text-xs font-mono">
{`# Apache .htaccess
<FilesMatch "\\.(env|git|config|sql|log|bak)$">
  Require all denied
</FilesMatch>

# Nginx
location ~ /\\. { deny all; }
location ~ \\.(env|config|sql|log|bak)$ { deny all; }`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
