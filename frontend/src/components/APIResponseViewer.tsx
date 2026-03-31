import { useState, useEffect } from 'react';
import axios from 'axios';

interface APIResponseViewerProps {
  scanId: string;
}

export default function APIResponseViewer({ scanId }: APIResponseViewerProps) {
  const [apiData, setApiData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedEndpoint, setSelectedEndpoint] = useState<number | null>(null);

  useEffect(() => {
    fetchAPIData();
  }, [scanId]);

  const fetchAPIData = async () => {
    try {
      const response = await axios.get(`/api/tools/${scanId}/api-response-viewer`);
      setApiData(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch API data:', error);
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

  if (!apiData || !apiData.endpoints_tested) {
    return null;
  }

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-green-400';
    if (status >= 300 && status < 400) return 'text-yellow-400';
    if (status >= 400 && status < 500) return 'text-orange-400';
    return 'text-red-400';
  };

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET': return 'bg-blue-600';
      case 'POST': return 'bg-green-600';
      case 'PUT': return 'bg-yellow-600';
      case 'DELETE': return 'bg-red-600';
      case 'PATCH': return 'bg-purple-600';
      default: return 'bg-gray-600';
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-blue-900/20 to-cyan-900/20 border-2 border-blue-500 rounded-lg p-6">
        <div className="flex items-start space-x-4">
          <div className="flex-shrink-0">
            <div className="w-12 h-12 bg-blue-500 rounded-lg flex items-center justify-center">
              <svg className="w-7 h-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
          </div>
          <div className="flex-1">
            <h3 className="text-2xl font-bold text-blue-400 mb-2">
              🔌 LIVE API RESPONSES CAPTURED
            </h3>
            <p className="text-white text-lg mb-4">
              Tested {apiData.total_endpoints} API endpoints and captured REAL responses!
            </p>
            <div className="bg-black/50 rounded-lg p-4">
              <p className="text-blue-300 font-semibold mb-2">⚡ ACTIVE TESTING RESULTS</p>
              <p className="text-gray-300 text-sm">
                Each endpoint was actually called and the responses below are real data from your API. This shows what information attackers can extract.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-white mb-1">{apiData.total_endpoints}</div>
          <div className="text-sm text-gray-400">Total Endpoints</div>
        </div>
        <div className="bg-green-900/20 border border-green-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400 mb-1">{apiData.success_count || 0}</div>
          <div className="text-sm text-gray-400">2xx Success</div>
        </div>
        <div className="bg-yellow-900/20 border border-yellow-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-yellow-400 mb-1">{apiData.redirect_count || 0}</div>
          <div className="text-sm text-gray-400">3xx Redirects</div>
        </div>
        <div className="bg-orange-900/20 border border-orange-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-orange-400 mb-1">{apiData.client_error_count || 0}</div>
          <div className="text-sm text-gray-400">4xx Errors</div>
        </div>
        <div className="bg-red-900/20 border border-red-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-red-400 mb-1">{apiData.vulnerabilities_found || 0}</div>
          <div className="text-sm text-gray-400">Vulnerabilities</div>
        </div>
      </div>

      {/* API Endpoints */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
        <h4 className="text-xl font-bold text-white mb-4">🧪 Tested Endpoints & Live Responses</h4>
        <div className="space-y-3">
          {apiData.endpoints && apiData.endpoints.map((endpoint: any, idx: number) => (
            <div key={idx} className="bg-neutral-950 border border-neutral-800 rounded-lg overflow-hidden">
              <button
                onClick={() => setSelectedEndpoint(selectedEndpoint === idx ? null : idx)}
                className="w-full px-4 py-3 flex items-center justify-between hover:bg-neutral-900 transition"
              >
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 text-xs font-bold rounded text-white ${getMethodColor(endpoint.method)}`}>
                    {endpoint.method}
                  </span>
                  <code className="text-white font-mono text-sm">{endpoint.path}</code>
                </div>
                <div className="flex items-center space-x-4">
                  <span className={`text-sm font-semibold ${getStatusColor(endpoint.status)}`}>
                    {endpoint.status}
                  </span>
                  <span className="text-xs text-gray-400">{endpoint.response_time}ms</span>
                  <svg
                    className={`w-5 h-5 text-gray-400 transition-transform ${
                      selectedEndpoint === idx ? 'rotate-180' : ''
                    }`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </button>

              {selectedEndpoint === idx && (
                <div className="px-4 pb-4 border-t border-neutral-800 pt-4 space-y-4">
                  {/* Request Details */}
                  <div>
                    <h5 className="text-sm font-semibold text-white mb-2">📤 Request Details:</h5>
                    <div className="bg-neutral-900 rounded-lg p-3">
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <span className="text-gray-400">Full URL:</span>
                          <p className="text-white mt-1 font-mono break-all">{endpoint.full_url}</p>
                        </div>
                        <div>
                          <span className="text-gray-400">Content-Type:</span>
                          <p className="text-white mt-1">{endpoint.content_type || 'N/A'}</p>
                        </div>
                      </div>
                      
                      {endpoint.headers && (
                        <div className="mt-3">
                          <span className="text-gray-400 text-xs">Request Headers:</span>
                          <div className="bg-black rounded p-2 mt-1">
                            <pre className="text-green-400 text-xs font-mono">
                              {JSON.stringify(endpoint.headers, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}

                      {endpoint.payload && (
                        <div className="mt-3">
                          <span className="text-gray-400 text-xs">Request Payload:</span>
                          <div className="bg-black rounded p-2 mt-1">
                            <pre className="text-green-400 text-xs font-mono">
                              {JSON.stringify(endpoint.payload, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Response Details */}
                  <div>
                    <h5 className="text-sm font-semibold text-green-400 mb-2">📥 LIVE Response Data:</h5>
                    <div className="bg-black rounded-lg p-3 overflow-x-auto max-h-96">
                      <pre className="text-green-400 text-xs font-mono">
                        {typeof endpoint.response === 'object' 
                          ? JSON.stringify(endpoint.response, null, 2)
                          : endpoint.response}
                      </pre>
                    </div>
                  </div>

                  {/* Response Headers */}
                  {endpoint.response_headers && (
                    <div>
                      <h5 className="text-sm font-semibold text-white mb-2">Response Headers:</h5>
                      <div className="bg-neutral-900 rounded-lg p-3">
                        {Object.entries(endpoint.response_headers).map(([key, value]: [string, any]) => (
                          <div key={key} className="flex justify-between text-xs py-1 border-b border-neutral-800 last:border-0">
                            <span className="text-gray-400">{key}:</span>
                            <span className="text-white font-mono">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Vulnerabilities */}
                  {endpoint.vulnerabilities && endpoint.vulnerabilities.length > 0 && (
                    <div className="bg-red-900/20 border border-red-500 rounded-lg p-3">
                      <h5 className="text-sm font-semibold text-red-400 mb-2">⚠️ Vulnerabilities Detected:</h5>
                      <ul className="space-y-2">
                        {endpoint.vulnerabilities.map((vuln: any, vidx: number) => (
                          <li key={vidx} className="text-sm">
                            <p className="text-red-300 font-semibold">{vuln.type}</p>
                            <p className="text-red-200 text-xs mt-1">{vuln.description}</p>
                            {vuln.exploit_example && (
                              <div className="bg-black rounded p-2 mt-2">
                                <p className="text-xs text-gray-400 mb-1">Exploit Example:</p>
                                <code className="text-green-400 text-xs font-mono">{vuln.exploit_example}</code>
                              </div>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Security Issues */}
                  {endpoint.security_issues && endpoint.security_issues.length > 0 && (
                    <div className="bg-yellow-900/20 border border-yellow-500 rounded-lg p-3">
                      <h5 className="text-sm font-semibold text-yellow-400 mb-2">⚡ Security Issues:</h5>
                      <ul className="space-y-1">
                        {endpoint.security_issues.map((issue: string, iidx: number) => (
                          <li key={iidx} className="text-xs text-yellow-300">• {issue}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Attack Scenarios */}
      <div className="bg-red-900/10 border-2 border-red-500 rounded-lg p-6">
        <h4 className="text-xl font-bold text-red-400 mb-4">🎯 How Attackers Exploit APIs</h4>
        <div className="space-y-3 text-white text-sm">
          <p className="font-semibold">Common API attack vectors discovered:</p>
          <ol className="list-decimal list-inside space-y-2">
            <li><strong>Authentication Bypass:</strong> APIs without proper auth can be accessed directly</li>
            <li><strong>Data Leakage:</strong> Overly verbose responses expose internal data structures</li>
            <li><strong>Rate Limiting:</strong> Missing rate limits allow brute-force and scraping</li>
            <li><strong>Injection Attacks:</strong> Unvalidated inputs can lead to SQLi, NoSQLi, command injection</li>
            <li><strong>IDOR:</strong> Manipulating IDs to access other users' data</li>
            <li><strong>Mass Assignment:</strong> Extra parameters can modify unintended fields</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
