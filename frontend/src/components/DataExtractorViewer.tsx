import { useState, useEffect } from 'react';
import axios from 'axios';

interface DataExtractorViewerProps {
  scanId: string;
}

export default function DataExtractorViewer({ scanId }: DataExtractorViewerProps) {
  const [extractedData, setExtractedData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'apis' | 'forms' | 'endpoints' | 'secrets'>('apis');

  useEffect(() => {
    fetchExtractedData();
  }, [scanId]);

  const fetchExtractedData = async () => {
    try {
      const response = await axios.get(`/api/tools/${scanId}/data-extractor-viewer`);
      setExtractedData(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch extracted data:', error);
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

  if (!extractedData || !extractedData.data_found) {
    return null;
  }

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-purple-900/20 to-pink-900/20 border-2 border-purple-500 rounded-lg p-6">
        <div className="flex items-start space-x-4">
          <div className="flex-shrink-0">
            <div className="w-12 h-12 bg-purple-500 rounded-lg flex items-center justify-center">
              <svg className="w-7 h-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
          </div>
          <div className="flex-1">
            <h3 className="text-2xl font-bold text-purple-400 mb-2">
              📊 LIVE DATA EXTRACTION SUCCESSFUL
            </h3>
            <p className="text-white text-lg mb-4">
              Extracted real API endpoints, forms, and sensitive data from your website!
            </p>
            <div className="bg-black/50 rounded-lg p-4">
              <p className="text-purple-300 font-semibold mb-2">⚡ REAL-TIME INTELLIGENCE</p>
              <p className="text-gray-300 text-sm">
                The data below was actively extracted by querying your website. This shows what attackers can discover about your infrastructure.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-lg overflow-hidden">
        <div className="flex border-b border-neutral-800">
          {[
            { id: 'apis', label: 'API Endpoints', icon: '🔌', count: extractedData.api_endpoints?.length || 0 },
            { id: 'forms', label: 'Forms', icon: '📝', count: extractedData.forms?.length || 0 },
            { id: 'endpoints', label: 'Hidden Endpoints', icon: '🔍', count: extractedData.hidden_endpoints?.length || 0 },
            { id: 'secrets', label: 'Exposed Secrets', icon: '🔑', count: extractedData.secrets?.length || 0 }
          ].map((tab: any) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 px-4 py-3 text-sm font-semibold transition ${
                activeTab === tab.id
                  ? 'bg-neutral-800 text-white border-b-2 border-purple-500'
                  : 'text-gray-400 hover:text-white hover:bg-neutral-800/50'
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.label}
              {tab.count > 0 && (
                <span className="ml-2 bg-purple-600 text-white text-xs px-2 py-0.5 rounded-full">
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* API Endpoints Tab */}
          {activeTab === 'apis' && extractedData.api_endpoints && (
            <div className="space-y-4">
              <h4 className="text-lg font-bold text-white mb-4">🔌 Discovered API Endpoints</h4>
              {extractedData.api_endpoints.map((api: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 text-xs font-bold rounded ${
                        api.method === 'GET' ? 'bg-blue-600 text-white' :
                        api.method === 'POST' ? 'bg-green-600 text-white' :
                        api.method === 'PUT' ? 'bg-yellow-600 text-white' :
                        api.method === 'DELETE' ? 'bg-red-600 text-white' :
                        'bg-gray-600 text-white'
                      }`}>
                        {api.method}
                      </span>
                      <code className="text-purple-400 font-mono text-sm">{api.endpoint}</code>
                    </div>
                    {api.authentication_required && (
                      <span className="text-xs bg-red-900/30 text-red-400 px-2 py-1 rounded">🔒 Auth Required</span>
                    )}
                  </div>
                  
                  {api.parameters && api.parameters.length > 0 && (
                    <div className="mb-3">
                      <p className="text-xs text-gray-400 mb-2">Parameters:</p>
                      <div className="flex flex-wrap gap-2">
                        {api.parameters.map((param: any, pidx: number) => (
                          <span key={pidx} className="text-xs bg-neutral-900 text-gray-300 px-2 py-1 rounded font-mono">
                            {param.name}: {param.type}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {api.sample_response && (
                    <div>
                      <p className="text-xs text-green-400 mb-2">✅ LIVE Response Sample:</p>
                      <div className="bg-black rounded p-3 overflow-x-auto">
                        <pre className="text-green-400 text-xs font-mono">
                          {JSON.stringify(api.sample_response, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}

                  {api.vulnerability && (
                    <div className="mt-3 bg-red-900/20 border border-red-500 rounded p-3">
                      <p className="text-red-400 font-semibold text-sm">⚠️ {api.vulnerability}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Forms Tab */}
          {activeTab === 'forms' && extractedData.forms && (
            <div className="space-y-4">
              <h4 className="text-lg font-bold text-white mb-4">📝 Extracted Forms</h4>
              {extractedData.forms.map((form: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h5 className="text-white font-semibold">{form.name || `Form ${idx + 1}`}</h5>
                    <span className="text-xs text-gray-400">{form.action}</span>
                  </div>

                  <div className="space-y-2 mb-3">
                    {form.fields && form.fields.map((field: any, fidx: number) => (
                      <div key={fidx} className="bg-neutral-900 rounded p-2 flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <span className="text-xs bg-neutral-800 text-gray-300 px-2 py-1 rounded font-mono">
                            {field.type}
                          </span>
                          <span className="text-white text-sm">{field.name}</span>
                        </div>
                        {field.required && (
                          <span className="text-xs text-red-400">Required</span>
                        )}
                      </div>
                    ))}
                  </div>

                  {form.vulnerabilities && form.vulnerabilities.length > 0 && (
                    <div className="bg-red-900/20 border border-red-500 rounded p-3">
                      <p className="text-red-400 font-semibold text-sm mb-2">⚠️ Security Issues:</p>
                      <ul className="text-sm text-red-300 space-y-1">
                        {form.vulnerabilities.map((vuln: string, vidx: number) => (
                          <li key={vidx}>• {vuln}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Hidden Endpoints Tab */}
          {activeTab === 'endpoints' && extractedData.hidden_endpoints && (
            <div className="space-y-4">
              <h4 className="text-lg font-bold text-white mb-4">🔍 Hidden/Debug Endpoints Found</h4>
              {extractedData.hidden_endpoints.map((endpoint: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 border border-red-800 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <code className="text-red-400 font-mono text-sm">{endpoint.path}</code>
                    <span className={`text-xs px-2 py-1 rounded font-semibold ${
                      endpoint.status === 200 ? 'bg-green-900/30 text-green-400' :
                      endpoint.status === 403 ? 'bg-yellow-900/30 text-yellow-400' :
                      'bg-red-900/30 text-red-400'
                    }`}>
                      Status: {endpoint.status}
                    </span>
                  </div>
                  
                  {endpoint.content && (
                    <div className="bg-black rounded p-3 overflow-x-auto max-h-64">
                      <pre className="text-green-400 text-xs font-mono">
                        {endpoint.content}
                      </pre>
                    </div>
                  )}

                  <div className="mt-3 text-xs text-gray-400">
                    <p><span className="font-semibold">Discovered via:</span> {endpoint.discovery_method}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Secrets Tab */}
          {activeTab === 'secrets' && extractedData.secrets && (
            <div className="space-y-4">
              <h4 className="text-lg font-bold text-white mb-4">🔑 Exposed Secrets & Credentials</h4>
              <div className="bg-red-900/20 border border-red-500 rounded-lg p-4 mb-4">
                <p className="text-red-300 font-semibold">🚨 CRITICAL: Hardcoded secrets found in your code!</p>
              </div>
              {extractedData.secrets.map((secret: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 border border-red-800 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className={`px-3 py-1 text-sm font-bold rounded ${
                      secret.type === 'API_KEY' ? 'bg-red-600 text-white' :
                      secret.type === 'PASSWORD' ? 'bg-orange-600 text-white' :
                      secret.type === 'TOKEN' ? 'bg-yellow-600 text-white' :
                      'bg-purple-600 text-white'
                    }`}>
                      {secret.type}
                    </span>
                    <span className="text-xs text-gray-400">{secret.location}</span>
                  </div>

                  <div className="bg-black rounded p-3 mb-3">
                    <p className="text-xs text-gray-400 mb-1">Exposed Value:</p>
                    <code className="text-red-400 font-mono text-sm break-all">{secret.value}</code>
                  </div>

                  {secret.service && (
                    <p className="text-sm text-white mb-2">
                      <span className="font-semibold">Service:</span> {secret.service}
                    </p>
                  )}

                  <div className="bg-red-900/20 border border-red-500 rounded p-3">
                    <p className="text-red-400 font-semibold text-sm mb-1">⚠️ Immediate Action Required:</p>
                    <p className="text-red-300 text-xs">{secret.recommendation}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Exploitation Guide */}
      <div className="bg-red-900/10 border-2 border-red-500 rounded-lg p-6">
        <h4 className="text-xl font-bold text-red-400 mb-4">🎯 How Attackers Use This Data</h4>
        <div className="space-y-3 text-white text-sm">
          <p className="font-semibold">This extracted intelligence enables attacks:</p>
          <ol className="list-decimal list-inside space-y-2">
            <li><strong>API Abuse:</strong> Discovered endpoints can be flooded or exploited for unauthorized access</li>
            <li><strong>Form Manipulation:</strong> Submit crafted payloads (XSS, SQLi) to vulnerable forms</li>
            <li><strong>Credential Theft:</strong> Use exposed API keys to access your services</li>
            <li><strong>Hidden Endpoints:</strong> Debug/admin panels often have weak security</li>
            <li><strong>Data Exfiltration:</strong> APIs without rate limiting can be scraped for all data</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
