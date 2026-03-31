import { useState } from 'react';

interface FindingCardProps {
  finding: any;
}

export default function FindingCard({ finding }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-900 text-red-100 border-red-700';
      case 'HIGH':
        return 'bg-orange-900 text-orange-100 border-orange-700';
      case 'MEDIUM':
        return 'bg-yellow-900 text-yellow-100 border-yellow-700';
      case 'LOW':
        return 'bg-blue-900 text-blue-100 border-blue-700';
      case 'INFO':
        return 'bg-gray-800 text-gray-100 border-gray-600';
      default:
        return 'bg-gray-800 text-gray-100 border-gray-600';
    }
  };

  const renderEvidence = () => {
    if (!finding.evidence) return null;

    const evidence = finding.evidence;

    // Render based on evidence type
    switch (evidence.type) {
      case 'credentials':
      case 'tokens':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-red-500">
            <h5 className="text-red-400 font-semibold mb-2 flex items-center">
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              {evidence.credential_type || 'Exposed Credentials'} ({evidence.count})
            </h5>
            <div className="space-y-2">
              {evidence.tokens?.map((token: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-3 font-mono text-sm text-red-300 break-all">
                  {token}
                </div>
              ))}
            </div>
          </div>
        );

      case 'javascript_credentials':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-orange-500">
            <h5 className="text-orange-400 font-semibold mb-2">
              Hardcoded Credentials ({evidence.count})
            </h5>
            <div className="space-y-2">
              {evidence.credentials?.map((cred: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-3">
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-mono text-sm text-orange-300">{cred.variable}</span>
                    <span className="text-xs text-gray-400">{cred.length} chars</span>
                  </div>
                  <div className="font-mono text-xs text-gray-300 break-all">{cred.value}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'forms':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-blue-500">
            <h5 className="text-blue-400 font-semibold mb-2">
              Forms Discovered ({evidence.count})
            </h5>
            <div className="space-y-3">
              {evidence.forms?.map((form: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-white">{form.method}</span>
                    <span className="text-xs text-gray-400">{form.input_count} inputs</span>
                  </div>
                  <div className="text-sm text-gray-300 mb-2 break-all">{form.action}</div>
                  <div className="space-y-1">
                    {form.inputs?.slice(0, 5).map((input: any, i: number) => (
                      <div key={i} className="text-xs bg-neutral-900 rounded px-2 py-1 flex items-center space-x-2">
                        <span className="text-gray-500">{input.type}</span>
                        <span className="text-gray-300">{input.name || input.id || 'unnamed'}</span>
                        {input.required && <span className="text-red-400">*required</span>}
                      </div>
                    ))}
                    {form.input_count > 5 && (
                      <div className="text-xs text-gray-500 px-2">+{form.input_count - 5} more</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'emails':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-gray-600">
            <h5 className="text-gray-300 font-semibold mb-2">
              Email Addresses ({evidence.count || evidence.emails?.length})
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {(evidence.emails || evidence.items || []).map((email: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded px-3 py-2 font-mono text-sm text-gray-300">
                  {email}
                </div>
              ))}
            </div>
          </div>
        );

      case 'phones':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-gray-600">
            <h5 className="text-gray-300 font-semibold mb-2">
              Phone Numbers ({evidence.count || evidence.items?.length})
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {(evidence.items || []).map((phone: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded px-3 py-2 font-mono text-sm text-gray-300">
                  {phone}
                </div>
              ))}
            </div>
          </div>
        );

      case 'api_endpoints':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-purple-600">
            <h5 className="text-purple-400 font-semibold mb-2">
              API Endpoints ({evidence.count || evidence.endpoints?.length})
            </h5>
            <div className="space-y-1">
              {(evidence.endpoints || []).map((endpoint: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded px-3 py-2 font-mono text-xs text-purple-300 break-all">
                  {endpoint}
                </div>
              ))}
            </div>
          </div>
        );

      case 'html_comments':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-yellow-600">
            <h5 className="text-yellow-400 font-semibold mb-2">
              Sensitive Comments ({evidence.count})
            </h5>
            <div className="space-y-2">
              {evidence.comments?.map((comment: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-3">
                  <div className="text-xs text-yellow-300 font-semibold mb-1">{comment.type}</div>
                  <div className="text-xs text-gray-300 font-mono break-all">{comment.comment}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'internal_ips':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-yellow-600">
            <h5 className="text-yellow-400 font-semibold mb-2">
              Internal IP Addresses ({evidence.count || evidence.ips?.length})
            </h5>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {(evidence.ips || []).map((ip: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded px-3 py-2 font-mono text-sm text-yellow-300">
                  {ip}
                </div>
              ))}
            </div>
          </div>
        );

      case 'technology_versions':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-gray-600">
            <h5 className="text-gray-300 font-semibold mb-2">
              Technology Versions ({evidence.count})
            </h5>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {evidence.versions?.map((ver: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-2">
                  <div className="text-sm text-white font-semibold">{ver.technology}</div>
                  <div className="text-xs text-gray-400 font-mono">{ver.version}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'sensitive_comments':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-yellow-600">
            <h5 className="text-yellow-400 font-semibold mb-2">
              Sensitive Comments ({evidence.count})
            </h5>
            <div className="space-y-1 max-h-60 overflow-y-auto">
              {evidence.items?.map((comment: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded px-3 py-2 text-xs font-mono text-gray-300 break-all">
                  {comment}
                </div>
              ))}
            </div>
          </div>
        );

      case 'hidden_inputs':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-gray-600">
            <h5 className="text-gray-300 font-semibold mb-2">
              Hidden Input Fields ({evidence.count})
            </h5>
            <div className="space-y-2">
              {evidence.fields?.map((field: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-3">
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-mono text-sm text-blue-300">{field.name}</span>
                    <span className="text-xs text-gray-400">{field.length} chars</span>
                  </div>
                  <div className="font-mono text-xs text-gray-300 break-all">{field.value}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'sensitive_hidden_inputs':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-orange-500">
            <h5 className="text-orange-400 font-semibold mb-2 flex items-center">
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              Sensitive Hidden Fields ({evidence.count})
            </h5>
            <div className="space-y-2">
              {evidence.fields?.map((field: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-3">
                  <div className="text-xs text-orange-300 font-semibold mb-1">{field.type}</div>
                  <div className="font-mono text-sm text-white mb-1">{field.name}</div>
                  <div className="font-mono text-xs text-orange-200 break-all">{field.value}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'metadata':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-gray-600">
            <h5 className="text-gray-300 font-semibold mb-2">
              Metadata Tags ({evidence.count})
            </h5>
            <div className="space-y-1 max-h-60 overflow-y-auto">
              {evidence.tags?.map((tag: any, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded p-2">
                  <div className="text-xs text-purple-300 font-semibold">{tag.name}</div>
                  <div className="text-xs text-gray-300 mt-1">{tag.content}</div>
                </div>
              ))}
            </div>
          </div>
        );

      case 'discovered_links':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-gray-600">
            <h5 className="text-gray-300 font-semibold mb-2">
              Discovered Links ({evidence.count})
              {evidence.count > evidence.endpoints?.length && (
                <span className="text-xs text-gray-500 ml-2">
                  (showing first {evidence.endpoints?.length})
                </span>
              )}
            </h5>
            <div className="space-y-1 max-h-60 overflow-y-auto">
              {evidence.endpoints?.map((endpoint: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded px-3 py-2 font-mono text-xs text-gray-300 break-all">
                  {endpoint}
                </div>
              ))}
            </div>
          </div>
        );

      case 'sensitive_endpoints':
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-yellow-600">
            <h5 className="text-yellow-400 font-semibold mb-2 flex items-center">
              <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
              </svg>
              API/Admin Endpoints ({evidence.count})
            </h5>
            <div className="space-y-1 max-h-60 overflow-y-auto">
              {evidence.endpoints?.map((endpoint: string, idx: number) => (
                <div key={idx} className="bg-neutral-950 rounded px-3 py-2 font-mono text-xs text-yellow-300 break-all">
                  {endpoint}
                </div>
              ))}
            </div>
          </div>
        );

      default:
        // Generic evidence display
        return (
          <div className="mt-3 bg-black bg-opacity-40 rounded-lg p-4 border border-gray-600">
            <pre className="text-xs text-gray-300 overflow-auto max-h-60">
              {JSON.stringify(evidence, null, 2)}
            </pre>
          </div>
        );
    }
  };

  return (
    <div className="bg-neutral-900 border border-neutral-800 rounded-lg overflow-hidden">
      <div
        className="p-4 cursor-pointer hover:bg-neutral-800 transition"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center space-x-3 mb-2">
              <span className={`px-2 py-1 rounded text-xs font-bold ${getSeverityColor(finding.severity)}`}>
                {finding.severity}
              </span>
              <span className="text-xs text-gray-500">{finding.category}</span>
            </div>
            <h4 className="text-white font-semibold mb-1">{finding.title}</h4>
            <p className="text-sm text-gray-400">{finding.description}</p>
          </div>
          <svg
            className={`w-5 h-5 text-gray-400 transition-transform ${expanded ? 'rotate-180' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t border-neutral-800">
          {finding.url && (
            <div className="mt-3 text-sm">
              <span className="text-gray-500">URL: </span>
              <span className="text-gray-300 font-mono break-all">{finding.url}</span>
            </div>
          )}

          {finding.payload && (
            <div className="mt-3">
              <h5 className="text-gray-400 text-sm font-semibold mb-2">Payload</h5>
              <div className="bg-black bg-opacity-40 rounded p-3 font-mono text-xs text-gray-300 overflow-auto max-h-40">
                {finding.payload}
              </div>
            </div>
          )}

          {renderEvidence()}

          {finding.remediation && (
            <div className="mt-3 bg-blue-900 bg-opacity-20 border border-blue-800 rounded p-3">
              <h5 className="text-blue-400 text-sm font-semibold mb-1 flex items-center">
                <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M10 2a6 6 0 00-6 6v3.586l-.707.707A1 1 0 004 14h12a1 1 0 00.707-1.707L16 11.586V8a6 6 0 00-6-6zM10 18a3 3 0 01-3-3h6a3 3 0 01-3 3z" />
                </svg>
                Remediation
              </h5>
              <p className="text-sm text-blue-200">{finding.remediation}</p>
            </div>
          )}

          {finding.timestamp && (
            <div className="mt-3 text-xs text-gray-500">
              Found: {new Date(finding.timestamp).toLocaleString()}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
