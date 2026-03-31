import { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { startCloudStorage, getToolStatus, getToolResults } from '../utils/api';
import FindingCard from '../components/FindingCard';
import ScanPhaseIcon from '../components/ScanPhaseIcon';
import CloudStorageExplorer from '../components/CloudStorageExplorer';
import SecureContent from '../components/SecureContent';

const CLOUD_STORAGE_PHASES = [
  {
    id: 1,
    name: 'AWS S3 Bucket Discovery',
    icon: 'cloud',
    actions: [
      'Scanning for S3 bucket references in HTML/JS',
      'Testing common bucket naming patterns',
      'Checking bucket ACL permissions',
      'Attempting anonymous bucket listing',
      'Testing for public read/write access',
      'Preparing aws s3 sync commands'
    ]
  },
  {
    id: 2,
    name: 'Azure Blob Storage Testing',
    icon: 'cloud',
    actions: [
      'Looking for Azure blob URLs',
      'Testing container permissions',
      'Checking for SAS token exposure',
      'Attempting anonymous container access',
      'Scanning for storage account keys',
      'Testing blob enumeration'
    ]
  },
  {
    id: 3,
    name: 'Google Cloud Storage Scan',
    icon: 'cloud',
    actions: [
      'Searching for GCS bucket references',
      'Testing bucket IAM permissions',
      'Checking for allUsers access',
      'Attempting object listing',
      'Looking for exposed service account keys',
      'Testing gsutil access commands'
    ]
  },
  {
    id: 4,
    name: 'DigitalOcean Spaces Analysis',
    icon: 'server',
    actions: [
      'Scanning for Spaces CDN URLs',
      'Testing bucket CORS misconfiguration',
      'Checking public access settings',
      'Attempting file enumeration',
      'Looking for exposed access keys',
      'Testing s3cmd compatibility'
    ]
  },
  {
    id: 5,
    name: 'Backblaze B2 Detection',
    icon: 'hard-drive',
    actions: [
      'Looking for B2 bucket URLs',
      'Testing bucket authorization',
      'Checking for public file access',
      'Scanning for application keys',
      'Attempting bucket enumeration',
      'Testing download authentication'
    ]
  }
];

export default function CloudStorage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [showWarning, setShowWarning] = useState<boolean>(false);
  const [dontShowAgain, setDontShowAgain] = useState(false);
  const [progress, setProgress] = useState(0);
  const [expandedPhases, setExpandedPhases] = useState<number[]>([]);
  const resultsRef = useRef<HTMLDivElement>(null);
  const progressRef = useRef<HTMLDivElement>(null);

  const togglePhase = (id: number) => {
    setExpandedPhases(prev =>
      prev.includes(id) ? prev.filter(p => p !== id) : [...prev, id]
    );
  };

  const scrollToResults = () => {
    resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const scrollToProgress = () => {
    progressRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      toast.error('Please enter a target domain');
      return;
    }

    // Check if user has dismissed the warning permanently
    const warningDismissed = localStorage.getItem('legalWarningDismissed') === 'true';
    
    if (!warningDismissed) {
      setShowWarning(true);
      return;
    }

    startScan();
  };

  const startScan = async () => {
    try {
      setLoading(true);
      setResults(null);
      setProgress(0);
      const loadingToast = toast.loading('Detecting cloud storage...');
      
      const data = await startCloudStorage(target);
      toast.dismiss(loadingToast);
      
      pollScanStatus(data.scan_id);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to start scan');
      setLoading(false);
    }
  };
  
  const pollScanStatus = async (id: string) => {
    const interval = setInterval(async () => {
      try {
        const status = await getToolStatus(id);
        setProgress(status.progress || 0);
        
        if (status.status === 'completed') {
          clearInterval(interval);
          const results = await getToolResults(id);
          setResults(results);
          setLoading(false);
          toast.success(`Found ${results.findings_count || 0} cloud storage issues!`);
        } else if (status.status === 'failed') {
          clearInterval(interval);
          setLoading(false);
          toast.error(status.message || 'Scan failed');
        }
      } catch (error) {
        clearInterval(interval);
        setLoading(false);
        toast.error('Failed to get scan status');
      }
    }, 2000);
  };

  const handleAcceptWarning = () => {
    if (dontShowAgain) {
      localStorage.setItem('legalWarningDismissed', 'true');
    }
    setShowWarning(false);
    startScan();
  };

  return (
    <SecureContent level="maximum">
      <>
      <div className="max-w-6xl mx-auto">
      <div className="mb-6">
        <Link
          to="/dashboard"
          className="inline-flex items-center text-gray-400 hover:text-white transition"
        >
          <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Dashboard
        </Link>
      </div>

      <div className="glass-card p-8">
        <div className="flex items-start space-x-4 mb-6">
          <div className="flex-shrink-0 w-16 h-16 bg-neutral-800 rounded-lg flex items-center justify-center">
            <svg className="w-10 h-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
            </svg>
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Cloud Storage Scanner</h1>
            <p className="text-gray-400 mt-2">
              Detect exposed S3, Azure Blob, Google Cloud Storage buckets and test access permissions
            </p>
          </div>
        </div>

        <form onSubmit={handleScan} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target Domain
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-white"
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-white hover:bg-gray-200 disabled:bg-gray-700 disabled:cursor-not-allowed text-black font-semibold py-3 px-6 rounded-lg transition"
          >
            {loading ? 'Scanning Cloud Storage...' : 'Start Cloud Storage Scan'}
          </button>
        </form>

        {/* See Progress Button */}
        {loading && (
          <div className="mt-6 flex justify-center">
            <button
              onClick={scrollToProgress}
              className="bg-white hover:bg-gray-200 text-black font-semibold py-3 px-8 rounded-lg transition flex items-center space-x-2 shadow-lg"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
              <span>See Progress</span>
            </button>
          </div>
        )}

        {/* What We Test */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Amazon S3 Buckets</h4>
                <p className="text-sm text-gray-400">Public bucket enumeration, ACL testing, object listing, download testing</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Azure Blob Storage</h4>
                <p className="text-sm text-gray-400">Container enumeration, SAS token testing, public access validation</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Google Cloud Storage</h4>
                <p className="text-sm text-gray-400">Bucket discovery, IAM policy testing, public object enumeration</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Object Enumeration</h4>
                <p className="text-sm text-gray-400">List all accessible files, identify sensitive data, backup files</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Permission Testing</h4>
                <p className="text-sm text-gray-400">Read/write access checks, upload testing, deletion capabilities</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Subdomain Discovery</h4>
                <p className="text-sm text-gray-400">Find related buckets via DNS, bruteforce common patterns</p>
              </div>
            </div>
          </div>
        </div>

        {/* Progress Section */}
        {loading && (
          <div ref={progressRef} className="mt-8 space-y-6">
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <h3 className="text-xl font-bold text-white mb-4">Detecting Cloud Storage...</h3>
              <div className="space-y-4">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Overall Progress:</span>
                  <span className="text-white font-semibold">{progress}%</span>
                </div>
                <div className="w-full bg-neutral-800 rounded-full h-2.5">
                  <div className="bg-gradient-to-r from-white to-gray-400 h-2.5 rounded-full progress-bar" data-progress={Math.round(progress / 10) * 10}></div>
                </div>
              </div>
            </div>

            {/* Expandable Phases */}
            <div className="space-y-3">
              {CLOUD_STORAGE_PHASES.map((phase) => {
                const isExpanded = expandedPhases.includes(phase.id);
                const currentPhase = Math.ceil((progress / 100) * CLOUD_STORAGE_PHASES.length);
                const isActive = phase.id === currentPhase;
                const isComplete = phase.id < currentPhase;

                return (
                  <div
                    key={phase.id}
                    className={`bg-neutral-900 border rounded-lg overflow-hidden transition-all ${
                      isActive ? 'border-white shadow-lg shadow-white/10' : 
                      isComplete ? 'border-neutral-700' : 'border-neutral-800'
                    }`}
                  >
                    <button
                      onClick={() => togglePhase(phase.id)}
                      className="w-full px-6 py-4 flex items-center justify-between hover:bg-neutral-800/50 transition"
                    >
                      <div className="flex items-center space-x-4">
                        <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
                          isActive ? 'bg-white' : isComplete ? 'bg-neutral-700' : 'bg-neutral-800'
                        }`}>
                          <ScanPhaseIcon 
                            icon={phase.icon} 
                            className={`w-6 h-6 ${isActive ? 'text-black' : 'text-white'}`} 
                          />
                        </div>
                        <div className="text-left">
                          <h4 className={`font-semibold ${isActive ? 'text-white' : 'text-gray-300'}`}>
                            {phase.name}
                          </h4>
                          <p className="text-sm text-gray-500">
                            {isComplete ? 'Completed' : isActive ? 'Testing...' : 'Pending'}
                          </p>
                        </div>
                      </div>
                      <svg
                        className={`w-5 h-5 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>

                    {isExpanded && (
                      <div className="px-6 pb-4 pt-2 border-t border-neutral-800">
                        <div className="space-y-2">
                          {phase.actions.map((action, idx) => (
                            <div key={idx} className="flex items-start space-x-3 text-sm">
                              <svg className="w-4 h-4 text-gray-500 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                              </svg>
                              <span className="text-gray-400">{action}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* View Results Button */}
        {!loading && results && (
          <div className="mt-6 flex justify-center">
            <button
              onClick={scrollToResults}
              className="bg-white hover:bg-gray-200 text-black font-semibold py-3 px-8 rounded-lg transition flex items-center space-x-2 shadow-lg"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
              <span>View Results</span>
            </button>
          </div>
        )}
        
        {results && (
          <div ref={resultsRef} className="mt-8 space-y-6">
            {/* Summary */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <svg className="w-6 h-6 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z" />
                  <path fillRule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd" />
                </svg>
                Scan Summary
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-neutral-950 rounded-lg p-4">
                  <div className="text-3xl font-bold text-white mb-1">{results.findings_count || 0}</div>
                  <div className="text-sm text-gray-400">Total Issues Found</div>
                </div>
                <div className="bg-neutral-950 rounded-lg p-4">
                  <div className={`text-3xl font-bold mb-1 ${results.risk_level === 'CRITICAL' || results.risk_level === 'HIGH' ? 'text-red-400' : results.risk_level === 'MEDIUM' ? 'text-yellow-400' : 'text-green-400'}`}>
                    {results.risk_level || 'UNKNOWN'}
                  </div>
                  <div className="text-sm text-gray-400">Risk Level</div>
                </div>
                <div className="bg-neutral-950 rounded-lg p-4">
                  <div className="text-3xl font-bold text-white mb-1">{results.risk_score || 0}</div>
                  <div className="text-sm text-gray-400">Risk Score</div>
                </div>
              </div>

              {results.findings_summary && (
                <div className="mt-4 grid grid-cols-2 md:grid-cols-5 gap-3">
                  {results.findings_summary.CRITICAL > 0 && (
                    <div className="bg-red-900/20 border border-red-800 rounded px-3 py-2">
                      <div className="text-red-400 font-bold text-lg">{results.findings_summary.CRITICAL}</div>
                      <div className="text-red-300 text-xs">Critical</div>
                    </div>
                  )}
                  {results.findings_summary.HIGH > 0 && (
                    <div className="bg-orange-900/20 border border-orange-800 rounded px-3 py-2">
                      <div className="text-orange-400 font-bold text-lg">{results.findings_summary.HIGH}</div>
                      <div className="text-orange-300 text-xs">High</div>
                    </div>
                  )}
                  {results.findings_summary.MEDIUM > 0 && (
                    <div className="bg-yellow-900/20 border border-yellow-800 rounded px-3 py-2">
                      <div className="text-yellow-400 font-bold text-lg">{results.findings_summary.MEDIUM}</div>
                      <div className="text-yellow-300 text-xs">Medium</div>
                    </div>
                  )}
                  {results.findings_summary.LOW > 0 && (
                    <div className="bg-blue-900/20 border border-blue-800 rounded px-3 py-2">
                      <div className="text-blue-400 font-bold text-lg">{results.findings_summary.LOW}</div>
                      <div className="text-blue-300 text-xs">Low</div>
                    </div>
                  )}
                  {results.findings_summary.INFO > 0 && (
                    <div className="bg-gray-800/20 border border-gray-700 rounded px-3 py-2">
                      <div className="text-gray-400 font-bold text-lg">{results.findings_summary.INFO}</div>
                      <div className="text-gray-300 text-xs">Info</div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Detailed Findings */}
            {results.findings && results.findings.length > 0 && (
              <div>
                <h4 className="text-xl font-bold text-white mb-4 flex items-center">
                  <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
                  </svg>
                  Detailed Findings ({results.findings.length})
                </h4>
                <div className="space-y-3">
                  {results.findings
                    .sort((a: any, b: any) => {
                      const severity = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5 };
                      return (severity[a.severity as keyof typeof severity] || 99) - (severity[b.severity as keyof typeof severity] || 99);
                    })
                    .map((finding: any, idx: number) => (
                      <FindingCard key={idx} finding={finding} />
                    ))}
                </div>
              </div>
            )}

            {/* Cloud Storage Explorer - Live Data */}
            {results.scan_id && (
              <div>
                <h4 className="text-xl font-bold text-white mb-4 flex items-center">
                  <svg className="w-5 h-5 mr-2 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                  </svg>
                  Live Cloud Storage Data
                </h4>
                <CloudStorageExplorer scanId={results.scan_id} />
              </div>
            )}
          </div>
        )}
      </div>


      {!!showWarning && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setShowWarning(false)}>
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6 max-w-md mx-4 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start space-x-3 mb-4">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white mb-1">Legal Notice</h3>
                <p className="text-sm text-gray-400">Important information before testing</p>
              </div>
            </div>
            
            <div className="space-y-3 text-sm text-gray-300 mb-6">
              <p>
                Only test applications and systems you own or have explicit written permission to test.
              </p>
              <p>
                Unauthorized penetration testing is illegal and may result in:
              </p>
              <ul className="list-disc list-inside space-y-1 text-gray-400 ml-2">
                <li>Criminal prosecution</li>
                <li>Civil lawsuits</li>
                <li>Significant financial penalties</li>
                <li>Damage to professional reputation</li>
              </ul>
              <p className="text-white font-medium mt-4">
                By continuing, you confirm you have proper authorization.
              </p>
            </div>

            <div className="mb-4">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={dontShowAgain}
                  onChange={(e) => setDontShowAgain(e.target.checked)}
                  className="w-4 h-4 bg-neutral-800 border-neutral-700 rounded text-white focus:ring-2 focus:ring-white"
                />
                <span className="text-sm text-gray-400">Don't show this again</span>
              </label>
            </div>

            <div className="flex space-x-3">
              <button
                onClick={() => setShowWarning(false)}
                className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white font-semibold py-2 px-4 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleAcceptWarning}
                className="flex-1 bg-white hover:bg-gray-200 text-black font-semibold py-2 px-4 rounded-lg transition"
              >
                I Understand
              </button>
            </div>
          </div>
        </div>
      )}
      </div>
    </>
    </SecureContent>
  );
}
