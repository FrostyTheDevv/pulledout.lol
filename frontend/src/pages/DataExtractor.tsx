import { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { startDataExtractor, getToolStatus, getToolResults } from '../utils/api';
import FindingCard from '../components/FindingCard';
import ScanPhaseIcon from '../components/ScanPhaseIcon';
import DataExtractorViewer from '../components/DataExtractorViewer';
import SecureContent from '../components/SecureContent';

// Data Extraction specific phases with detailed actions
const DATA_EXTRACTION_PHASES = [
  {
    id: 1,
    name: 'API Key Detection',
    icon: 'key',
    progress: 16,
    actions: [
      'Scanning for AWS access keys',
      'Detecting Google Cloud Platform API keys',
      'Finding Azure subscription keys',
      'Extracting Stripe payment keys',
      'Locating SendGrid API tokens',
      'Identifying Twilio account credentials',
      'Detecting Slack webhook URLs'
    ]
  },
  {
    id: 2,
    name: 'Credential Extraction',
    icon: 'unlock',
    progress: 33,
    actions: [
      'Analyzing JavaScript for hardcoded passwords',
      'Extracting database connection strings',
      'Finding SMTP credentials',
      'Detecting FTP usernames and passwords',
      'Locating SSH private keys',
      'Identifying JWT tokens',
      'Extracting OAuth client secrets'
    ]
  },
  {
    id: 3,
    name: 'Form Analysis',
    icon: 'edit',
    progress: 50,
    actions: [
      'Mapping all input forms',
      'Identifying hidden form fields',
      'Extracting sensitive hidden inputs',
      'Analyzing form validation patterns',
      'Detecting password fields',
      'Checking for autocomplete vulnerabilities',
      'Testing for form token exposure'
    ]
  },
  {
    id: 4,
    name: 'Metadata Extraction',
    icon: 'file-text',
    progress: 66,
    actions: [
      'Parsing HTML meta tags',
      'Extracting author information',
      'Analyzing generator metadata',
      'Finding internal paths in comments',
      'Detecting version numbers',
      'Locating debugging information',
      'Identifying framework versions'
    ]
  },
  {
    id: 5,
    name: 'Endpoint Discovery',
    icon: 'link-2',
    progress: 83,
    actions: [
      'Discovering API endpoints',
      'Mapping admin panels',
      'Finding backup files',
      'Locating configuration files',
      'Detecting sensitive directories',
      'Identifying development endpoints',
      'Extracting internal URLs'
    ]
  },
  {
    id: 6,
    name: 'Token Analysis',
    icon: 'shield',
    progress: 100,
    actions: [
      'Identifying session tokens',
      'Analyzing cookie security',
      'Detecting API authentication tokens',
      'Finding bearer tokens',
      'Locating refresh tokens',
      'Extracting CSRF tokens'
    ]
  }
];

export default function DataExtractor() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [showWarning, setShowWarning] = useState(false);
  const [dontShowAgain, setDontShowAgain] = useState(false);
  const [progress, setProgress] = useState(0);
  const [expandedPhases, setExpandedPhases] = useState<Set<number>>(new Set());
  const progressRef = useRef<HTMLDivElement>(null);

  const scrollToProgress = () => {
    progressRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      toast.error('Please enter a target URL');
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
      const loadingToast = toast.loading('Starting data extraction...');
      
      const data = await startDataExtractor(target);
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
          toast.success(`Extracted ${results.findings_count || 0} sensitive data items!`);
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

  const togglePhase = (phaseId: number) => {
    setExpandedPhases(prev => {
      const newSet = new Set(prev);
      if (newSet.has(phaseId)) {
        newSet.delete(phaseId);
      } else {
        newSet.add(phaseId);
      }
      return newSet;
    });
  };

  const getCurrentPhase = () => {
    return DATA_EXTRACTION_PHASES.find(p => progress < p.progress) || DATA_EXTRACTION_PHASES[DATA_EXTRACTION_PHASES.length - 1];
  };

  const getCompletedPhases = () => {
    return DATA_EXTRACTION_PHASES.filter(p => progress >= p.progress).map(p => p.id);
  };

  return (
    <SecureContent level="maximum">
      <div className="min-h-screen bg-black text-white p-6">
      <div className="max-w-6xl mx-auto">
        <div className="mb-6">
          <Link
            to="/dashboard"
            className="inline-flex items-center text-gray-400 hover:text-white transition group"
          >
            <svg className="w-4 h-4 mr-1 group-hover:-translate-x-1 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to Dashboard
          </Link>
        </div>

        <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-8">
          <div className="flex items-start space-x-4 mb-6">
            <div className="flex-shrink-0 w-16 h-16 bg-neutral-800 rounded-lg flex items-center justify-center">
              <ScanPhaseIcon icon="folder" className="w-10 h-10" />
            </div>
            <div>
              <h1 className="text-4xl font-bold text-white tracking-tight">Data Extractor</h1>
              <p className="text-gray-400 mt-2 text-sm font-mono">
                API keys • Credentials • Tokens • Sensitive data extraction
              </p>
            </div>
          </div>

        <form onSubmit={handleScan} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target URL
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-white"
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-white hover:bg-gray-200 disabled:bg-gray-700 disabled:cursor-not-allowed text-black font-semibold py-3 px-6 rounded-lg transition"
          >
            {loading ? 'Extracting Data...' : 'Start Data Extraction'}
          </button>
        </form>

        {/* See Progress Button */}
        {loading && (
          <div className="mt-6 flex justify-center">
            <button
              onClick={scrollToProgress}
              className="bg-white hover:bg-gray-200 text-black font-semibold py-3 px-6 rounded-lg transition flex items-center space-x-2"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
              </svg>
              <span>See Progress</span>
            </button>
          </div>
        )}

        {/* What We Extract */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">API Keys</h4>
                <p className="text-sm text-gray-400">AWS, Google Cloud, Azure, Stripe, SendGrid, Twilio keys</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Authentication Tokens</h4>
                <p className="text-sm text-gray-400">JWT tokens, OAuth tokens, session cookies, bearer tokens</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Database Credentials</h4>
                <p className="text-sm text-gray-400">Connection strings, usernames, passwords in configs</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Personal Information</h4>
                <p className="text-sm text-gray-400">Email addresses, phone numbers, names, addresses</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Hardcoded Secrets</h4>
                <p className="text-sm text-gray-400">Private keys, encryption keys, API secrets in source code</p>
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
                <h4 className="font-semibold text-white mb-1">Configuration Files</h4>
                <p className="text-sm text-gray-400">.env files, config.json, web.config, application.properties</p>
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
                <h4 className="font-semibold text-white mb-1">Cloud Service Keys</h4>
                <p className="text-sm text-gray-400">S3 credentials, GCP service accounts, Azure storage keys</p>
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
                <h4 className="font-semibold text-white mb-1">Internal URLs</h4>
                <p className="text-sm text-gray-400">Admin panels, internal APIs, staging environments, debug endpoints</p>
              </div>
            </div>
          </div>
        </div>

        {/* Results */}
        {loading && (
          <div ref={progressRef} className="mt-6 space-y-4">
            {/* Progress Bar */}
            <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-mono uppercase tracking-wider text-gray-400">Extraction Progress</span>
                <span className="text-sm font-mono text-white">{progress}%</span>
              </div>
              <div className="w-full bg-neutral-900 rounded h-2 overflow-hidden">
                <div 
                  className="h-full bg-white transition-all duration-500 ease-out"
                  data-progress={progress}
                  ref={(el) => {
                    if (el) el.style.width = `${progress}%`;
                  }}
                />
              </div>
              <div className="flex items-center space-x-2 text-gray-400 mt-3">
                <div className="w-4 h-4 border-2 border-gray-600 border-t-white rounded-full animate-spin"></div>
                <span className="text-sm font-mono">Extracting sensitive data...</span>
              </div>
            </div>

            {/* Detailed Extraction Phases */}
            <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center">
                <ScanPhaseIcon icon="folder" className="w-5 h-5 mr-2" />
                Data Extraction Phases
              </h3>
              
              <div className="space-y-2 max-h-[500px] overflow-y-auto">
                {DATA_EXTRACTION_PHASES.map((phase) => {
                  const isCompleted = getCompletedPhases().includes(phase.id);
                  const isActive = getCurrentPhase()?.id === phase.id;
                  const isExpanded = expandedPhases.has(phase.id);
                  
                  return (
                    <div 
                      key={phase.id}
                      className={`border rounded transition-all ${
                        isActive ? 'bg-neutral-700 border-white shadow-lg' : 
                        isCompleted ? 'bg-neutral-800 border-neutral-600' :
                        'bg-neutral-900 border-neutral-700'
                      }`}
                    >
                      {/* Phase Header */}
                      <button
                        onClick={() => togglePhase(phase.id)}
                        className="w-full flex items-center p-4 text-left hover:bg-neutral-700/50 transition-colors"
                      >
                        {/* Status Icon */}
                        <div className="flex-shrink-0 w-6 h-6 flex items-center justify-center mr-3">
                          {isCompleted ? (
                            <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                            </svg>
                          ) : isActive ? (
                            <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                          ) : (
                            <div className="w-3 h-3 rounded-full bg-neutral-600"></div>
                          )}
                        </div>
                        
                        {/* Phase Icon */}
                        <div className={`flex-shrink-0 mr-3 ${
                          isActive ? 'text-white' : 
                          isCompleted ? 'text-gray-300' :
                          'text-gray-600'
                        }`}>
                          <ScanPhaseIcon icon={phase.icon} className="w-5 h-5" />
                        </div>
                        
                        {/* Phase Name */}
                        <div className="flex-1">
                          <div className={`text-sm font-semibold ${
                            isActive ? 'text-white' : 
                            isCompleted ? 'text-gray-300' :
                            'text-gray-500'
                          }`}>
                            {phase.name}
                          </div>
                        </div>
                        
                        {/* Status Badge */}
                        <div className="flex items-center space-x-3">
                          {isActive && (
                            <span className="text-xs font-mono uppercase tracking-wider text-white px-2 py-1 bg-neutral-600 rounded">
                              Running
                            </span>
                          )}
                          {isCompleted && (
                            <span className="text-xs font-mono uppercase tracking-wider text-gray-400">
                              Complete
                            </span>
                          )}
                          
                          {/* Expand/Collapse Icon */}
                          <svg 
                            className={`w-4 h-4 text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} 
                            fill="none" 
                            viewBox="0 0 24 24" 
                            stroke="currentColor"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </div>
                      </button>

                      {/* Expanded Actions */}
                      {isExpanded && (
                        <div className="px-4 pb-4 pt-2 border-t border-neutral-700">
                          <div className="ml-9 space-y-1.5">
                            <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">
                              Extraction Actions
                            </div>
                            {phase.actions.map((action, idx) => (
                              <div 
                                key={idx}
                                className="flex items-start text-sm text-gray-400"
                              >
                                <svg className="w-4 h-4 mr-2 mt-0.5 flex-shrink-0 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                </svg>
                                <span className="font-mono text-xs leading-relaxed">{action}</span>
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
          </div>
        )}
        
        {results && (
          <div className="mt-8 space-y-6">
            {/* Summary */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <svg className="w-6 h-6 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z" />
                  <path fillRule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd" />
                </svg>
                Results Summary
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-neutral-950 rounded-lg p-4">
                  <div className="text-3xl font-bold text-white mb-1">{results.findings_count || 0}</div>
                  <div className="text-sm text-gray-400">Total Findings</div>
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

            {/* Data Extractor Viewer - Live Extracted Data */}
            {results.scan_id && (
              <div>
                <h4 className="text-xl font-bold text-white mb-4 flex items-center">
                  <svg className="w-5 h-5 mr-2 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Extracted Intelligence
                </h4>
                <DataExtractorViewer scanId={results.scan_id} />
              </div>
            )}
          </div>
        )}
      </div>

      {/* Legal Warning Modal */}
      {showWarning && (
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
    </div>
    </SecureContent>
  );
}
