import { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { startExposedFiles, getToolStatus, getToolResults } from '../utils/api';
import FindingCard from '../components/FindingCard';
import ScanPhaseIcon from '../components/ScanPhaseIcon';
import ExposedFilesViewer from '../components/ExposedFilesViewer';
import SecureContent from '../components/SecureContent';

const EXPOSED_FILES_PHASES = [
  {
    id: 1,
    name: 'Git Repository Scanning',
    icon: 'git-branch',
    actions: [
      'Testing for .git/config exposure',
      'Checking .git/HEAD accessibility',
      'Looking for .git/index files',
      'Scanning for exposed commit logs',
      'Attempting to reconstruct source code',
      'Testing git-dumper exploitation'
    ]
  },
  {
    id: 2,
    name: 'Environment & Config Files',
    icon: 'file-text',
    actions: [
      'Scanning for .env files',
      'Checking .env.production, .env.local',
      'Looking for config.php, web.config',
      'Testing for settings.json, application.yml',
      'Searching for credentials.json',
      'Checking for AWS credentials files'
    ]
  },
  {
    id: 3,
    name: 'Backup & Archive Files',
    icon: 'package',
    actions: [
      'Searching for .sql backup files',
      'Checking for .zip, .tar.gz archives',
      'Looking for database dump files',
      'Testing for backup.sql, dump.sql',
      'Scanning for old/ and backup/ directories',
      'Checking for .bak and .old files'
    ]
  },
  {
    id: 4,
    name: 'Admin & Debug Interfaces',
    icon: 'shield',
    actions: [
      'Testing for phpMyAdmin panels',
      'Checking for Adminer interfaces',
      'Looking for /admin, /administrator paths',
      'Scanning for debug.php, test.php',
      'Testing for phpinfo() pages',
      'Checking for Swagger/API docs'
    ]
  },
  {
    id: 5,
    name: 'Source Code & Documentation',
    icon: 'code',
    actions: [
      'Scanning for README.md files',
      'Looking for CHANGELOG exposed',
      'Checking for TODO.txt files',
      'Testing for .DS_Store files',
      'Searching for composer.json, package.json',
      'Looking for deployment scripts'
    ]
  }
];

export default function ExposedFiles() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [showWarning, setShowWarning] = useState(false);
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
      const loadingToast = toast.loading('Scanning for exposed files...');
      
      const data = await startExposedFiles(target);
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
          toast.success(`Found ${results.findings_count || 0} exposed files!`);
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
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Exposed Files Scanner</h1>
            <p className="text-gray-400 mt-2">
              Find .git directories, .env files, backups, configs, and exposed admin panels
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
            {loading ? 'Scanning for Files...' : 'Start File Scan'}
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

        {/* What We Scan For */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">.git Directory Exposure</h4>
                <p className="text-sm text-gray-400">.git/config, .git/HEAD, source code extraction, commit history</p>
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
                <h4 className="font-semibold text-white mb-1">Environment Files</h4>
                <p className="text-sm text-gray-400">.env, .env.production, .env.local with credentials and secrets</p>
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
                <h4 className="font-semibold text-white mb-1">Database Backups</h4>
                <p className="text-sm text-gray-400">backup.sql, dump.sql, database.bak, mysqldump files</p>
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
                <h4 className="font-semibold text-white mb-1">Configuration Files</h4>
                <p className="text-sm text-gray-400">config.php, web.config, settings.json, application.yml</p>
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
                <h4 className="font-semibold text-white mb-1">Admin Panels</h4>
                <p className="text-sm text-gray-400">/admin, /administrator, /wp-admin, phpMyAdmin, control panels</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">Log Files</h4>
                <p className="text-sm text-gray-400">error.log, access.log, debug.log, application logs</p>
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-1">SSH/Private Keys</h4>
                <p className="text-sm text-gray-400">id_rsa, id_dsa, private.key, server.key files</p>
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
                <h4 className="font-semibold text-white mb-1">Temporary Files</h4>
                <p className="text-sm text-gray-400">~backup, .bak, .old, .tmp, .swp editor files</p>
              </div>
            </div>
          </div>
        </div>

        {/* Results */}
        {loading && (
          <div ref={progressRef} className="mt-8 space-y-6">
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <h3 className="text-xl font-bold text-white mb-4">Scanning for Exposed Files...</h3>
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
              {EXPOSED_FILES_PHASES.map((phase) => {
                const isExpanded = expandedPhases.includes(phase.id);
                const currentPhase = Math.ceil((progress / 100) * EXPOSED_FILES_PHASES.length);
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
                            {isComplete ? 'Completed' : isActive ? 'Scanning...' : 'Pending'}
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

            {/* Exposed Files Viewer - Live File Contents */}
            {results.scan_id && (
              <div>
                <h4 className="text-xl font-bold text-white mb-4 flex items-center">
                  <svg className="w-5 h-5 mr-2 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Live File Data
                </h4>
                <ExposedFilesViewer scanId={results.scan_id} />
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
    </SecureContent>
  );
}
