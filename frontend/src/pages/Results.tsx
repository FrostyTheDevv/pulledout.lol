import { useEffect, useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScanResults, getScanStatus } from '../utils/api';
import toast from 'react-hot-toast';
import FindingCard from '../components/FindingCard';
import ScanPhaseIcon from '../components/ScanPhaseIcon';
import SecureContent from '../components/SecureContent';
import axios from 'axios';

interface Finding {
  severity: string;
  category: string;
  title: string;
  description: string;
  url: string;
  remediation: string;
  evidence?: any;
  payload?: string;
  timestamp?: string;
}

interface ScanResults {
  target_url: string;
  risk_score: number;
  risk_level: string;
  pages_scanned: number;
  findings: Finding[];
  findings_count: number;
  findings_summary: {
    CRITICAL?: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
}

interface ScanPhase {
  id: number;
  name: string;
  progress: number;
  icon: string;
  category: string;
  actions?: string[];
}

interface ScanStatus {
  status: 'starting' | 'running' | 'completed' | 'failed';
  progress: number;
  message: string;
  pages_scanned?: number;
  total_findings?: number;
  error_details?: string;
  current_phase?: ScanPhase;
  completed_phases?: number[];
  total_phases?: number;
}

export default function Results() {
  const { scanId} = useParams<{ scanId: string }>();
  const [phase, setPhase] = useState<'loading' | 'running' | 'completed' | 'failed'>('loading');
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [allPhases, setAllPhases] = useState<ScanPhase[]>([]);
  const [expandedPhases, setExpandedPhases] = useState<Set<number>>(new Set());
  const pollInterval = useRef<number | null>(null);
  
  // Load scan phases on mount
  useEffect(() => {
    const loadPhases = async () => {
      try {
        const response = await axios.get('/api/scan/phases');
        setAllPhases(response.data.phases);
      } catch (error) {
        console.error('Failed to load scan phases:', error);
      }
    };
    loadPhases();
  }, []);

  useEffect(() => {
    if (scanId) {
      startPolling(scanId);
    }
    return () => {
      if (pollInterval.current) {
        clearInterval(pollInterval.current);
      }
    };
  }, [scanId]);

  const startPolling = async (id: string) => {
    // Immediate first check
    await pollStatus(id);
    
    // Poll every second
    pollInterval.current = setInterval(() => {
      pollStatus(id);
    }, 1000);
  };

  const pollStatus = async (id: string) => {
    try {
      const statusData = await getScanStatus(id);
      setStatus(statusData);

      if (statusData.status === 'completed') {
        // Stop polling and fetch final results
        if (pollInterval.current) {
          clearInterval(pollInterval.current);
        }
        const resultsData = await getScanResults(id);
        setResults(resultsData);
        setPhase('completed');
      } else if (statusData.status === 'failed') {
        if (pollInterval.current) {
          clearInterval(pollInterval.current);
        }
        setPhase('failed');
        toast.error('Scan failed');
      } else {
        setPhase('running');
      }
    } catch (error: any) {
      // If 404, scan might be old and only in results
      if (error.response?.status === 404) {
        try {
          const resultsData = await getScanResults(id);
          setResults(resultsData);
          setPhase('completed');
          if (pollInterval.current) {
            clearInterval(pollInterval.current);
          }
        } catch {
          setPhase('failed');
          toast.error('Scan not found');
        }
      }
    }
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

  // Live scanning state
  if (phase === 'loading' || phase === 'running') {
    return (
      <div className="min-h-screen bg-black text-white p-6">
        <div className="max-w-6xl mx-auto space-y-6">
          <div>
            <Link to="/dashboard" className="text-gray-400 hover:text-white text-sm mb-4 inline-flex items-center group transition-colors">
              <svg className="w-4 h-4 mr-1 group-hover:-translate-x-1 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              Back to Dashboard
            </Link>
            <h1 className="text-4xl font-bold text-white tracking-tight">Security Scan in Progress</h1>
            <p className="text-gray-400 mt-2 text-sm font-mono">Comprehensive vulnerability assessment underway</p>
          </div>

          {/* Live Progress Bar */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
            <div className="mb-4">
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-mono uppercase tracking-wider text-gray-400">Scan Progress</span>
                <span className="text-sm font-mono text-white">{status?.progress || 0}%</span>
              </div>
              <div className="w-full bg-neutral-800 rounded h-2 overflow-hidden">
                <div 
                  className="h-full bg-white transition-all duration-500 ease-out"
                  data-progress={status?.progress || 0}
                  ref={(el) => {
                    if (el) el.style.width = `${status?.progress || 0}%`;
                  }}
                />
              </div>
            </div>
            
            <div className="flex items-center space-x-2 text-gray-400">
              <div className="w-4 h-4 border-2 border-gray-600 border-t-white rounded-full animate-spin"></div>
              <span className="text-sm font-mono">{status?.message || 'Initializing security modules...'}</span>
            </div>
          </div>

          {/* Live Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Pages Scanned</div>
              <div className="text-3xl font-bold text-white font-mono">
                {status?.pages_scanned || 0}
              </div>
            </div>
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Findings Detected</div>
              <div className="text-3xl font-bold text-white font-mono">
                {status?.total_findings || 0}
              </div>
            </div>
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Phases Complete</div>
              <div className="text-3xl font-bold text-white font-mono">
                {status?.completed_phases?.length || 0}/{status?.total_phases || 37}
              </div>
            </div>
          </div>

          {/* Scanning Phases - Professional Expandable Display */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center">
              <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
              Security Assessment Phases
            </h2>
            
            <div className="space-y-2 max-h-[600px] overflow-y-auto">
              {allPhases.map((scanPhase: ScanPhase) => {
                const isCompleted = status?.completed_phases?.includes(scanPhase.id);
                const isActive = status?.current_phase?.id === scanPhase.id;
                const isExpanded = expandedPhases.has(scanPhase.id);
                const hasActions = scanPhase.actions && scanPhase.actions.length > 0;
                
                return (
                  <div 
                    key={scanPhase.id}
                    className={`border rounded transition-all ${
                      isActive ? 'bg-neutral-800 border-white shadow-lg' : 
                      isCompleted ? 'bg-neutral-900 border-neutral-700' :
                      'bg-black border-neutral-800'
                    }`}
                  >
                    {/* Phase Header - Click to expand */}
                    <button
                      onClick={() => togglePhase(scanPhase.id)}
                      className="w-full flex items-center p-4 text-left hover:bg-neutral-800/50 transition-colors"
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
                          <div className="w-3 h-3 rounded-full bg-neutral-700"></div>
                        )}
                      </div>
                      
                      {/* Phase Icon */}
                      <div className={`flex-shrink-0 mr-3 ${
                        isActive ? 'text-white' : 
                        isCompleted ? 'text-gray-300' :
                        'text-gray-600'
                      }`}>
                        <ScanPhaseIcon icon={scanPhase.icon} className="w-5 h-5" />
                      </div>
                      
                      {/* Phase Name */}
                      <div className="flex-1">
                        <div className={`text-sm font-semibold ${
                          isActive ? 'text-white' : 
                          isCompleted ? 'text-gray-300' :
                          'text-gray-500'
                        }`}>
                          {scanPhase.name}
                        </div>
                      </div>
                      
                      {/* Status Badge */}
                      <div className="flex items-center space-x-3">
                        {isActive && (
                          <span className="text-xs font-mono uppercase tracking-wider text-white px-2 py-1 bg-neutral-700 rounded">
                            Running
                          </span>
                        )}
                        {isCompleted && (
                          <span className="text-xs font-mono uppercase tracking-wider text-gray-400">
                            Complete
                          </span>
                        )}
                        
                        {/* Expand/Collapse Icon */}
                        {hasActions && (
                          <svg 
                            className={`w-4 h-4 text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} 
                            fill="none" 
                            viewBox="0 0 24 24" 
                            stroke="currentColor"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        )}
                      </div>
                    </button>

                    {/* Expanded Actions */}
                    {isExpanded && hasActions && (
                      <div className="px-4 pb-4 pt-2 border-t border-neutral-800">
                        <div className="ml-9 space-y-1.5">
                          <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">
                            Assessment Actions
                          </div>
                          {scanPhase.actions!.map((action, idx) => (
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
      </div>
    );
  }

  // Failed state
  if (phase === 'failed') {
    return (
      <div className="min-h-screen bg-black text-white p-6 flex items-center justify-center">
        <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-8 max-w-lg">
          <svg className="w-16 h-16 mx-auto text-white mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h2 className="text-2xl font-bold text-white mb-2 text-center">Scan Failed</h2>
          <p className="text-gray-400 mb-4 text-center text-sm">{status?.message || 'An error occurred during the scan'}</p>
          {status?.error_details && (
            <pre className="text-left text-xs text-gray-400 bg-black border border-neutral-800 p-4 rounded overflow-auto max-h-48 font-mono">
              {status.error_details}
            </pre>
          )}
          <Link to="/dashboard" className="inline-flex items-center justify-center w-full mt-6 text-gray-400 hover:text-white transition-colors">
            <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  // No results loaded yet
  if (!results) {
    return (
      <div className="min-h-screen bg-black text-white p-6 flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-gray-600 border-t-white rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400 font-mono text-sm">Loading results...</p>
        </div>
      </div>
    );
  }

  return (
    <SecureContent level="maximum">
      <div className="min-h-screen bg-black text-white p-6">
        <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div>
          <Link to="/dashboard" className="text-gray-400 hover:text-white text-sm mb-4 inline-flex items-center group transition-colors">
            <svg className="w-4 h-4 mr-1 group-hover:-translate-x-1 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to Dashboard
          </Link>
          <h1 className="text-4xl font-bold text-white tracking-tight">{results.target_url}</h1>
          <p className="text-gray-400 mt-2 text-sm font-mono">{results.pages_scanned} pages scanned • {results.findings?.length || 0} findings</p>
        </div>

        {/* Summary */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
            <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Risk Score</div>
            <div className="text-3xl font-bold text-white font-mono">{results.risk_score}</div>
            <div className="text-sm mt-1 font-mono text-gray-400">
              {results.risk_level}
            </div>
          </div>
          {results.findings_summary?.CRITICAL && results.findings_summary.CRITICAL > 0 && (
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
              <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Critical</div>
              <div className="text-3xl font-bold text-white font-mono">
                {results.findings_summary.CRITICAL}
              </div>
            </div>
          )}
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
            <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">High</div>
            <div className="text-3xl font-bold text-white font-mono">
              {results.findings_summary?.HIGH || 0}
            </div>
          </div>
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
            <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Medium</div>
            <div className="text-3xl font-bold text-white font-mono">
              {results.findings_summary?.MEDIUM || 0}
            </div>
          </div>
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
            <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Low</div>
            <div className="text-3xl font-bold text-white font-mono">
              {results.findings_summary?.LOW || 0}
            </div>
          </div>
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
            <div className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Info</div>
            <div className="text-3xl font-bold text-white font-mono">
              {results.findings_summary?.INFO || 0}
            </div>
          </div>
        </div>

        {/* Findings */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
          <h2 className="text-xl font-bold text-white mb-6 flex items-center">
            <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
            </svg>
            Security Findings ({results.findings?.length || 0})
          </h2>
          
          <div className="space-y-3">
            {results.findings && results.findings.length > 0 ? (
              results.findings
                .sort((a: any, b: any) => {
                  const severity = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5 };
                  return (severity[a.severity as keyof typeof severity] || 99) - (severity[b.severity as keyof typeof severity] || 99);
                })
                .map((finding: Finding, index: number) => (
                  <FindingCard key={index} finding={finding} />
                ))
            ) : (
              <div className="text-center py-12">
                <svg className="w-16 h-16 mx-auto text-gray-700 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p className="text-gray-300 text-lg font-semibold">No Security Issues Detected</p>
                <p className="text-gray-500 text-sm mt-2 font-mono">Scan completed successfully with 0 findings</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
    </SecureContent>
  );
}