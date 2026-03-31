import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getScans, deleteScan, getPlatformCapabilities } from '../utils/api';
import toast from 'react-hot-toast';
import SecureContent from '../components/SecureContent';

interface Scan {
  scan_id: string;
  target_url: string;
  scan_date: string;
  scan_type?: string;
  risk_level: string;
  risk_score: number;
  findings_count: number;
  pages_scanned: number;
}

interface PlatformCapabilities {
  active_modules: number;
  total_modules: number;
  attack_vectors: number;
  coverage_percentage: number;
  coverage_level: string;
}

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'tools' | 'history'>('overview');
  const [capabilities, setCapabilities] = useState<PlatformCapabilities | null>(null);

  useEffect(() => {
    loadScans();
    loadCapabilities();
  }, []);

  const loadCapabilities = async () => {
    try {
      const data = await getPlatformCapabilities();
      setCapabilities(data);
    } catch (error) {
      console.error('Failed to load platform capabilities:', error);
    }
  };

  const loadScans = async () => {
    try {
      const data = await getScans();
      setScans(data.scans || []);
    } catch (error: any) {
      toast.error(error.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (scanId: string) => {
    // Create a custom confirmation using toast
    const confirmed = window.confirm('Are you sure you want to delete this scan? This action cannot be undone.');
    
    if (!confirmed) return;

    const loadingToast = toast.loading('Deleting scan...');

    try {
      await deleteScan(scanId);
      toast.success('Scan deleted successfully', { id: loadingToast });
      loadScans();
    } catch (error: any) {
      toast.error('Failed to delete scan', { id: loadingToast });
    }
  };

  const getRiskColor = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'text-red-400';
      case 'HIGH':
        return 'text-orange-400';
      case 'MEDIUM':
        return 'text-yellow-400';
      case 'LOW':
        return 'text-blue-400';
      default:
        return 'text-gray-400';
    }
  };

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="animate-pulse text-gray-400">Loading scans...</div>
      </div>
    );
  }

  const tools = [
    {
      id: 'scanner',
      name: 'Vulnerability Scanner',
      description: capabilities 
        ? `${capabilities.coverage_level} web security scanning with ${capabilities.active_modules} active modules and ${capabilities.attack_vectors}+ attack vectors`
        : 'Comprehensive web application security scanning',
      icon: 'search',
      link: '/scanner',
      features: ['SQL Injection', 'XSS Testing', 'Auth Bypass', 'RCE Detection']
    },
    {
      id: 'database',
      name: 'Database Intrusion',
      description: 'Test MongoDB, MySQL, PostgreSQL, Redis, Elasticsearch exposure',
      icon: 'database',
      link: '/tools/database',
      features: ['Port Scanning', 'Connection Testing', 'Data Extraction', 'Breach Simulation']
    },
    {
      id: 'data-extract',
      name: 'Data Extractor',
      description: 'Extract API keys, secrets, credentials, and sensitive data',
      icon: 'folder',
      link: '/tools/data-extractor',
      features: ['API Keys', 'AWS Secrets', 'JWTs', 'Credentials', 'PII Scraping']
    },
    {
      id: 'cloud',
      name: 'Cloud Storage Scanner',
      description: 'Detect exposed S3, Azure, GCP buckets and test access',
      icon: 'cloud',
      link: '/tools/cloud',
      features: ['S3 Buckets', 'Azure Blobs', 'GCP Buckets', 'Public Access Testing']
    },
    {
      id: 'files',
      name: 'Exposed Files Scanner',
      description: 'Find .git, .env, backups, configs, and admin  panels',
      icon: 'document',
      link: '/tools/files',
      features: ['.git Exposure', '.env Files', 'Backups', 'Config Files', 'Admin Panels']
    },
    {
      id: 'api',
      name: 'API Security Tester',
      description: 'Test APIs for CORS, GraphQL, rate limiting, authentication',
      icon: 'plug',
      link: '/tools/api',
      features: ['CORS Testing', 'GraphQL', 'Swagger', 'Rate Limiting', 'Auth Bypass']
    },
    {
      id: 'network',
      name: 'Network Reconnaissance',
      description: 'DNS enumeration, subdomain discovery, port scanning',
      icon: 'globe',
      link: '/tools/network',
      features: ['DNS Records', 'Subdomains', 'Port Scanning', 'Service Detection']
    },
    {
      id: 'exploit',
      name: 'Penetration Testing',
      description: '30+ attack vectors - SQLi, XSS, CSRF, auth bypass, session hijacking',
      icon: 'lightning',
      link: '/tools/exploit',
      features: ['Injection Attacks', 'RCE Testing', 'Access Control', 'Protocol Attacks']
    }
  ];

  const getIconSVG = (iconName: string) => {
    const icons: Record<string, JSX.Element> = {
      search: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      ),
      database: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
        </svg>
      ),
      folder: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
      ),
      cloud: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
        </svg>
      ),
      document: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      ),
      plug: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
      ),
      globe: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
        </svg>
      ),
      lightning: (
        <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      )
    };
    return icons[iconName] || icons.search;
  };

  return (
    <SecureContent level="high">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <img src="/pulledout.png" alt="PULLEDOUT.LOL" className="h-16" />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-neutral-800">
        <div className="flex space-x-8">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-4 px-2 font-semibold transition ${
              activeTab === 'overview'
                ? 'text-white border-b-2 border-white'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('tools')}
            className={`pb-4 px-2 font-semibold transition ${
              activeTab === 'tools'
                ? 'text-white border-b-2 border-white'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Tools
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`pb-4 px-2 font-semibold transition ${
              activeTab === 'history'
                ? 'text-white border-b-2 border-white'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Scan History
          </button>
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="glass-card p-6">
              <div className="text-gray-400 text-sm mb-2">Total Scans</div>
              <div className="text-3xl font-bold text-white">{scans.length}</div>
              <div className="text-xs text-gray-500 mt-1">All-time scans</div>
            </div>
            <div className="glass-card p-6">
              <div className="text-gray-400 text-sm mb-2">Critical Issues</div>
              <div className="text-3xl font-bold text-white">
                {scans.filter(s => s.risk_level === 'CRITICAL').length}
              </div>
              <div className="text-xs text-gray-500 mt-1">Require immediate attention</div>
            </div>
            <div className="glass-card p-6">
              <div className="text-gray-400 text-sm mb-2">High Priority</div>
              <div className="text-3xl font-bold text-white">
                {scans.filter(s => s.risk_level === 'HIGH').length}
              </div>
              <div className="text-xs text-gray-500 mt-1">Should be addressed soon</div>
            </div>
            <div className="glass-card p-6">
              <div className="text-gray-400 text-sm mb-2">Avg Risk Score</div>
              <div className="text-3xl font-bold text-white">
                {scans.length > 0
                  ? Math.round(scans.reduce((sum, s) => sum + (s.risk_score || 0), 0) / scans.length)
                  : 0}
              </div>
              <div className="text-xs text-gray-500 mt-1">Out of 100</div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="glass-card p-6">
            <h2 className="text-xl font-bold text-white mb-4">Quick Launch</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <Link
                to="/scanner"
                className="bg-neutral-900 border border-neutral-800 hover:border-white rounded-lg p-5 transition group"
              >
                <svg className="w-10 h-10 text-white mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <div className="font-semibold text-white">Full Scan</div>
                <div className="text-sm text-gray-500 mt-1">Complete vulnerability assessment</div>
              </Link>
              <Link
                to="/tools/database"
                className="bg-neutral-900 border border-neutral-800 hover:border-white rounded-lg p-5 transition group"
              >
                <svg className="w-10 h-10 text-white mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                </svg>
                <div className="font-semibold text-white">DB Intrusion</div>
                <div className="text-sm text-gray-500 mt-1">Test database exposure</div>
              </Link>
              <Link
                to="/tools/files"
                className="bg-neutral-900 border border-neutral-800 hover:border-white rounded-lg p-5 transition group"
              >
                <svg className="w-10 h-10 text-white mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <div className="font-semibold text-white">File Scanner</div>
                <div className="text-sm text-gray-500 mt-1">Find exposed sensitive files</div>
              </Link>
              <Link
                to="/tools/cloud"
                className="bg-neutral-900 border border-neutral-800 hover:border-white rounded-lg p-5 transition group"
              >
                <svg className="w-10 h-10 text-white mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
                <div className="font-semibold text-white">Cloud Storage</div>
                <div className="text-sm text-gray-500 mt-1">S3, Azure, GCP testing</div>
              </Link>
            </div>
          </div>

          {/* Capabilities */}
          <div className="glass-card p-6">
            <h2 className="text-xl font-bold text-white mb-4">Platform Capabilities</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-neutral-950 border border-neutral-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-gray-400 text-sm">Active Modules</span>
                  <span className="text-white font-bold">
                    {capabilities ? `${capabilities.active_modules}/${capabilities.total_modules}` : '...'}
                  </span>
                </div>
                <div className="w-full bg-neutral-800 rounded-full h-2">
                  <div
                    className="bg-white h-2 rounded-full transition-all duration-500"
                    {...(capabilities && {
                      style: { width: `${Math.round((capabilities.active_modules / capabilities.total_modules) * 100)}%` }
                    })}
                  ></div>
                </div>
              </div>
              <div className="bg-neutral-950 border border-neutral-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-gray-400 text-sm">Attack Vectors</span>
                  <span className="text-white font-bold">
                    {capabilities ? `${capabilities.attack_vectors}+` : '...'}
                  </span>
                </div>
                <div className="w-full bg-neutral-800 rounded-full h-2">
                  <div className="bg-white h-2 rounded-full w-full"></div>
                </div>
              </div>
              <div className="bg-neutral-950 border border-neutral-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-gray-400 text-sm">Coverage</span>
                  <span className="text-white font-bold">
                    {capabilities ? capabilities.coverage_level : '...'}
                  </span>
                </div>
                <div className="w-full bg-neutral-800 rounded-full h-2">
                  <div
                    className="bg-white h-2 rounded-full transition-all duration-500"
                    {...(capabilities?.coverage_percentage && {
                      style: { width: `${capabilities.coverage_percentage}%` }
                    })}
                  ></div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Tools Tab */}
      {activeTab === 'tools' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {tools.map((tool) => {
            return (
              <Link
                key={tool.id}
                to={tool.link}
                className="glass-card p-6 border-2 border-neutral-800 hover:border-white transition group"
              >
                <div className="flex items-start space-x-4">
                  <div className="text-white flex-shrink-0">{getIconSVG(tool.icon)}</div>
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-white group-hover:text-gray-300 mb-2">
                      {tool.name}
                    </h3>
                    <p className="text-gray-400 text-sm mb-4">{tool.description}</p>
                    <div className="flex flex-wrap gap-2">
                      {tool.features.map((feature, idx) => (
                        <span
                          key={idx}
                          className="text-xs px-2 py-1 rounded bg-neutral-900 border border-neutral-800 text-white"
                        >
                          {feature}
                        </span>
                      ))}
                    </div>
                  </div>
                  <svg
                    className="w-6 h-6 text-gray-400 group-hover:text-white flex-shrink-0 transition"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </div>
              </Link>
            );
          })}
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="glass-card">
          <div className="p-6 border-b border-neutral-800 flex justify-between items-center">
            <h2 className="text-xl font-semibold text-white">Scan History</h2>
            <Link
              to="/scanner"
              className="px-4 py-2 bg-white hover:bg-gray-200 text-black rounded-lg transition font-semibold text-sm"
            >
              + New Scan
            </Link>
          </div>
          
          {scans.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              <svg className="mx-auto h-12 w-12 text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <p className="text-lg font-medium">No scans yet</p>
              <p className="text-sm text-gray-600 mt-1">Start your first security scan to see results here</p>
              <Link to="/scanner" className="inline-block mt-4 px-5 py-2 bg-white text-black rounded-lg hover:bg-gray-200 transition font-semibold">
                Start First Scan →
              </Link>
            </div>
          ) : (
            <div className="divide-y divide-neutral-800">
              {scans.map((scan) => (
                <div key={scan.scan_id} className="p-6 hover:bg-neutral-950/50 transition">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <Link
                          to={`/results/${scan.scan_id}`}
                          className="text-lg font-semibold text-white hover:text-gray-300 transition"
                        >
                          {scan.target_url}
                        </Link>
                        {scan.scan_type && scan.scan_type !== 'Comprehensive Scan' && (
                          <span className="px-2 py-0.5 text-xs rounded bg-neutral-800 border border-neutral-700 text-gray-300">
                            {scan.scan_type}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center space-x-4 mt-2 text-sm text-gray-400">
                        <span>📅 {new Date(scan.scan_date).toLocaleDateString()}</span>
                        <span>•</span>
                        <span>📄 {scan.pages_scanned} pages</span>
                        <span>•</span>
                        <span>🔍 {scan.findings_count} findings</span>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <div className={`text-lg font-bold ${getRiskColor(scan.risk_level)}`}>
                          {scan.risk_level || 'UNKNOWN'}
                        </div>
                        <div className="text-sm text-gray-500">Score: {scan.risk_score || 0}</div>
                      </div>
                      <button
                        onClick={() => handleDelete(scan.scan_id)}
                        className="px-3 py-1 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition text-sm"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
    </SecureContent>
  );
}
