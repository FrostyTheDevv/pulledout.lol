import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { startScan } from '../utils/api';
import toast from 'react-hot-toast';
import SecureContent from '../components/SecureContent';

export default function Scanner() {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [maxPages, setMaxPages] = useState(10);
  const [loading, setLoading] = useState(false);
  const [showWarning, setShowWarning] = useState(false);
  const [dontShowAgain, setDontShowAgain] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!url.trim()) {
      toast.error('Please enter a URL');
      return;
    }

    // Check if user has dismissed the warning permanently
    const warningDismissed = localStorage.getItem('legalWarningDismissed') === 'true';
    
    if (!warningDismissed) {
      setShowWarning(true);
      return;
    }

    performScan();
  };

  const performScan = async () => {
    setLoading(true);

    try {
      const result = await startScan(url, maxPages);
      toast.success('Scan started successfully!');
      navigate(`/results/${result.scan_id}`);
    } catch (error: any) {
      toast.error(error.message || 'Failed to start scan');
      setLoading(false);
    }
  };

  const handleAcceptWarning = () => {
    if (dontShowAgain) {
      localStorage.setItem('legalWarningDismissed', 'true');
    }
    setShowWarning(false);
    performScan();
  };

  return (
    <SecureContent level="high">
      <div className="max-w-2xl mx-auto">
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
        <h1 className="text-3xl font-bold text-white mb-6">New Security Scan</h1>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target URL
            </label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-white"
              disabled={loading}
            />
            <p className="mt-2 text-sm text-gray-500">
              Enter the target website URL to scan for vulnerabilities
            </p>
          </div>

          <div>
            <label htmlFor="maxPages" className="block text-sm font-medium text-gray-300 mb-2">
              Max Pages to Scan
            </label>
            <input
              id="maxPages"
              type="number"
              value={maxPages}
              onChange={(e) => setMaxPages(parseInt(e.target.value) || 100)}
              min="1"
              max="1000"
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-white"
              disabled={loading}
            />
            <p className="mt-2 text-sm text-gray-500">
              Limit the number of pages to crawl (default: 10)
            </p>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-white hover:bg-gray-200 disabled:bg-gray-700 disabled:cursor-not-allowed text-black font-semibold py-3 px-6 rounded-lg transition"
          >
            {loading ? 'Starting Scan...' : 'Start Scan'}
          </button>
        </form>

        <div className="mt-8">
          <h3 className="text-xl font-bold text-white mb-6 text-center">Comprehensive Security Analysis</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5 hover:border-neutral-700 transition">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-white mb-1">Injection Attacks</h4>
                  <p className="text-sm text-gray-400">SQL, NoSQL, XSS, SSTI, RCE testing</p>
                </div>
              </div>
            </div>
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5 hover:border-neutral-700 transition">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-white mb-1">Authentication & Sessions</h4>
                  <p className="text-sm text-gray-400">Auth bypass, session hijacking, credential harvesting</p>
                </div>
              </div>
            </div>
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5 hover:border-neutral-700 transition">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-white mb-1">Database Security</h4>
                  <p className="text-sm text-gray-400">Exposure detection, penetration, intrusion testing</p>
                </div>
              </div>
            </div>
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5 hover:border-neutral-700 transition">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-white mb-1">File & Upload Security</h4>
                  <p className="text-sm text-gray-400">Upload testing, exposed files, path traversal</p>
                </div>
              </div>
            </div>
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5 hover:border-neutral-700 transition">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-white mb-1">Infrastructure & Headers</h4>
                  <p className="text-sm text-gray-400">SSL/TLS, security headers, network recon</p>
                </div>
              </div>
            </div>
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5 hover:border-neutral-700 transition">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-10 h-10 bg-neutral-800 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold text-white mb-1">CMS & API Testing</h4>
                  <p className="text-sm text-gray-400">WordPress, Drupal, Joomla exploits + API security</p>
                </div>
              </div>
            </div>
          </div>
        </div>
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
