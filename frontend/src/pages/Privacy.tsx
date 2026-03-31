import { Link } from 'react-router-dom';

export default function Privacy() {
  return (
    <div className="min-h-screen bg-black py-8 px-4">
      <div className="max-w-5xl mx-auto">
        {/* Header Card */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <Link to="/login" className="text-white hover:text-gray-300 text-sm inline-flex items-center gap-2 mb-6">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7"></path>
            </svg>
            Back to Login
          </Link>
          <div className="flex items-start gap-4">
            <svg className="w-12 h-12 text-white flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
            </svg>
            <div className="flex-1">
              <h1 className="text-4xl sm:text-5xl font-bold text-white mb-3">Privacy Policy</h1>
              <div className="flex items-center gap-2 text-gray-400">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                </svg>
                <p className="text-sm">Last Updated: March 21, 2026</p>
              </div>
            </div>
          </div>
        </div>

        {/* Introduction Card */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <p className="text-gray-300 text-lg leading-relaxed mb-6">
            At PULLEDOUT.LOL ("we", "us", or "our"), we take your privacy seriously. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our Advanced Web Security Analysis Platform ("Service").
          </p>

          <div className="bg-blue-500/10 border-l-4 border-blue-500 rounded-r-lg p-5">
            <div className="flex items-start gap-3">
              <svg className="w-6 h-6 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
              <div>
                <strong className="text-blue-300 text-lg block mb-2">📌 Quick Summary</strong>
                <p className="text-gray-300">
                  We use Discord OAuth for authentication and require server membership for access. We collect minimal data necessary to operate the Service. Payment is processed securely through LemonSqueezy. We do not sell your information.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Section 1: Information Collection */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4 mb-6">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              1
            </div>
            <h2 className="text-2xl font-bold text-white">Information We Collect</h2>
          </div>
          
          <div className="space-y-6">
            {/* Discord Info */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028 14.09 14.09 0 001.226-1.994.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
                </svg>
                <h3 className="text-xl font-semibold text-white">1.1 Discord Account Information</h3>
              </div>
              <p className="text-gray-300 mb-4">When you authenticate using Discord OAuth, we collect:</p>
              <div className="grid gap-3">
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Discord User ID:</strong>
                    <span className="text-gray-300 ml-2">Your unique Discord identifier</span>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Discord Username:</strong>
                    <span className="text-gray-300 ml-2">Your Discord username and discriminator</span>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Discord Avatar:</strong>
                    <span className="text-gray-300 ml-2">Your Discord profile avatar URL</span>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Server Membership:</strong>
                    <span className="text-gray-300 ml-2">Verification of Discord server membership</span>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Authentication Tokens:</strong>
                    <span className="text-gray-300 ml-2">Temporary OAuth tokens (not stored permanently)</span>
                  </div>
                </div>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 mt-4">
                <p className="text-green-300 text-sm">
                  <strong>🔒 Secure:</strong> We do NOT store your Discord password. Authentication is handled securely through Discord's OAuth 2.0 system.
                </p>
              </div>
            </div>

            {/* Payment Info */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"></path>
                </svg>
                <h3 className="text-xl font-semibold text-white">1.2 Payment Information</h3>
              </div>
              <p className="text-gray-300 mb-4">Payment processing is handled by LemonSqueezy. We collect:</p>
              <div className="grid gap-3">
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Transaction ID:</strong>
                    <span className="text-gray-300 ml-2">Unique identifier for your purchase</span>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Payment Status:</strong>
                    <span className="text-gray-300 ml-2">Success/failure status of transactions</span>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Purchase Date:</strong>
                    <span className="text-gray-300 ml-2">Timestamp of your access purchase</span>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  <div>
                    <strong className="text-white">Payment Amount:</strong>
                    <span className="text-gray-300 ml-2">Amount paid for access</span>
                  </div>
                </div>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 mt-4">
                <p className="text-blue-300 text-sm">
                  <strong>💳 Important:</strong> We do NOT store credit card numbers, CVV codes, or banking details. All payment card data is processed and stored securely by LemonSqueezy in compliance with PCI-DSS standards.
                </p>
              </div>
            </div>

            {/* Scan Data */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path>
                </svg>
                <h3 className="text-xl font-semibold text-white">1.3 Scan Data</h3>
              </div>
              <p className="text-gray-300 mb-4">When you use our security scanning features, we collect and store:</p>
              <div className="grid gap-2">
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Target URLs</strong> and domains you submit</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Scan Results</strong> and security analysis data</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Scan Metadata</strong> (date, time, settings)</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Generated Reports</strong> in HTML format</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Scan History</strong> (limited retention)</div>
                </div>
              </div>
            </div>

            {/* Technical Info */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                </svg>
                <h3 className="text-xl font-semibold text-white">1.4 Technical Information</h3>
              </div>
              <p className="text-gray-300 mb-4">We automatically collect certain technical data:</p>
              <div className="grid gap-2">
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">IP Address</strong> for security and fraud prevention</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Browser Information</strong> (type, version, language)</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Device Information</strong> (OS and device type)</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Usage Data</strong> (pages, features, timestamps)</div>
                </div>
                <div className="flex items-center gap-2 text-gray-300">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0"></span>
                  <div><strong className="text-white">Session Tokens</strong> (7-day expiration)</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Section 2-5: Boxed sections */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4 mb-6">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              2
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-4">How We Use Your Information</h2>
              <div className="grid sm:grid-cols-2 gap-3">
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Provide and maintain Services</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Verify Discord membership</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Process payments</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Generate security reports</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Improve user experience</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Prevent fraud and abuse</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Comply with legal obligations</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  <span className="text-gray-300">Communicate important updates</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              3
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-4">Data Sharing and Disclosure</h2>
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4 mb-4">
                <p className="text-green-300 font-semibold">🚫 We do NOT sell your personal information</p>
              </div>
              <p className="text-gray-300 mb-4">We may share data with:</p>
              <div className="space-y-3">
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028 14.09 14.09 0 001.226-1.994.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
                    </svg>
                    <strong className="text-white">Discord</strong>
                  </div>
                  <p className="text-gray-400 text-sm">OAuth authentication and server membership verification</p>
                </div>
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"></path>
                    </svg>
                    <strong className="text-white">LemonSqueezy</strong>
                  </div>
                  <p className="text-gray-400 text-sm">Payment processing and transaction management</p>
                </div>
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path>
                    </svg>
                    <strong className="text-white">Hosting Providers</strong>
                  </div>
                  <p className="text-gray-400 text-sm">Railway and infrastructure services</p>
                </div>
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3"></path>
                    </svg>
                    <strong className="text-white">Legal Authorities</strong>
                  </div>
                  <p className="text-gray-400 text-sm">When required by law or to protect our rights</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid sm:grid-cols-2 gap-6 mb-6">
          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                4
              </div>
              <h2 className="text-2xl font-bold text-white">Data Security</h2>
            </div>
            <p className="text-gray-300">
              We implement industry-standard security measures including encryption, secure authentication, and regular security audits. However, no system is completely secure.
            </p>
          </div>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                5
              </div>
              <h2 className="text-2xl font-bold text-white">Data Retention</h2>
            </div>
            <p className="text-gray-300">
              We retain information as needed to provide the Service. Scan history has limited retention. Request account deletion through Discord.
            </p>
          </div>
        </div>

        <div className="grid sm:grid-cols-2 gap-6 mb-6">
          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                6
              </div>
              <h2 className="text-xl font-bold text-white">Your Rights</h2>
            </div>
            <div className="space-y-2">
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7"></path>
                </svg>
                <span className="text-gray-300 text-sm">Access your information</span>
              </div>
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7"></path>
                </svg>
                <span className="text-gray-300 text-sm">Request data correction</span>
              </div>
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7"></path>
                </svg>
                <span className="text-gray-300 text-sm">Request account deletion</span>
              </div>
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7"></path>
                </svg>
                <span className="text-gray-300 text-sm">Object to data processing</span>
              </div>
              <div className="flex items-start gap-2">
                <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7"></path>
                </svg>
                <span className="text-gray-300 text-sm">Withdraw consent</span>
              </div>
            </div>
          </div>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                7
              </div>
              <h2 className="text-xl font-bold text-white">Cookies</h2>
            </div>
            <p className="text-gray-300 text-sm">
              We use session cookies for authentication and functionality. These are essential for operation. We do not use tracking or advertising cookies.
            </p>
          </div>
        </div>

        <div className="grid sm:grid-cols-3 gap-6 mb-6">
          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                8
              </div>
              <h2 className="text-lg font-bold text-white">Third-Party Links</h2>
            </div>
            <p className="text-gray-300 text-sm">
              We link to third-party sites (Discord, LemonSqueezy). Review their privacy policies.
            </p>
          </div>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                9
              </div>
              <h2 className="text-lg font-bold text-white">Policy Changes</h2>
            </div>
            <p className="text-gray-300 text-sm">
              We may update this policy. Check the "Last Updated" date. Continued use means acceptance.
            </p>
          </div>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                10
              </div>
              <h2 className="text-lg font-bold text-white">Contact Us</h2>
            </div>
            <p className="text-gray-300 text-sm">
              Questions? Contact us through our Discord server.
            </p>
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              <Link to="/terms" className="text-white hover:text-gray-300 font-medium inline-flex items-center gap-2">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                Terms of Service
              </Link>
              <Link to="/login" className="text-white hover:text-gray-300 font-medium inline-flex items-center gap-2">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"></path>
                </svg>
                Login
              </Link>
            </div>
            <p className="text-gray-500 text-sm">© 2026 PULLEDOUT.LOL</p>
          </div>
        </div>
      </div>
    </div>
  );
}
