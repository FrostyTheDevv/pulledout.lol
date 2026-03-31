import { Link } from 'react-router-dom';

export default function Terms() {
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
          <h1 className="text-4xl sm:text-5xl font-bold text-white mb-3">Terms of Service</h1>
          <div className="flex items-center gap-2 text-gray-400">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
            </svg>
            <p className="text-sm">Last Updated: March 21, 2026</p>
          </div>
        </div>

        {/* Introduction Card */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <p className="text-gray-300 text-lg leading-relaxed mb-6">
            Welcome to PULLEDOUT.LOL ("Service", "we", "us", or "our"). By accessing or using our Advanced Web Security Analysis Platform, you agree to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms, do not use the Service.
          </p>

          <div className="bg-yellow-500/10 border-l-4 border-yellow-500 rounded-r-lg p-5">
            <div className="flex items-start gap-3">
              <svg className="w-6 h-6 text-yellow-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
              </svg>
              <div>
                <strong className="text-yellow-400 text-lg block mb-2">⚠️ Important Notice</strong>
                <p className="text-gray-300">
                  This service requires Discord authentication and paid membership. Access is restricted to members of our exclusive Discord server.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Section 1 */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              1
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-4">Acceptance of Terms</h2>
              <p className="text-gray-300 mb-4">By creating an account or using PULLEDOUT.LOL, you confirm that you:</p>
              <ul className="space-y-3">
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-white flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  Are at least 18 years of age or have parental/guardian consent
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-white flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  Have the legal authority to enter into this agreement
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-white flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  Will comply with all applicable laws and regulations
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-white flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  Accept full responsibility for your use of the Service
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-white flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  Have read and agree to Discord's Terms of Service
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-white flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  Understand this is a paid service requiring Discord server membership
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Section 2 */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              2
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-4">Service Description</h2>
              <p className="text-gray-300 mb-4">PULLEDOUT.LOL provides automated web security scanning and vulnerability assessment tools. Our Service:</p>
              <div className="grid sm:grid-cols-2 gap-3">
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                    <span className="text-white font-semibold">Security Scanning</span>
                  </div>
                  <p className="text-gray-400 text-sm">Comprehensive vulnerability detection and misconfigurations</p>
                </div>
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                    <span className="text-white font-semibold">Detailed Reports</span>
                  </div>
                  <p className="text-gray-400 text-sm">OWASP Top 10 compliant security reports</p>
                </div>
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <span className="text-white font-semibold">Scan History</span>
                  </div>
                  <p className="text-gray-400 text-sm">Store and review all previous scans</p>
                </div>
                <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028 14.09 14.09 0 001.226-1.994.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
                    </svg>
                    <span className="text-white font-semibold">Discord OAuth</span>
                  </div>
                  <p className="text-gray-400 text-sm">Secure authentication integration</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Section 3 */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4 mb-6">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              3
            </div>
            <h2 className="text-2xl font-bold text-white">Account and Authentication</h2>
          </div>
          
          <div className="space-y-6">
            {/* Discord OAuth */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028 14.09 14.09 0 001.226-1.994.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
                </svg>
                <h3 className="text-xl font-semibold text-white">3.1 Discord OAuth</h3>
              </div>
              <p className="text-gray-300 mb-4">Authentication is handled exclusively through Discord OAuth. By using this Service, you:</p>
              <div className="grid gap-2">
                <div className="flex items-start gap-2">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0 mt-2"></span>
                  <span className="text-gray-300">Must have a valid Discord account in good standing</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0 mt-2"></span>
                  <span className="text-gray-300">Authorize us to access your Discord user ID, username, and avatar</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0 mt-2"></span>
                  <span className="text-gray-300">Agree that your Discord account represents your identity on our platform</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="w-2 h-2 bg-white rounded-full flex-shrink-0 mt-2"></span>
                  <span className="text-gray-300">Accept that account actions are linked to your Discord profile</span>
                </div>
              </div>
            </div>

            {/* Server Membership */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path>
                </svg>
                <h3 className="text-xl font-semibold text-white">3.2 Server Membership Requirement</h3>
              </div>
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4">
                <p className="text-red-300"><strong>CRITICAL:</strong> Access requires active Discord server membership</p>
              </div>
              <p className="text-gray-300 mb-3">We verify your server membership before granting access. If you:</p>
              <div className="grid gap-2">
                <div className="flex items-start gap-2">
                  <svg className="w-4 h-4 text-red-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                  </svg>
                  <span className="text-gray-300">Leave the Discord server, your access will be immediately revoked</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-4 h-4 text-red-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                  </svg>
                  <span className="text-gray-300">Are banned or kicked from the server, you will lose all access</span>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-4 h-4 text-red-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                  </svg>
                  <span className="text-gray-300">Transfer your account, access will be revoked (non-transferable)</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Section 4 */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4 mb-6">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              4
            </div>
            <h2 className="text-2xl font-bold text-white">Payment and Access</h2>
          </div>
          
          <div className="space-y-6">
            {/* Payment Terms */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z"></path>
                </svg>
                <h3 className="text-xl font-semibold text-white">4.1 Payment Terms</h3>
              </div>
              <div className="grid sm:grid-cols-2 gap-3">
                <div className="flex items-start gap-2">
                  <span className="text-white font-semibold min-w-fit">Price:</span>
                  <span className="text-gray-300">One-time $50 payment</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-white font-semibold min-w-fit">Processor:</span>
                  <span className="text-gray-300">LemonSqueezy (secure)</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-white font-semibold min-w-fit">Currency:</span>
                  <span className="text-gray-300">USD</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-white font-semibold min-w-fit">Taxes:</span>
                  <span className="text-gray-300">May apply by jurisdiction</span>
                </div>
                <div className="flex items-start gap-2 sm:col-span-2">
                  <span className="text-white font-semibold min-w-fit">Methods:</span>
                  <span className="text-gray-300">Credit/debit card, LemonSqueezy supported methods</span>
                </div>
              </div>
            </div>

            {/* Refund Policy */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                <h3 className="text-xl font-semibold text-white">4.2 Refund Policy</h3>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 mb-4">
                <p className="text-green-300"><strong>7-Day Refund Window:</strong> Full refund available within 7 days of purchase</p>
              </div>
              <div className="space-y-2">
                <div className="flex items-start gap-2">
                  <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  <div><strong className="text-white">Conditions:</strong> <span className="text-gray-300">No excessive usage or abuse</span></div>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  <div><strong className="text-white">Process:</strong> <span className="text-gray-300">Contact support via Discord</span></div>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                  </svg>
                  <div><strong className="text-white">Exceptions:</strong> <span className="text-gray-300">May be denied for violations or fraud</span></div>
                </div>
                <div className="flex items-start gap-2">
                  <svg className="w-4 h-4 text-red-400 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                  </svg>
                  <div><strong className="text-white">After 7 Days:</strong> <span className="text-gray-300">All sales are final (unless required by law)</span></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Section 5 - Critical Warning */}
        <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/30 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4">
            <div className="bg-red-500 text-white rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              !
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-4">5. Authorized Use Only</h2>
              <div className="bg-red-500/20 border border-red-500/40 rounded-lg p-4 mb-4">
                <p className="text-white font-semibold text-lg mb-2">
                  🚨 CRITICAL: Authorization Required
                </p>
                <p className="text-gray-200">
                  You must ONLY scan websites and web applications for which you have explicit written authorization.
                </p>
              </div>
              <p className="text-gray-300 mb-4">You agree to use this Service exclusively for:</p>
              <ul className="space-y-2 mb-4">
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  Websites and applications that you own
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  Systems where you have obtained explicit written permission
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  Your own development, staging, or testing environments
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  Legitimate security research with proper authorization
                </li>
                <li className="flex items-start gap-3 text-gray-300">
                  <svg className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                  Educational purposes with documented permission
                </li>
              </ul>
              <div className="bg-yellow-500/20 border-l-4 border-yellow-500 rounded-r-lg p-4">
                <p className="text-yellow-300 font-semibold mb-2">⚠️ Legal Warning</p>
                <p className="text-gray-200 text-sm">
                  Scanning websites without authorization may violate the Computer Fraud and Abuse Act (CFAA), anti-hacking laws, or similar legislation in your jurisdiction, and may result in civil and criminal penalties.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Section 6 */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8 mb-6">
          <div className="flex items-start gap-4">
            <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
              6
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-4">Prohibited Activities</h2>
              <div className="bg-red-500/10 border-l-4 border-red-500 rounded-r-lg p-4 mb-4">
                <p className="text-red-300 font-semibold">🚫 You explicitly agree NOT to use PULLEDOUT.LOL to:</p>
              </div>
              <div className="grid gap-3">
                <div className="flex items-start gap-3 bg-neutral-900 border border-neutral-800 rounded-lg p-3">
                  <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                  </svg>
                  <span className="text-gray-300">Scan any website without explicit authorization from the owner</span>
                </div>
                <div className="flex items-start gap-3 bg-neutral-900 border border-neutral-800 rounded-lg p-3">
                  <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                  </svg>
                  <span className="text-gray-300">Conduct attacks, exploits, or any malicious activities</span>
                </div>
                <div className="flex items-start gap-3 bg-neutral-900 border border-neutral-800 rounded-lg p-3">
                  <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                  </svg>
                  <span className="text-gray-300">Attempt to gain unauthorized access to systems or data</span>
                </div>
                <div className="flex items-start gap-3 bg-neutral-900 border border-neutral-800 rounded-lg p-3">
                  <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                  </svg>
                  <span className="text-gray-300">Violate any local, state, national, or international laws</span>
                </div>
                <div className="flex items-start gap-3 bg-neutral-900 border border-neutral-800 rounded-lg p-3">
                  <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                  </svg>
                  <span className="text-gray-300">Distribute malware, viruses, or harmful code</span>
                </div>
                <div className="flex items-start gap-3 bg-neutral-900 border border-neutral-800 rounded-lg p-3">
                  <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                  </svg>
                  <span className="text-gray-300">Share, resell, or redistribute your access without permission</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Sections 7-9 Grid */}
        <div className="grid sm:grid-cols-3 gap-6 mb-6">
          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                7
              </div>
              <h2 className="text-xl font-bold text-white">Liability</h2>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
              <p className="text-gray-300 text-sm">
                TO THE MAXIMUM EXTENT PERMITTED BY LAW, we are NOT LIABLE for any damages. Total liability shall not exceed the amount you paid for the Service.
              </p>
            </div>
          </div>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                8
              </div>
              <h2 className="text-xl font-bold text-white">Modifications</h2>
            </div>
            <p className="text-gray-300 text-sm">
              We reserve the right to modify, suspend, or discontinue the Service at any time. Continued use after changes means acceptance of modified Terms.
            </p>
          </div>

          <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-white text-black rounded-lg w-10 h-10 flex items-center justify-center font-bold text-lg flex-shrink-0">
                9
              </div>
              <h2 className="text-xl font-bold text-white">Contact</h2>
            </div>
            <div className="flex items-center gap-2 bg-neutral-900 border border-neutral-800 rounded-lg p-3">
              <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 24 24">
                <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028 14.09 14.09 0 001.226-1.994.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
              </svg>
              <p className="text-gray-300 text-sm">Discord server</p>
            </div>
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-6 sm:p-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              <Link to="/privacy" className="text-white hover:text-gray-300 font-medium inline-flex items-center gap-2">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                </svg>
                Privacy Policy
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
