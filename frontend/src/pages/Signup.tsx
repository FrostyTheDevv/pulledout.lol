import { Link } from 'react-router-dom';
const API_URL = import.meta.env.VITE_API_URL || '';

export default function Signup() {
  const handleDiscordSignup = () => {
    // Redirect to Discord OAuth for signup
    window.location.href = `${API_URL}/auth/login`;
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4">
      <div className="bg-neutral-950 border border-neutral-800 rounded-xl shadow-2xl max-w-md w-full p-6 sm:p-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">
            Create Account
          </h1>
          <p className="text-gray-400">PULLEDOUT.LOL</p>
        </div>

        {/* Payment Notice */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4 mb-6">
          <div className="flex items-center gap-3 mb-2">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect>
              <line x1="1" y1="10" x2="23" y2="10"></line>
            </svg>
            <strong className="text-white">One-Time Payment Required</strong>
          </div>
          <p className="text-gray-400 text-sm">
            After signing up via Discord, you'll be directed to checkout. <Link to="/pay" className="text-white hover:text-gray-300 underline">View pricing</Link>
          </p>
        </div>

        {/* Discord Signup Button */}
        <button
          onClick={handleDiscordSignup}
          className="w-full bg-white hover:bg-gray-200 text-black font-semibold py-3 px-6 rounded-lg transition flex items-center justify-center space-x-3 mb-6"
        >
          <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
            <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
          </svg>
          <span>Sign up with Discord</span>
        </button>

        {/* Footer */}
        <div className="text-center">
          <p className="text-sm text-gray-400 mb-4">
            Already have an account? <Link to="/login" className="text-white hover:text-gray-300">Login here</Link>
          </p>
          <p className="text-xs text-gray-600 mb-4">
            <Link to="/terms" className="hover:text-gray-400">Terms of Service</Link> • <Link to="/privacy" className="hover:text-gray-400">Privacy Policy</Link>
          </p>
          <p className="text-xs text-gray-500">
            By signing up, you agree to our Terms and will complete payment after authentication
          </p>
        </div>
      </div>
    </div>
  );
}
