import { Link } from 'react-router-dom';
import { useState } from 'react';
import toast from 'react-hot-toast';

const API_URL = import.meta.env.VITE_API_URL || '';

function getCookie(name: string): string | null {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null;
  }
  return null;
}

export default function Pricing() {
  const [loading, setLoading] = useState(false);

  const handlePurchase = async () => {
    setLoading(true);
    
    try {
      // Get session token from cookie
      const sessionToken = getCookie('sessionToken');
      
      if (!sessionToken) {
        toast.error('Please login first to purchase access');
        window.location.href = '/login';
        return;
      }

      // Call backend to create checkout session
      const response = await fetch(`${API_URL}/api/payment/create-checkout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`
        },
        credentials: 'include'
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to create checkout session');
      }

      if (data.checkout_url) {
        // Redirect to LemonSqueezy checkout
        toast.success('Redirecting to secure checkout...');
        window.location.href = data.checkout_url;
      } else {
        throw new Error('No checkout URL received');
      }
    } catch (error: any) {
      console.error('Payment error:', error);
      toast.error(error.message || 'Failed to initiate payment');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4">
      <div className="bg-neutral-950 border border-neutral-800 rounded-xl shadow-2xl max-w-md w-full p-6 sm:p-8 animate-fadeIn">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">
            Join the exclusive community.
          </h1>
        </div>

        {/* Paid Notice */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4 mb-6">
          <div className="flex items-center gap-3 mb-3">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect>
              <line x1="1" y1="10" x2="23" y2="10"></line>
            </svg>
            <strong className="text-white">One-Time Payment: $50</strong>
          </div>
          <p className="text-gray-400 text-sm mb-2">
            What's included: Unlimited scans, Specified Reporting, Consistent catigorization, Complete analysis
          </p>
          <p className="text-gray-400 text-sm mb-2">
            Use the button for its walkthrough on payment and how to access this service before logging in again.
          </p>
          <p className="text-gray-400 text-sm">
            1. Complete Purchase → 2. Recieve private message → 3. Join and verify payment to unlock access → 4. Confidenciality is key.
          </p>
        </div>

        {/* Purchase Button */}
        <button
          onClick={handlePurchase}
          disabled={loading}
          className="w-full bg-white hover:bg-gray-200 text-black font-semibold py-3 px-6 rounded-lg transition mb-6 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Processing...
            </span>
          ) : (
            'Purchase Access Now'
          )}
        </button>

        {/* Footer */}
        <div className="text-center">
          <p className="text-sm text-gray-400 mb-4">
            Already have access? <Link to="/login" className="text-white hover:text-gray-300">Login</Link>
          </p>
          <p className="text-xs text-gray-600">
            <Link to="/terms" className="hover:text-gray-400">Terms of Service</Link> • <Link to="/privacy" className="hover:text-gray-400">Privacy Policy</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
