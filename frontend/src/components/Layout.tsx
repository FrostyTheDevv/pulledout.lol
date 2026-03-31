import { Link, useNavigate, useLocation, Outlet } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { SecureStorage } from '../utils/security';

export default function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Get user info from session
    const userInfo = SecureStorage.getItem('user_info');
    if (userInfo) {
      try {
        const parsed = JSON.parse(userInfo);
        setUsername(parsed.username || parsed.discord_username || 'User');
      } catch {}
    }
    setIsLoading(false);
  }, []);

  const handleLogout = () => {
    SecureStorage.clear();
    navigate('/login');
  };

  const isActive = (path: string) => location.pathname === path;

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      {/* Header */}
      <nav className="bg-neutral-950 border-b border-neutral-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link to="/dashboard" className="flex items-center">
                <span className="text-2xl md:text-3xl font-bold text-white tracking-wide">
                  PULLEDOUT.LOL
                </span>
              </Link>
              
              <div className="hidden md:flex space-x-1">
                <Link
                  to="/dashboard"
                  className={`px-4 py-2 rounded-lg transition ${
                    isActive('/dashboard')
                      ? 'bg-white/10 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  Dashboard
                </Link>
                <Link
                  to="/scanner"
                  className={`px-4 py-2 rounded-lg transition ${
                    isActive('/scanner')
                      ? 'bg-white/10 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  New Scan
                </Link>
                <Link
                  to="/settings"
                  className={`px-4 py-2 rounded-lg transition ${
                    isActive('/settings')
                      ? 'bg-white/10 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  Settings
                </Link>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <span className="text-gray-400 text-sm">
                {username}
              </span>
              <button
                onClick={handleLogout}
                className="px-4 py-2 bg-white text-black rounded-lg hover:bg-gray-200 transition"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-neutral-800 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <p className="text-center text-gray-500 text-xs sm:text-sm">
            &copy; 2026 PULLEDOUT.LOL - Made by Frosty
          </p>
        </div>
      </footer>
    </div>
  );
}
