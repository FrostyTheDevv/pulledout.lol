import { useState, useEffect } from 'react';
import { getProfile } from '../utils/api';
import toast from 'react-hot-toast';

interface UserProfile {
  username: string;
  discord_username: string;
  discord_avatar: string;
  created_at: string;
  total_scans: number;
}

export default function Settings() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadProfile();
  }, []);

  const loadProfile = async () => {
    try {
      const data = await getProfile();
      setProfile(data);
    } catch (error: any) {
      toast.error('Failed to load profile');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="animate-pulse text-gray-400">Loading settings...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
        <h1 className="text-3xl font-bold text-white">Settings</h1>

        {/* Profile Card */}
        <div className="glass-card p-6">
          <h2 className="text-xl font-semibold text-white mb-6">Profile</h2>
          
          <div className="space-y-4">
            {profile?.discord_avatar && (
              <div className="flex items-center space-x-4">
                <img
                  src={profile.discord_avatar}
                  alt="Avatar"
                  className="w-16 h-16 rounded-full"
                />
                <div>
                  <div className="text-white font-semibold">
                    {profile.discord_username || profile.username}
                  </div>
                  <div className="text-sm text-gray-400">Discord Account</div>
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4 mt-6">
              <div className="bg-neutral-900 p-4 rounded-lg">
                <div className="text-sm text-gray-400">Account Created</div>
                <div className="text-white mt-1">
                  {profile?.created_at ? new Date(profile.created_at).toLocaleDateString() : 'N/A'}
                </div>
              </div>
              <div className="bg-neutral-900 p-4 rounded-lg">
                <div className="text-sm text-gray-400">Total Scans</div>
                <div className="text-white mt-1">{profile?.total_scans || 0}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="glass-card p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Security</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-neutral-900 rounded-lg">
              <div>
                <div className="text-white font-medium">Two-Factor Authentication</div>
                <div className="text-sm text-gray-400">Managed through Discord</div>
              </div>
              <a
                href="https://discord.com/settings/account"
                target="_blank"
                rel="noopener noreferrer"
                className="text-white hover:text-gray-300 text-sm"
              >
                Configure →
              </a>
            </div>

            <div className="flex items-center justify-between p-4 bg-neutral-900 rounded-lg">
              <div>
                <div className="text-white font-medium">Active Sessions</div>
                <div className="text-sm text-gray-400">View and manage active sessions</div>
              </div>
              <button className="text-primary-400 hover:text-primary-300 text-sm">
                Manage →
              </button>
            </div>
          </div>
        </div>

        {/* Preferences */}
        <div className="glass-card p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Preferences</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-white font-medium">Dark Mode</div>
                <div className="text-sm text-gray-400">Always enabled for security</div>
              </div>
              <div className="text-green-400 text-sm">On</div>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <div className="text-white font-medium">Desktop Notifications</div>
                <div className="text-sm text-gray-400">Get notified when scans complete</div>
              </div>
              <button className="bg-dark-600 px-4 py-2 rounded text-sm text-white hover:bg-dark-500">
                Enable
              </button>
            </div>
          </div>
        </div>

        {/* Danger Zone */}
        <div className="glass-card p-6 border border-red-500/30">
          <h2 className="text-xl font-semibold text-red-400 mb-4">Danger Zone</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-white font-medium">Delete Account</div>
                <div className="text-sm text-gray-400">Permanently delete your account and all scans</div>
              </div>
              <button
                className="bg-red-500/20 hover:bg-red-500/30 text-red-400 px-4 py-2 rounded text-sm transition"
                onClick={() => toast.error('Contact support to delete your account')}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>
  );
}
