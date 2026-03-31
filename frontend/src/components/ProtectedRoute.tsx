import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { SecureStorage } from '../utils/security';
import { useEffect } from 'react';

function getCookie(name: string): string | null {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null;
  }
  return null;
}

export default function ProtectedRoute() {
  const location = useLocation();
  
  useEffect(() => {
    // Check if we have cookies from OAuth callback and store them in sessionStorage
    const sessionTokenCookie = getCookie('sessionToken');
    const usernameCookie = getCookie('username');
    const avatarCookie = getCookie('discordAvatar');
    
    if (sessionTokenCookie && !SecureStorage.getItem('session_token')) {
      // Store cookies in sessionStorage for API calls
      SecureStorage.setItem('session_token', sessionTokenCookie);
      if (usernameCookie) SecureStorage.setItem('username', usernameCookie);
      if (avatarCookie) SecureStorage.setItem('discord_avatar', avatarCookie);
    }
  }, [location]);

  // Check both sessionStorage and cookies for session token
  const sessionToken = SecureStorage.getItem('session_token') || getCookie('sessionToken');

  if (!sessionToken) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
