// API client for Discord OAuth-based backend

import axios, { AxiosInstance } from 'axios';
import { SecureStorage } from './security';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// CSRF token storage
let csrfToken: string | null = null;

// Fetch CSRF token
const fetchCsrfToken = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/api/csrf-token`, {
      withCredentials: true
    });
    csrfToken = response.data.csrf_token;
    return csrfToken;
  } catch (error) {
    console.error('Failed to fetch CSRF token:', error);
    return null;
  }
};

// Initialize CSRF token on module load
fetchCsrfToken();

// Request interceptor
api.interceptors.request.use(
  async (config: any) => {
    // Try to get token from sessionStorage or cookies
    let sessionToken = SecureStorage.getItem('session_token');
    
    // Fallback to cookie if not in sessionStorage
    if (!sessionToken) {
      const cookies = document.cookie.split('; ');
      const sessionCookie = cookies.find(c => c.startsWith('sessionToken='));
      if (sessionCookie) {
        sessionToken = sessionCookie.split('=')[1];
        // Store in sessionStorage for future requests
        SecureStorage.setItem('session_token', sessionToken);
      }
    }
    
    if (sessionToken) {
      config.headers['Authorization'] = `Bearer ${sessionToken}`;
    }

    // Add CSRF token for state-changing requests
    if (['post', 'put', 'delete', 'patch'].includes(config.method?.toLowerCase() || '')) {
      if (!csrfToken) {
        await fetchCsrfToken();
      }
      if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
    }

    const currentFingerprint = (window as any).__fingerprint__;
    if (currentFingerprint) {
      config.headers['X-Fingerprint'] = currentFingerprint;
    }

    return config;
  },
  (error: any) => Promise.reject(error)
);

// Response interceptor
api.interceptors.response.use(
  (response: any) => response,
  async (error: any) => {
    // If CSRF token is invalid, refresh it and retry
    if (error.response?.status === 403 && error.response?.data?.error?.includes('CSRF')) {
      await fetchCsrfToken();
      // Retry the request
      const config = error.config;
      if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
      return api.request(config);
    }
    
    if (error.response?.status === 401) {
      SecureStorage.clear();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Scan API endpoints
export const startScan = async (url: string, maxPages: number = 100) => {
  const response = await api.post('/api/scan', {
    target_url: url,
    max_pages: maxPages,
  });
  return response.data;
};

export const getScanStatus = async (scanId: string) => {
  const response = await api.get(`/api/scan/${scanId}/status`);
  return response.data;
};

export const getScanResults = async (scanId: string) => {
  const response = await api.get(`/api/scan/${scanId}/results`);
  return response.data;
};

export const getScans = async () => {
  const response = await api.get('/api/scans');
  return response.data;
};

export const deleteScan = async (scanId: string) => {
  const response = await api.delete(`/api/scans/${scanId}`);
  return response.data;
};

export const exportScan = async (scanId: string, format: string = 'html') => {
  const response = await api.get(`/api/scans/${scanId}/export`, {
    params: { format },
    responseType: 'blob',
  });
  return response.data;
};

// User API endpoints
export const getProfile = async () => {
  const response = await api.get('/api/auth/me');
  return response.data;
};

// Health check
export const healthCheck = async () => {
  const response = await api.get('/api/health');
  return response.data;
};

// Debug and monitoring endpoints
export const getDebugLogs = async (params?: {
  limit?: number;
  level?: string;
  category?: string;
}) => {
  const response = await api.get('/api/debug/logs', { params });
  return response.data;
};

export const getDebugStats = async () => {
  const response = await api.get('/api/debug/stats');
  return response.data;
};

// ==============================================================================
// SPECIALIZED SECURITY TOOLS API
// ==============================================================================

// Database Intrusion Testing
export const startDatabaseIntrusion = async (target: string, ports?: string) => {
  const response = await api.post('/api/tools/database-intrusion', {
    target,
    ports: ports || '27017,3306,5432,6379,9200,5984'
  });
  return response.data;
};

// Data Extraction
export const startDataExtractor = async (target: string) => {
  const response = await api.post('/api/tools/data-extractor', {
    target
  });
  return response.data;
};

// Cloud Storage Detection
export const startCloudStorage = async (target: string) => {
  const response = await api.post('/api/tools/cloud-storage', {
    target
  });
  return response.data;
};

// Exposed Files Scanner
export const startExposedFiles = async (target: string) => {
  const response = await api.post('/api/tools/exposed-files', {
    target
  });
  return response.data;
};

// API Security Tester
export const startAPITester = async (target: string) => {
  const response = await api.post('/api/tools/api-tester', {
    target
  });
  return response.data;
};

// Network Reconnaissance
export const startNetworkRecon = async (target: string) => {
  const response = await api.post('/api/tools/network-recon', {
    target
  });
  return response.data;
};

// Penetration Testing
export const startPenetrationTest = async (target: string, categories?: string[]) => {
  const response = await api.post('/api/tools/penetration-test', {
    target,
    categories: categories || ['all']
  });
  return response.data;
};

// Get tool scan results (unified endpoint for all tools)
export const getToolResults = async (scanId: string) => {
  const response = await api.get(`/api/tools/${scanId}/results`);
  return response.data;
};

// Get tool scan status
export const getToolStatus = async (scanId: string) => {
  const response = await api.get(`/api/tools/${scanId}/status`);
  return response.data;
};

// ==============================================================================
// PLATFORM CAPABILITIES API
// ==============================================================================

// Get real-time platform capability statistics
export const getPlatformCapabilities = async () => {
  const response = await api.get('/api/platform/capabilities');
  return response.data;
};

// ==============================================================================
// END SPECIALIZED TOOLS API
// ==============================================================================

export default api;
