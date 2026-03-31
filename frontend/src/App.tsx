import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useEffect } from 'react';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import Results from './pages/Results';
import Login from './pages/Login';
import Settings from './pages/Settings';
import Pricing from './pages/Pricing';
import Signup from './pages/Signup';
import Terms from './pages/Terms';
import Privacy from './pages/Privacy';
import NotFound from './pages/NotFound';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import SecurityOverlay from './components/SecurityOverlay';
import DatabaseIntrusion from './pages/DatabaseIntrusion';
import DataExtractor from './pages/DataExtractor';
import CloudStorage from './pages/CloudStorage';
import ExposedFiles from './pages/ExposedFiles';
import APITester from './pages/APITester';
import NetworkRecon from './pages/NetworkRecon';
import PenetrationTesting from './pages/ActiveExploit';
import { initSecurity } from './utils/security';

function App() {
  useEffect(() => {
    // Initialize security features
    initSecurity();
  }, []);
  
  return (
    <>
      <BrowserRouter>
        {/* Anti-Screenshot Security Overlay - must be inside BrowserRouter to use useLocation */}
        <SecurityOverlay />
        
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/pay" element={<Pricing />} />
          <Route path="/pricing" element={<Pricing />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/terms" element={<Terms />} />
          <Route path="/privacy" element={<Privacy />} />
          
          {/* Protected routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<Layout />}>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scanner" element={<Scanner />} />
              <Route path="/results/:scanId" element={<Results />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/tools/database" element={<DatabaseIntrusion />} />
              <Route path="/tools/data-extractor" element={<DataExtractor />} />
              <Route path="/tools/cloud" element={<CloudStorage />} />
              <Route path="/tools/files" element={<ExposedFiles />} />
              <Route path="/tools/api" element={<APITester />} />
              <Route path="/tools/network" element={<NetworkRecon />} />
              <Route path="/tools/exploit" element={<PenetrationTesting />} />
            </Route>
          </Route>
          
          {/* 404 */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
      
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#000000',
            color: '#ffffff',
            border: '1px solid #333333',
          },
          success: {
            iconTheme: {
              primary: '#ffffff',
              secondary: '#000000',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#f3f4f6',
            },
          },
        }}
      />
    </>
  );
}

export default App;
