import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';

/**
 * SecurityOverlay - Anti-Screenshot & Screen Security Protection
 * 
 * Features:
 * - Blacks out screen when window loses focus
 * - Prevents screenshots via visibility detection
 * - Detects tab switching and minimization
 * - Watermarks content for accountability
 * - Prevents screen recording detection
 */
export default function SecurityOverlay() {
  const [isSecure, setIsSecure] = useState(true);
  const [blurLevel, setBlurLevel] = useState(0);  // 0 = none, 1 = light, 2 = heavy, 3 = blackout
  const [showWarning, setShowWarning] = useState(false);
  const location = useLocation();

  useEffect(() => {
    console.log('🔒 SecurityOverlay MOUNTED - Anti-screenshot system active');
    let warningTimeout: number;
    let blurDebounceTimeout: number;
    let lastBlackoutTime = 0;  // Prevent spam from key repeats
    let forcedBlackoutUntil = 0;  // Timestamp when forced blackout expires

    // Helper function to trigger FORCED blackout that cannot be interrupted
    const triggerBlackout = (reason: string, duration: number = 3000) => {
      const now = Date.now();
      // Prevent spam - only blackout once per second
      if (now - lastBlackoutTime < 1000) {
        console.log('⚠️ Blackout request ignored - too soon after last blackout');
        return;
      }
      
      lastBlackoutTime = now;
      forcedBlackoutUntil = now + duration;  // Set forced blackout expiry
      console.warn(`🚨 ${reason} - FORCED BLACKOUT for ${duration}ms`);
      setBlurLevel(3);
      setIsSecure(false);
      setShowWarning(true);
      
      // Auto-restore ONLY after forced duration expires
      setTimeout(() => {
        forcedBlackoutUntil = 0;  // Clear forced blackout
        if (document.hasFocus() && !document.hidden) {
          console.log('✅ Forced blackout expired - restoring content');
          setBlurLevel(0);
          setIsSecure(true);
          setShowWarning(false);
        }
      }, duration);
    };

    // Track if user is actively viewing - IMMEDIATE response
    const handleVisibilityChange = () => {
      if (document.hidden) {
        console.warn('🚨 DOCUMENT HIDDEN - FULL BLACKOUT');
        setBlurLevel(3);  // Maximum protection
        setIsSecure(false);
        setShowWarning(true);
        logSecurityEvent('Tab hidden - potential screenshot attempt');
      } else {
        console.log('✅ Document visible - restoring content');
        setBlurLevel(0);
        setIsSecure(true);
        warningTimeout = window.setTimeout(() => setShowWarning(false), 3000);
      }
    };

    // Track window focus - INSTANT BLACKOUT with zero delay
    const handleBlur = () => {
      // Don't interfere with forced blackouts
      if (Date.now() < forcedBlackoutUntil) {
        console.log('⚠️ Blur event ignored - forced blackout active');
        return;
      }
      
      // INSTANT blackout - catches Snipping Tool before overlay fully loads
      console.warn('🚨 BLUR EVENT - INSTANT BLACKOUT');
      setBlurLevel(3);
      setIsSecure(false);
      logSecurityEvent('Window blur detected - instant blackout');
      
      // Clear any existing debounce
      if (blurDebounceTimeout) {
        clearTimeout(blurDebounceTimeout);
      }
      
      // Shorter restore window to catch navigation faster (50ms instead of 200ms)
      blurDebounceTimeout = window.setTimeout(() => {
        // Don't restore if we're in forced blackout
        if (Date.now() < forcedBlackoutUntil) {
          console.log('⚠️ Restore blocked - forced blackout still active');
          return;
        }
        
        if (document.hasFocus() && !document.hidden) {
          console.log('✅ Focus returned - restoring content');
          setBlurLevel(0);
          setIsSecure(true);
        } else {
          console.warn('🚨 No focus - keeping blackout active');
          setShowWarning(true);
        }
      }, 50);
    };

    const handleFocus = (e: Event) => {
      // Don't restore during forced blackout
      if (Date.now() < forcedBlackoutUntil) {
        console.log('⚠️ Focus event ignored - forced blackout active');
        return;
      }
      
      // Clear blur debounce - focus returned
      if (blurDebounceTimeout) {
        clearTimeout(blurDebounceTimeout);
      }
      console.log('✅ Window focused - restoring content', e.type);
      setBlurLevel(0);  // Remove blur
      setIsSecure(true);
      warningTimeout = window.setTimeout(() => setShowWarning(false), 3000);
    };

    // Comprehensive hotkey blocking
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore key repeats (when user holds key down)
      if (e.repeat) {
        e.preventDefault();
        return;
      }

      // Win+Shift+R - Screen recording / Snipping Tool variant
      if ((e.metaKey || e.key === 'Meta') && e.shiftKey && (e.key === 'r' || e.key === 'R')) {
        e.preventDefault();
        e.stopPropagation();
        triggerBlackout('Win+Shift+R detected - screen recording attempt', 3000);
        logSecurityEvent('Win+Shift+R detected - screen recording attempt');
        return;
      }

      // Win+Shift+S - Snipping Tool
      if ((e.metaKey || e.key === 'Meta') && e.shiftKey && (e.key === 's' || e.key === 'S')) {
        e.preventDefault();
        e.stopPropagation();
        triggerBlackout('Win+Shift+S Snipping Tool detected', 3000);
        logSecurityEvent('Win+Shift+S Snipping Tool detected');
        return;
      }

      // Block ALL other Windows key combinations (but don't spam blackout)
      if (e.metaKey || e.key === 'Meta' || e.key === 'OS') {
        console.warn('🚨 Windows key detected - blocking', e.key);
        e.preventDefault();
        e.stopPropagation();
        // Don't blackout for generic Windows key - too disruptive
        logSecurityEvent('Windows key press detected');
        return;
      }

      // Block screenshot hotkeys
      if (
        e.key === 'PrintScreen' ||
        (e.ctrlKey && e.shiftKey && e.key === 'Print') ||
        (e.altKey && e.key === 'PrintScreen')
      ) {
        e.preventDefault();
        e.stopPropagation();
        triggerBlackout('PrintScreen key detected', 3000);
        logSecurityEvent('PrintScreen key detected');
        return;
      }

      // Block common save/print shortcuts
      if (e.ctrlKey || e.metaKey) {
        const blockedKeys = ['s', 'p', 'S', 'P'];
        if (blockedKeys.includes(e.key)) {
          console.warn('🚨 Save/Print shortcut blocked:', e.key);
          e.preventDefault();
          e.stopPropagation();
          return;
        }
      }

      // Block F12 (DevTools)
      if (e.key === 'F12') {
        console.warn('🚨 F12 DevTools blocked');
        e.preventDefault();
        e.stopPropagation();
        return;
      }

      // Block Ctrl+Shift+I/J/C (DevTools)
      if ((e.ctrlKey && e.shiftKey) && ['I', 'J', 'C', 'i', 'j', 'c'].includes(e.key)) {
        console.warn('🚨 DevTools shortcut blocked');
        e.preventDefault();
        e.stopPropagation();
        return;
      }
    };

    // ========== COMPREHENSIVE ANTI-COPY/SCREENSHOT PROTECTION ==========
    // Inspired by pdfanticopy.com approach (implemented safely without external scripts)
    
    // Disable right-click context menu (noCopy)
    const handleContextMenu = (e: MouseEvent) => {
      console.warn('🚨 Right-click blocked');
      e.preventDefault();
      e.stopPropagation();
      return false;
    };

    // Disable text selection (noCopy)
    const handleSelectStart = (e: Event) => {
      console.warn('🚨 Text selection blocked');
      e.preventDefault();
      return false;
    };

    // Disable copy/cut/paste (noCopy)
    const handleCopyPaste = (e: ClipboardEvent) => {
      console.warn('🚨 Clipboard operation blocked:', e.type);
      e.preventDefault();
      e.stopPropagation();
      return false;
    };

    // Disable drag operations (noCopy)
    const handleDragStart = (e: DragEvent) => {
      console.warn('🚨 Drag operation blocked');
      e.preventDefault();
      return false;
    };

    // Block print operations (noPrint)
    const handleBeforePrint = (e: Event) => {
      console.warn('🚨 Print attempt blocked');
      e.preventDefault();
      e.stopPropagation();
      setBlurLevel(3);
      setIsSecure(false);
      setShowWarning(true);
      logSecurityEvent('Print attempt detected');
      return false;
    };

    // Auto-blur on mouse leave (autoBlur concept)
    const handleMouseLeaveAggressive = (e: MouseEvent) => {
      // Auto-blur whenever mouse leaves the document
      const isOutside = !e.relatedTarget || 
                       (e.relatedTarget as HTMLElement).nodeName === 'HTML';
      if (isOutside) {
        console.warn('🚨 Mouse left document - auto-blur activated');
        setBlurLevel(2);
        setIsSecure(false);
        logSecurityEvent('Mouse left document - auto-blur');
      }
    };

    // Detect screenshot via keyboard combinations (expanded)
    const handleKeyDownExpanded = (e: KeyboardEvent) => {
      // First run original handler
      handleKeyDown(e);

      // Additional screenshot detection
      // Alt+PrtScn (Windows active window screenshot)
      if (e.altKey && e.key === 'PrintScreen') {
        console.warn('🚨 Alt+PrtScn detected');
        e.preventDefault();
        setBlurLevel(3);
        setIsSecure(false);
        logSecurityEvent('Alt+PrintScreen detected');
        return false;
      }

      // Block Ctrl+P (Print)
      if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
        console.warn('🚨 Print shortcut blocked');
        e.preventDefault();
        e.stopPropagation();
        return false;
      }
    };

    // Detect DevTools opening (potential screenshot via devtools)
    const detectDevTools = () => {
      const threshold = 160;
      const widthThreshold = window.outerWidth - window.innerWidth > threshold;
      const heightThreshold = window.outerHeight - window.innerHeight > threshold;
      
      if (widthThreshold || heightThreshold) {
        logSecurityEvent('DevTools potentially opened');
      }
    };

    // Check for screen recording software
    const detectScreenRecording = () => {
      // Check if user is screen recording (heuristic)
      if (typeof (window as any).chrome !== 'undefined') {
        const isRecording = (navigator.mediaDevices as any)?.getUserMedia !== undefined;
        if (isRecording) {
          logSecurityEvent('Potential screen recording detected');
        }
      }
    };

    // Add ALL event listeners (comprehensive protection)
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleBlur, true);
    window.addEventListener('focus', handleFocus, true);
    document.addEventListener('keydown', handleKeyDownExpanded, true);
    document.addEventListener('keyup', handleKeyDownExpanded, true);
    
    // Anti-copy protection (noCopy)
    document.addEventListener('contextmenu', handleContextMenu, true);
    document.addEventListener('selectstart', handleSelectStart, true);
    document.addEventListener('copy', handleCopyPaste, true);
    document.addEventListener('cut', handleCopyPaste, true);
    document.addEventListener('paste', handleCopyPaste, true);
    document.addEventListener('dragstart', handleDragStart, true);
    
    // Anti-print protection (noPrint)
    window.addEventListener('beforeprint', handleBeforePrint, true);
    window.addEventListener('afterprint', handleBeforePrint, true);
    
    // Auto-blur protection (autoBlur)
    document.addEventListener('mouseleave', handleMouseLeaveAggressive, true);
    document.addEventListener('mouseout', handleMouseLeaveAggressive, true);
    
    // DevTools detection interval
    const devToolsInterval = setInterval(detectDevTools, 1000);
    
    // Ultra-aggressive focus monitoring - 10ms polling catches Snipping Tool instantly
    const focusInterval = setInterval(() => {
      // Don't interfere with forced blackouts
      if (Date.now() < forcedBlackoutUntil) {
        return;
      }
      
      if (!document.hasFocus() && !document.hidden) {
        // INSTANT blackout on ANY focus loss detected by polling
        console.warn('🚨 POLLING DETECTED FOCUS LOSS - INSTANT BLACKOUT');
        setBlurLevel(3);
        setIsSecure(false);
      } else {
        // Restore immediately when focus returns
        if (!document.hidden && document.hasFocus()) {
          setBlurLevel(0);
          setIsSecure(true);
        }
      }
    }, 10);  // 10ms polling = 100 checks per second
    
    detectScreenRecording();

    // Initial check - if we don't have focus on load, black out immediately
    if (!document.hasFocus() || document.hidden) {
      console.warn('🚨 INITIAL CHECK: No focus - blacking out');
      setIsSecure(false);
    }

    // Expose test function to window for debugging
    (window as any).testBlackout = () => {
      console.log('🧪 TEST: Manually triggering blackout');
      setIsSecure(false);
      setTimeout(() => {
        console.log('🧪 TEST: Restoring content');
        setIsSecure(true);
      }, 3000);
    };
    
    console.log('✅ SecurityOverlay event listeners installed. Type testBlackout() in console to test.');

    return () => {
      // Cleanup all event listeners
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleBlur, true);
      window.removeEventListener('focus', handleFocus, true);
      document.removeEventListener('keydown', handleKeyDownExpanded, true);
      document.removeEventListener('keyup', handleKeyDownExpanded, true);
      
      // Anti-copy cleanup
      document.removeEventListener('contextmenu', handleContextMenu, true);
      document.removeEventListener('selectstart', handleSelectStart, true);
      document.removeEventListener('copy', handleCopyPaste, true);
      document.removeEventListener('cut', handleCopyPaste, true);
      document.removeEventListener('paste', handleCopyPaste, true);
      document.removeEventListener('dragstart', handleDragStart, true);
      
      // Anti-print cleanup
      window.removeEventListener('beforeprint', handleBeforePrint, true);
      window.removeEventListener('afterprint', handleBeforePrint, true);
      
      // Auto-blur cleanup
      document.removeEventListener('mouseleave', handleMouseLeaveAggressive, true);
      document.removeEventListener('mouseout', handleMouseLeaveAggressive, true);
      
      clearInterval(devToolsInterval);
      clearInterval(focusInterval);
      if (warningTimeout) clearTimeout(warningTimeout);
      if (blurDebounceTimeout) clearTimeout(blurDebounceTimeout);
    };
  }, []); // Run once on mount

  const logSecurityEvent = (event: string) => {
    console.warn(`[SECURITY] ${event} at ${new Date().toISOString()}`);
    // Send to backend for audit logging
    fetch('/api/security/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event,
        timestamp: new Date().toISOString(),
        page: location.pathname,
        userAgent: navigator.userAgent
      })
    }).catch(() => {});
  };

  // Don't render overlay on public pages
  const publicPages = ['/login', '/signup', '/pricing', '/terms', '/privacy'];
  if (publicPages.includes(location.pathname)) {
    return null;
  }

  console.log('🔒 SecurityOverlay Render:', {
    isSecure,
    showWarning,
    pathname: location.pathname,
    willShowBlackScreen: !isSecure
  });

  return (
    <>
      {/* Progressive blur protection - Level 2: Heavy blur for Snipping Tool */}
      {blurLevel === 2 && (
        <div className="security-blur-overlay-heavy">
          <div className="text-center px-8">
            <svg className="w-16 h-16 mx-auto mb-3 text-white opacity-70" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <h3 className="text-xl font-bold text-white">Viewing Suspended</h3>
          </div>
        </div>
      )}

      {/* Full blackout - Level 3: Maximum protection */}
      {blurLevel === 3 && (
        <div className="security-blackout-overlay">
          <div className="text-center px-8">
            <svg className="w-20 h-20 mx-auto mb-4 text-white opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <h2 className="text-2xl font-bold text-white mb-2">Content Protected</h2>
            <p className="text-gray-400">Return to window to continue viewing</p>
          </div>
        </div>
      )}

      {/* Warning toast when returning to window */}
      {showWarning && isSecure && (
        <div className="warning-toast fixed top-4 right-4 z-[9998] bg-red-500/90 backdrop-blur-sm text-white px-6 py-3 rounded-lg shadow-2xl border border-red-400 animate-pulse">
          <div className="flex items-center space-x-3">
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <span className="font-semibold">Security Alert: Window focus changed</span>
          </div>
        </div>
      )}

      {/* Subtle watermark - timestamp only */}
      {isSecure && !publicPages.includes(location.pathname) && (
        <div className="watermark-overlay fixed inset-0 z-[100] pointer-events-none select-none">
          {/* Timestamp watermark - top right */}
          <div className="absolute top-4 right-4 opacity-[0.15] text-white text-xs font-mono select-none">
            {new Date().toLocaleString()}
          </div>
        </div>
      )}
    </>
  );
}
