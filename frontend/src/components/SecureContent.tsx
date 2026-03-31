import { ReactNode, useEffect } from 'react';

interface SecureContentProps {
  children: ReactNode;
  level?: 'standard' | 'high' | 'maximum';
}

/**
 * SecureContent - Wrapper for sensitive content with anti-screenshot protection
 * 
 * Levels:
 * - standard: Basic protection (disable right-click, text selection)
 * - high: + Prevent copy/paste, print
 * - maximum: + Additional DRM-like protections
 */
export default function SecureContent({ children, level = 'high' }: SecureContentProps) {
  useEffect(() => {
    // Prevent right-click context menu
    const handleContextMenu = (e: MouseEvent) => {
      e.preventDefault();
      return false;
    };

    // Prevent text selection on drag
    const handleSelectStart = (e: Event) => {
      if (level === 'high' || level === 'maximum') {
        e.preventDefault();
        return false;
      }
    };

    // Prevent copy
    const handleCopy = (e: ClipboardEvent) => {
      if (level === 'high' || level === 'maximum') {
        e.preventDefault();
        e.clipboardData?.setData('text/plain', '🔒 This content is protected and cannot be copied');
        return false;
      }
    };

    // Prevent cut
    const handleCut = (e: ClipboardEvent) => {
      if (level === 'high' || level === 'maximum') {
        e.preventDefault();
        return false;
      }
    };

    // Prevent paste (to avoid screen reader extraction)
    const handlePaste = (e: ClipboardEvent) => {
      if (level === 'maximum') {
        e.preventDefault();
        return false;
      }
    };

    // Prevent print
    const handleBeforePrint = (e: Event) => {
      if (level === 'high' || level === 'maximum') {
        e.preventDefault();
        alert('🔒 Printing is disabled for security reasons. Download the official report instead.');
        return false;
      }
    };

    // Prevent Ctrl+P, Cmd+P
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
        if (level === 'high' || level === 'maximum') {
          e.preventDefault();
          alert('🔒 Printing is disabled for security reasons. Download the official report instead.');
          return false;
        }
      }
      
      // Prevent Ctrl+S, Cmd+S (Save page)
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        if (level === 'maximum') {
          e.preventDefault();
          return false;
        }
      }

      // Prevent Ctrl+U, Cmd+U (View source)
      if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
        if (level === 'maximum') {
          e.preventDefault();
          return false;
        }
      }

      // Prevent F12 (DevTools)
      if (e.key === 'F12') {
        if (level === 'maximum') {
          e.preventDefault();
          return false;
        }
      }
    };

    // Add event listeners
    document.addEventListener('contextmenu', handleContextMenu);
    document.addEventListener('selectstart', handleSelectStart);
    document.addEventListener('copy', handleCopy);
    document.addEventListener('cut', handleCut);
    document.addEventListener('paste', handlePaste);
    document.addEventListener('keydown', handleKeyDown);
    window.addEventListener('beforeprint', handleBeforePrint);

    return () => {
      document.removeEventListener('contextmenu', handleContextMenu);
      document.removeEventListener('selectstart', handleSelectStart);
      document.removeEventListener('copy', handleCopy);
      document.removeEventListener('cut', handleCut);
      document.removeEventListener('paste', handlePaste);
      document.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('beforeprint', handleBeforePrint);
    };
  }, [level]);

  return (
    <div className={`secure-content secure-content-${level}`}>
      {children}
    </div>
  );
}
