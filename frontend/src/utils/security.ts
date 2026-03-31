import Fingerprint2 from 'fingerprintjs2';
import CryptoJS from 'crypto-js';

const ENCRYPTION_KEY = import.meta.env.VITE_ENCRYPTION_KEY || 'sawsap-ultra-secure-2024';

/**
 * Initialize all security measures
 */
export function initSecurity() {
  // Anti-debugging
  detectDebugger();
  
  // Fingerprinting
  generateFingerprint();
  
  // DOM protection
  protectDOM();
  
  // Network monitoring
  monitorNetworkRequests();
  
  // Performance monitoring (detect automation)
  detectAutomation();
}

/**
 * Detect debugger and DevTools
 */
function detectDebugger() {
  // Check for debugger
  setInterval(() => {
    const start = performance.now();
    debugger; // This will pause if DevTools is open
    const end = performance.now();
    
    if (end - start > 100) {
      console.warn('Debugger detected - monitoring enabled');
      // Could send alert to backend
      window.dispatchEvent(new CustomEvent('security:debugger-detected'));
    }
  }, 1000);
  
  // Detect console
  // @ts-expect-error - devtools is used in property getter and interval
  let devtools = false;
  const element = new Image();
  Object.defineProperty(element, 'id', {
    get: function() {
      devtools = true;
      console.log('DevTools opened - security logging enabled');
      window.dispatchEvent(new CustomEvent('security:devtools-opened'));
      throw new Error('DevTools detected');
    }
  });
  
  setInterval(() => {
    devtools = false;
    console.log(element);
    console.clear();
  }, 1000);
}

/**
 * Generate unique browser fingerprint
 */
export async function generateFingerprint(): Promise<string> {
  return new Promise((resolve) => {
    Fingerprint2.get((components) => {
      const values = components.map(component => component.value);
      const fingerprint = Fingerprint2.x64hash128(values.join(''), 31);
      
      // Store fingerprint
      sessionStorage.setItem('fp', encrypt(fingerprint));
      
      resolve(fingerprint);
    });
  });
}

/**
 * Get stored fingerprint
 */
export function getFingerprint(): string | null {
  const encrypted = sessionStorage.getItem('fp');
  return encrypted ? decrypt(encrypted) : null;
}

/**
 * Encrypt data
 */
export function encrypt(data: string): string {
  return CryptoJS.AES.encrypt(data, ENCRYPTION_KEY).toString();
}

/**
 * Decrypt data
 */
export function decrypt(encryptedData: string): string {
  const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
  return bytes.toString(CryptoJS.enc.Utf8);
}

/**
 * Protect DOM from inspection
 */
function protectDOM() {
  // Disable text selection on sensitive elements
  document.addEventListener('selectstart', (e) => {
    const target = e.target as HTMLElement;
    if (target.classList.contains('protected')) {
      e.preventDefault();
    }
  });
  
  // Disable copy on protected elements
  document.addEventListener('copy', (e) => {
    const selection = window.getSelection();
    if (selection) {
      const range = selection.getRangeAt(0);
      const container = range.commonAncestorContainer;
      const element = container.nodeType === 1 ? container as HTMLElement : container.parentElement;
      
      if (element && element.classList && element.classList.contains('protected')) {
        e.preventDefault();
        console.log('Copy prevented on protected content');
      }
    }
  });
  
  // Detect screenshot attempts (some browsers)
  document.addEventListener('keyup', (e) => {
    if (e.key === 'PrintScreen') {
      console.log('Screenshot attempt detected');
      window.dispatchEvent(new CustomEvent('security:screenshot-attempt'));
    }
  });
}

/**
 * Monitor network requests for suspicious activity
 */
function monitorNetworkRequests() {
  // Monitor fetch
  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    const url = args[0] as string;
    
    // Log all API calls
    console.log('API Request:', url);
    
    // Add fingerprint to requests
    if (typeof args[1] === 'object') {
      args[1].headers = {
        ...args[1].headers,
        'X-Fingerprint': getFingerprint() || '',
        'X-Client-Time': Date.now().toString(),
      };
    }
    
    return originalFetch.apply(this, args);
  };
  
  // Monitor XMLHttpRequest
  const originalOpen = XMLHttpRequest.prototype.open;
  // @ts-expect-error - originalSend captured for future use
  const originalSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method: string, url: string | URL, async: boolean = true) {
    this.addEventListener('load', function() {
      console.log('XHR Request:', method, url, this.status);
    });
    return originalOpen.call(this, method, url, async);
  };
}

/**
 * Detect automation (bots, headless browsers)
 */
function detectAutomation() {
  const tests: { [key: string]: boolean } = {};
  
  // Check for webdriver
  tests.webdriver = navigator.webdriver || false;
  
  // Check for headless
  tests.headless = !navigator.plugins.length;
  
  // Check for automation
  tests.automation = window.navigator.webdriver || 
                     (window as any).document.documentElement.getAttribute('webdriver') ||
                     (window as any).callPhantom ||
                     (window as any)._phantom;
  
  // Check user agent
  tests.suspiciousUA = /headless|phantom|selenium|puppeteer|playwright/i.test(navigator.userAgent);
  
  // Check permissions
  tests.permissionsAPI = !navigator.permissions;
  
  // Check chrome detection
  tests.chrome = !(window as any).chrome && /Google Inc/.test(navigator.vendor);
  
  const suspiciousCount = Object.values(tests).filter(Boolean).length;
  
  if (suspiciousCount >= 2) {
    console.warn('Automation detected:', tests);
    window.dispatchEvent(new CustomEvent('security:automation-detected', {
      detail: { tests, score: suspiciousCount }
    }));
  }
  
  return tests;
}

/**
 * Rate limiting helper
 */
export class RateLimiter {
  private attempts: Map<string, number[]> = new Map();
  
  constructor(
    private maxAttempts: number = 5,
    private windowMs: number = 60000
  ) {}
  
  check(key: string): boolean {
    const now = Date.now();
    const attempts = this.attempts.get(key) || [];
    
    // Remove old attempts outside window
    const validAttempts = attempts.filter(time => now - time < this.windowMs);
    
    if (validAttempts.length >= this.maxAttempts) {
      console.warn(`Rate limit exceeded for: ${key}`);
      return false;
    }
    
    validAttempts.push(now);
    this.attempts.set(key, validAttempts);
    return true;
  }
  
  reset(key: string) {
    this.attempts.delete(key);
  }
}

/**
 * Secure token storage
 */
export class SecureStorage {
  private static encrypt(value: string): string {
    return encrypt(value);
  }
  
  private static decrypt(value: string): string {
    return decrypt(value);
  }
  
  static setItem(key: string, value: string) {
    try {
      const encrypted = this.encrypt(value);
      sessionStorage.setItem(key, encrypted);
    } catch (error) {
      console.error('Failed to store item:', error);
    }
  }
  
  static getItem(key: string): string | null {
    try {
      const encrypted = sessionStorage.getItem(key);
      return encrypted ? this.decrypt(encrypted) : null;
    } catch (error) {
      console.error('Failed to retrieve item:', error);
      return null;
    }
  }
  
  static removeItem(key: string) {
    sessionStorage.removeItem(key);
  }
  
  static clear() {
    sessionStorage.clear();
  }
}

/**
 * Anti-CSRF token generator
 */
export function generateCSRFToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Input sanitization
 */
export function sanitizeInput(input: string): string {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
}

/**
 * URL validation
 */
export function isValidURL(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * Detect proxy/VPN
 */
export async function detectProxy(): Promise<boolean> {
  try {
    // Check WebRTC leaks
    const pc = new RTCPeerConnection({ iceServers: [] });
    const noop = () => {};
    
    pc.createDataChannel('');
    pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(noop);
    
    return new Promise((resolve) => {
      pc.onicecandidate = (ice) => {
        if (!ice || !ice.candidate || !ice.candidate.candidate) {
          resolve(false);
          return;
        }
        
        const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
        const match = ipRegex.exec(ice.candidate.candidate);
        
        if (match) {
          const ip = match[1];
          // Check if IP is private (potential VPN)
          const isPrivate = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(ip);
          resolve(isPrivate);
        }
        
        pc.close();
      };
    });
  } catch {
    return false;
  }
}
