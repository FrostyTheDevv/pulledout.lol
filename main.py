#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Security Scanner - Main CLI Application
A comprehensive security vulnerability scanner for websites and web applications

Usage:
    python main.py <target_url> [options]

Examples:
    python main.py https://example.com
    python main.py https://example.com --output report.html
    python main.py https://example.com --max-pages 20
"""

import sys
import io
import argparse
from core.scanner import SecurityScanner
from core.report_generator import generate_html_report
import os

# Fix encoding for Windows console
if sys.platform == 'win32':
    try:
        # Set console to UTF-8 mode
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCP(65001)
        kernel32.SetConsoleOutputCP(65001)
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')  # type: ignore
    except:
        # Fallback for older Python versions
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════╗
║                                                   ║
║              🔍  SawSap  🔍                      ║
║                                                   ║
║  State of the Art Web Security Analysis Platform  ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
    """
    try:
        print(banner)
    except UnicodeEncodeError:
        # Fallback for systems that don't support Unicode
        print("\n===================================================")
        print("        SawSap")
        print("  State of the Art Web Security Analysis Platform")
        print("===================================================\n")

def main():
    """Main entry point for the security scanner"""
    
    print_banner()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='SawSap - State of the Art Web Security Analysis Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py gotchya.lol
  python main.py https://example.com
  python main.py example.com --output my_report.html
  python main.py gotchya.lol --max-pages 20 --output scan.html
  
Security Categories Checked:
  • Transport Security (HTTPS, TLS/SSL)
  • Security Headers (HSTS, CSP, X-Frame-Options, etc.)
  • Form Security (Password handling, CSRF protection)
  • Information Disclosure (Error messages, sensitive files)
  • Cryptography / TLS (Certificate validation, cipher strength)
  • Session / Cookies (Secure, HttpOnly, SameSite flags)
        '''
    )
    
    parser.add_argument(
        'target_url',
        help='Target domain or URL (e.g., gotchya.lol or https://example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='security_report.html',
        help='Output HTML report filename (default: security_report.html)'
    )
    
    parser.add_argument(
        '-m', '--max-pages',
        type=int,
        default=9999,
        help='Maximum number of pages to scan (default: unlimited, 0 = unlimited)'
    )
    
    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip HTML report generation'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Handle unlimited pages
    if args.max_pages == 0:
        args.max_pages = 9999
    
    # Auto-prefix URL if needed
    target_url = args.target_url
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'https://{target_url}'
        print(f"[*] Auto-prefixed URL to: {target_url}")
    
    try:
        # Create scanner instance
        scanner = SecurityScanner(target_url, max_pages=args.max_pages)
        
        # Run the scan
        results = scanner.scan()
        
        # Generate report
        if not args.no_report:
            print(f"\n[*] Generating HTML report...")
            report_file = generate_html_report(results, args.output)
            abs_path = os.path.abspath(report_file)
            print(f"[OK] Report saved to: {abs_path}")
            print(f"\n[*] Open the report in your browser to view detailed findings.")
        
        # Print summary
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target URL:    {target_url}")
        print(f"Risk Score:    {results['risk_score']} ({results['risk_level']})")
        print(f"Pages Scanned: {results['pages_scanned']}")
        print(f"\nFindings:")
        print(f"  HIGH:   {results['findings_summary']['HIGH']}")
        print(f"  MEDIUM: {results['findings_summary']['MEDIUM']}")
        print(f"  LOW:    {results['findings_summary']['LOW']}")
        print(f"  INFO:   {results['findings_summary']['INFO']}")
        
        if results['findings_summary']['HIGH'] > 0:
            print("\n[!] WARNING: High-severity issues detected! Review the report immediately.")
        elif results['findings_summary']['MEDIUM'] > 0:
            print("\n[!] Medium-severity issues detected. Review and address them.")
        else:
            print("\n[OK] No high or medium severity issues detected.")
        
        print("="*60 + "\n")
        
        # Return exit code based on severity
        if results['findings_summary']['HIGH'] > 0:
            sys.exit(2)  # High severity issues
        elif results['findings_summary']['MEDIUM'] > 0:
            sys.exit(1)  # Medium severity issues
        else:
            sys.exit(0)  # No critical issues
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[X] Error during scan: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
