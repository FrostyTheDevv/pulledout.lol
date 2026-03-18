"""
Quick Start Script - Launch Web Dashboard
Opens browser automatically when server is ready
"""

import subprocess
import time
import webbrowser
import socket
import sys

def is_port_open(port, host='localhost'):
    """Check if a port is open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def wait_for_server(port=5000, timeout=30):
    """Wait for server to start"""
    print(f"[*] Waiting for server to start on port {port}...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if is_port_open(port):
            print(f"[+] Server is ready!")
            return True
        time.sleep(0.5)
    
    print(f"[-] Server did not start within {timeout} seconds")
    return False

def main():
    print("""
    ===============================================
        SawSap - Web Security Scanner        
    ===============================================
    """)
    
    # Use virtual environment Python if available
    import os
    venv_python = os.path.join('.venv', 'Scripts', 'python.exe')
    python_exe = venv_python if os.path.exists(venv_python) else sys.executable
    
    # Start the web server
    print("[*] Starting web server...")
    print("[*] Loading Selenium and security modules...")
    try:
        server_process = subprocess.Popen(
            [python_exe, 'web_server.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Print server output in real-time
        import threading
        def print_output():
            if server_process.stdout:  # Type guard for Pylance
                for line in iter(server_process.stdout.readline, ''):
                    if line:
                        print(line.rstrip())
        
        output_thread = threading.Thread(target=print_output, daemon=True)
        output_thread.start()
        
        # Wait for server to be ready
        if wait_for_server():
            print("[+] Opening browser...")
            time.sleep(1)
            webbrowser.open('http://localhost:5000')
            print("""
    ===============================================
        Dashboard opened in your browser!
        
        Access at: http://localhost:5000
        
        Press Ctrl+C to stop the server
    ===============================================
            """)
            
            # Keep the server running
            try:
                server_process.wait()
            except KeyboardInterrupt:
                print("\n[*] Shutting down server...")
                server_process.terminate()
                server_process.wait()
                print("[+] Server stopped successfully")
        else:
            print("[-] Failed to start server. Check for errors above.")
            server_process.terminate()
            
    except Exception as e:
        print(f"[-] Error starting server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
