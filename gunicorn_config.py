# Gunicorn configuration file

import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', '8080')}"

# Worker processes
workers = 4
worker_class = "sync"
timeout = 120

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Custom server string (hide version info)
proc_name = "pulledout"

# Security: Suppress server header completely
server_name = ""

# Logging hook
def on_starting(server):
    """Called just before the master process is initialized"""
    server.log.info("Starting gunicorn with suppressed server header")
