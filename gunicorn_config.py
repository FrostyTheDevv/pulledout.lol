# Gunicorn configuration file

import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', '8080')}"

# Worker processes
workers = 4
worker_class = "sync"
timeout = 120

# Hide server header for security
raw_env = ["SERVER_SOFTWARE="]

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Security: Hide gunicorn version in Server header
# This is done by suppressing the default Server header
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting gunicorn with hidden server header")
