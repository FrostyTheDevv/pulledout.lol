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

# Post-fork hook to customize worker behavior
def post_fork(server, worker):
    """Called after a worker has been forked"""
    # Disable gunicorn's Server header
    server.cfg.set("server_software", "")

# Security: Hide gunicorn version in Server header
# This is done by suppressing the default Server header
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting gunicorn with hidden server header")
