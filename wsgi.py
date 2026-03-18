"""
Production WSGI entry point for SawSap Security Scanner
Use with Gunicorn on Railway
"""

from web_server import app

if __name__ == "__main__":
    app.run()
