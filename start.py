"""
Unified Startup Script
Runs both Flask web server and Discord bot in separate threads
For Railway deployment
"""

import threading
import logging
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def run_web_server():
    """Run Flask web server"""
    try:
        logger.info("Starting Flask web server...")
        from web_server import app
        port = int(os.environ.get('PORT', 5000))
        debug = os.environ.get('FLASK_ENV', 'production') != 'production'
        
        # Use gunicorn in production
        if not debug:
            logger.info(f"Running Flask with gunicorn on port {port}")
            import gunicorn.app.base
            
            class StandaloneApplication(gunicorn.app.base.BaseApplication):
                def __init__(self, app, options=None):
                    self.options = options or {}
                    self.application = app
                    super().__init__()
                
                def load_config(self):
                    for key, value in self.options.items():
                        self.cfg.set(key.lower(), value)  # type: ignore
                
                def load(self):
                    return self.application
            
            options = {
                'bind': f'0.0.0.0:{port}',
                'workers': 4,
                'worker_class': 'sync',
                'timeout': 120,
                'accesslog': '-',
                'errorlog': '-',
                'loglevel': 'info'
            }
            
            StandaloneApplication(app, options).run()
        else:
            logger.info(f"Running Flask in debug mode on port {port}")
            app.run(host='0.0.0.0', port=port, debug=debug)
            
    except Exception as e:
        logger.error(f"Flask web server error: {e}", exc_info=True)
        sys.exit(1)

def run_discord_bot():
    """Run Discord bot"""
    try:
        logger.info("Starting Discord bot...")
        from discord_bot import run_bot
        run_bot()
    except Exception as e:
        logger.error(f"Discord bot error: {e}", exc_info=True)
        # Don't exit - allow web server to continue running
        logger.warning("Discord bot failed but web server will continue")

def main():
    """Main entry point - starts both services"""
    logger.info("=== Starting pulledout.lol services ===")
    
    # Check if Discord bot should be enabled
    discord_enabled = os.environ.get('ENABLE_DISCORD_BOT', 'true').lower() == 'true'
    
    if discord_enabled:
        # Start Discord bot in background thread
        bot_thread = threading.Thread(target=run_discord_bot, daemon=True, name="DiscordBot")
        bot_thread.start()
        logger.info("Discord bot thread started")
    else:
        logger.info("Discord bot disabled (ENABLE_DISCORD_BOT=false)")
    
    # Run web server in main thread (blocks)
    run_web_server()

if __name__ == '__main__':
    main()
