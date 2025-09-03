import os
import logging
import atexit
import signal
import sys
from flask import Flask, session
import mongoengine
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, logout_user, current_user
from flask_mail import Mail

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ Environment variables loaded from .env file")
except ImportError:
    print("⚠️ python-dotenv not installed, using system environment variables")

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize extensions
login_manager = LoginManager()
mail = Mail()

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Store active sessions for cleanup - make it accessible from app
app.active_sessions = set()

# Session configuration for automatic logout
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 2 hour session timeout
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Application configuration
app.config['ALLOW_REGISTRATIONS'] = os.environ.get('ALLOW_REGISTRATIONS', 'false').lower() in ['true', 'on', '1']

# Configure MongoDB
mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
mongodb_db = os.environ.get("MONGODB_DB", "lifevault")

def cleanup_all_sessions():
    """Cleanup all active sessions on server shutdown"""
    try:
        from models import User
        from datetime import datetime
        
        # Set server restart timestamp to invalidate all sessions
        restart_time = datetime.utcnow()
        
        # Update all active users with logout timestamp
        active_users = User.objects(last_login__exists=True, last_logout__exists=False)
        for user in active_users:
            user.last_logout = restart_time
            user.server_restart_at = restart_time  # New field to track restarts
            user.save()
        
        # Also update users who were logged in recently (within last 2 hours)
        recent_threshold = restart_time - timedelta(hours=2)
        recent_users = User.objects(last_login__gte=recent_threshold)
        for user in recent_users:
            if not user.last_logout or user.last_logout < user.last_login:
                user.last_logout = restart_time
                user.server_restart_at = restart_time
                user.save()
        
        # Store server restart time globally for session validation
        with open('.server_restart_time', 'w') as f:
            f.write(restart_time.isoformat())
        
        logging.info(f"Cleaned up sessions for server shutdown at {restart_time}")
    except Exception as e:
        logging.error(f"Error during session cleanup: {str(e)}")

def signal_handler(sig, frame):
    """Handle shutdown signals"""
    logging.info(f"Received signal {sig}, cleaning up sessions...")
    cleanup_all_sessions()
    sys.exit(0)

# Register shutdown handlers
atexit.register(cleanup_all_sessions)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Connect to MongoDB
try:
    mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
    logging.info(f"MongoDB connection configured for database: {mongodb_db}")
except Exception as e:
    logging.error(f"Failed to configure MongoDB connection: {str(e)}")
    # For development, we'll continue without MongoDB for now
    pass

# Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Initialize extensions
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    from models import User
    import os
    from datetime import datetime
    
    try:
        user = User.objects(id=user_id).first()
        if not user:
            return None
            
        # Check for server restart invalidation BEFORE loading user
        if os.path.exists('.server_restart_time'):
            try:
                with open('.server_restart_time', 'r') as f:
                    restart_time_str = f.read().strip()
                    restart_time = datetime.fromisoformat(restart_time_str)
                    
                    # If user logged in before the server restart, return None to force logout
                    if user.last_login and user.last_login < restart_time:
                        print(f"🔄 User {user.username} session invalidated - logged in before restart")
                        return None
            except Exception as e:
                print(f"Error checking restart time: {e}")
        
        # Check if user was marked as logged out due to server restart
        if (user.server_restart_at and 
            user.last_login and 
            user.server_restart_at > user.last_login):
            print(f"🔄 User {user.username} session invalid - marked for restart logout")
            return None
            
        # Track active session
        if hasattr(session, 'get'):
            session_id = session.get('_id', getattr(session, 'sid', str(user_id)))
            app.active_sessions.add(session_id)
            
        return user
    except Exception as e:
        print(f"Error in user_loader: {e}")
        return None

@app.before_request
def before_request():
    """Handle session management and automatic logout"""
    from flask import request, session as flask_session
    from flask_login import current_user
    from datetime import datetime
    
    # Make session permanent to enable timeout
    flask_session.permanent = True
    
    # Skip for static files and logout endpoints
    if request.endpoint in ['static', 'logout', 'browser_close_logout', 'check_session', 'login']:
        return
    
    # If user is authenticated, update last activity
    if current_user.is_authenticated:
        # Track this session
        session_id = flask_session.get('_id', getattr(flask_session, 'sid', None))
        if session_id:
            app.active_sessions.add(session_id)
        
        # Update user's last activity
        try:
            current_user.last_activity = datetime.utcnow()
            current_user.save()
        except:
            pass

# Setup security headers and template utilities
from utils import setup_security_headers, template_utils
setup_security_headers(app)
app.context_processor(template_utils)

# Add custom Jinja2 filters
import json
@app.template_filter('tojsonfilter')
def to_json_filter(obj):
    return json.dumps(obj)

with app.app_context():
    # Import models to register them
    import models  # noqa: F401
    logging.info("MongoDB models registered")
    
    # Initialize server startup detection and invalidate all existing sessions
    try:
        import os
        from datetime import datetime
        
        startup_time = datetime.utcnow()
        
        # Always create a restart marker on startup to invalidate existing sessions
        with open('.server_restart_time', 'w') as f:
            f.write(startup_time.isoformat())
        logging.info(f"Created server restart marker at startup: {startup_time}")
        
        # Find users who were logged in and mark them for logout
        from models import User
        recently_active = User.objects(
            last_login__exists=True,
            last_activity__gte=startup_time - timedelta(hours=24)  # Active in last 24 hours
        )
        
        logout_count = 0
        for user in recently_active:
            # If user was logged in but has no logout time, or logout was before last login
            if not user.last_logout or user.last_logout < user.last_login:
                user.last_logout = startup_time
                user.server_restart_at = startup_time
                user.save()
                logout_count += 1
        
        logging.info(f"Server startup: Invalidated {logout_count} existing user sessions")
            
    except Exception as e:
        logging.error(f"Error during startup session cleanup: {str(e)}")
    
    # Register admin routes
    from admin_routes import register_admin_routes
    register_admin_routes(app)
    logging.info("Admin routes registered")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
