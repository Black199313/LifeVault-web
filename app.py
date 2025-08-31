import os
import logging
from flask import Flask
import mongoengine
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager
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

# Application configuration
app.config['ALLOW_REGISTRATIONS'] = os.environ.get('ALLOW_REGISTRATIONS', 'false').lower() in ['true', 'on', '1']

# Configure MongoDB
mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
mongodb_db = os.environ.get("MONGODB_DB", "lifevault")

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
    try:
        return User.objects(id=user_id).first()
    except:
        return None

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
    
    # Register admin routes
    from admin_routes import register_admin_routes
    register_admin_routes(app)
    logging.info("Admin routes registered")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
