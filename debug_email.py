import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("Environment Variables:")
print(f"MAIL_SERVER: {os.getenv('MAIL_SERVER')}")
print(f"MAIL_PORT: {os.getenv('MAIL_PORT')}")
print(f"MAIL_USERNAME: {os.getenv('MAIL_USERNAME')}")
print(f"MAIL_PASSWORD: {'Set' if os.getenv('MAIL_PASSWORD') else 'Not set'}")
print(f"MAIL_DEFAULT_SENDER: {os.getenv('MAIL_DEFAULT_SENDER')}")
print(f"MAIL_USE_TLS: {os.getenv('MAIL_USE_TLS')}")

print("\nTesting Flask-Mail import...")
try:
    from flask_mail import Mail, Message
    print("✅ Flask-Mail imported successfully")
except ImportError as e:
    print(f"❌ Flask-Mail import failed: {e}")

print("\nTesting app import...")
try:
    from app import app, mail
    print("✅ App imported successfully")
except ImportError as e:
    print(f"❌ App import failed: {e}")

print("\nTesting Flask app context...")
try:
    with app.app_context():
        print("✅ App context working")
        print(f"App MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
        print(f"App MAIL_DEFAULT_SENDER: {app.config.get('MAIL_DEFAULT_SENDER')}")
except Exception as e:
    print(f"❌ App context failed: {e}")

print("\nTesting email service import...")
try:
    from email_utils import email_service
    print("✅ Email service imported successfully")
except ImportError as e:
    print(f"❌ Email service import failed: {e}")

print("\nTesting direct mail send...")
try:
    with app.app_context():
        msg = Message(
            subject="Test Email",
            recipients=['sachinprabhu.devops@gmail.com'],
            html="<h1>Test Email</h1><p>This is a test email.</p>",
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
        print("✅ Direct mail send successful")
except Exception as e:
    print(f"❌ Direct mail send failed: {e}")
    import traceback
    traceback.print_exc()
