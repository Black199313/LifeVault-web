#!/usr/bin/env python3
"""
Simple email test to sachinprabhu@gmail.com without timeout protection
"""

import os
from pathlib import Path

# Load environment variables from .env file
def load_env_file():
    env_file = Path('.env')
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

load_env_file()

# Import Flask app after loading env
from flask import Flask
from flask_mail import Mail, Message
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create simple Flask app with mail config
app = Flask(__name__)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp-relay.brevo.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

def test_simple_email():
    """Test sending a simple email"""
    print("=== SIMPLE EMAIL TEST ===")
    
    # Print configuration
    print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
    print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
    print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
    print(f"MAIL_PASSWORD: {'***SET***' if app.config['MAIL_PASSWORD'] else 'NOT SET'}")
    print(f"MAIL_DEFAULT_SENDER: {app.config['MAIL_DEFAULT_SENDER']}")
    print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
    print()
    
    with app.app_context():
        try:
            # Create test email
            msg = Message(
                subject="LifeVault Email Test",
                recipients=['sachinprabhu@gmail.com'],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            
            # Email content
            msg.html = """
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>LifeVault Email Test</h2>
                <p>Hello,</p>
                <p>This is a test email from LifeVault to verify email functionality.</p>
                <div style="background-color: #f8f9fa; padding: 20px; margin: 20px 0; text-align: center; font-size: 18px; font-weight: bold; border-radius: 5px;">
                    Email delivery is working! ✅
                </div>
                <p>Test details:</p>
                <ul>
                    <li>Recipient: sachinprabhu@gmail.com</li>
                    <li>SMTP Server: Brevo (smtp-relay.brevo.com)</li>
                    <li>Sender: sachinprabhu.dev@gmail.com</li>
                </ul>
                <p>If you received this email, the LifeVault email system is functioning correctly.</p>
            </div>
            """
            
            print("Sending email to sachinprabhu@gmail.com...")
            print("Please wait...")
            
            # Send the email
            mail.send(msg)
            
            print("✅ SUCCESS: Email sent successfully!")
            print("📧 Check sachinprabhu@gmail.com for the test email.")
            print("📝 Subject: 'LifeVault Email Test'")
            
            return True
            
        except Exception as e:
            print(f"❌ ERROR: Failed to send email: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    print("LifeVault Simple Email Test")
    print("Target: sachinprabhu@gmail.com")
    print("SMTP: Brevo (smtp-relay.brevo.com)")
    print("=" * 50)
    
    success = test_simple_email()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 Test completed successfully!")
        print("Email should be delivered to sachinprabhu@gmail.com")
    else:
        print("❌ Test failed - check error messages above")
