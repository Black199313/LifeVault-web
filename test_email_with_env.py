#!/usr/bin/env python3
"""
Test email sending to sachinprabhu@gmail.com using .env credentials
"""

import os
import sys
from pathlib import Path

# Load environment variables from .env file
def load_env_file():
    """Load environment variables from .env file"""
    env_file = Path('.env')
    if env_file.exists():
        print("Loading .env file...")
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
                    print(f"Set {key.strip()} = {value.strip()}")
        print("Environment variables loaded from .env file\n")
    else:
        print("No .env file found")

# Load .env before importing Flask app
load_env_file()

from email_utils import email_service
from app import app
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class TestUser:
    def __init__(self, email):
        self.username = 'TestUser'
        self.recovery_email = email

def check_email_config():
    """Check email configuration"""
    print("=== EMAIL CONFIGURATION CHECK ===")
    
    with app.app_context():
        config_items = [
            'MAIL_SERVER', 'MAIL_PORT', 'MAIL_USE_TLS', 
            'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_DEFAULT_SENDER'
        ]
        
        for item in config_items:
            value = app.config.get(item)
            if item == 'MAIL_PASSWORD':
                display_value = '***SET***' if value else 'NOT SET'
            else:
                display_value = value if value else 'NOT SET'
            print(f"{item}: {display_value}")

def test_email_send():
    """Test sending email to sachinprabhu@gmail.com"""
    print("\n=== EMAIL SEND TEST ===")
    
    with app.app_context():
        user = TestUser('sachinprabhu@gmail.com')
        test_code = 'TEST123456'
        
        print(f"Testing email to: {user.recovery_email}")
        print(f"Recovery code: {test_code}")
        print("Sender email: " + str(app.config.get('MAIL_DEFAULT_SENDER')))
        print()
        
        try:
            print("Attempting to send email...")
            result = email_service.send_recovery_code_email(user, test_code)
            
            if result:
                print("✅ SUCCESS: Email sent successfully!")
                print("📧 Check sachinprabhu@gmail.com for the test email.")
                print("📝 Subject: 'Email Recovery Password - LifeVault'")
                print(f"🔑 Recovery code in email: {test_code}")
            else:
                print("❌ FAILED: Email sending returned False")
                print("Check the logs above for error details.")
                
        except Exception as e:
            print(f"❌ ERROR: Exception occurred: {e}")
            import traceback
            print("\nFull traceback:")
            traceback.print_exc()

if __name__ == '__main__':
    print("LifeVault Email Test - sachinprabhu@gmail.com")
    print("Using Brevo SMTP Service")
    print("=" * 50)
    
    # Check current configuration
    check_email_config()
    
    # Try to send email
    test_email_send()
    
    print("\n" + "=" * 50)
    print("Test completed.")
