#!/usr/bin/env python3
"""
Test email sending to sachinprabhu@gmail.com
This will show us what email configuration is needed.
"""

import os
import sys
from email_utils import email_service
from app import app, mail
import logging

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

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
        
        print(f"\nEnvironment variables:")
        env_vars = ['MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_SERVER', 'MAIL_PORT']
        for var in env_vars:
            value = os.environ.get(var)
            if var == 'MAIL_PASSWORD':
                display_value = '***SET***' if value else 'NOT SET'
            else:
                display_value = value if value else 'NOT SET'
            print(f"{var}: {display_value}")

def test_email_send():
    """Test sending email to sachinprabhu@gmail.com"""
    print("\n=== EMAIL SEND TEST ===")
    
    with app.app_context():
        user = TestUser('sachinprabhu@gmail.com')
        test_code = 'TEST123456'
        
        print(f"Testing email to: {user.recovery_email}")
        print(f"Recovery code: {test_code}")
        
        try:
            # Try to send email
            result = email_service.send_recovery_code_email(user, test_code)
            
            if result:
                print("✅ SUCCESS: Email sent successfully!")
                print("Check sachinprabhu@gmail.com for the test email.")
            else:
                print("❌ FAILED: Email sending returned False")
                
        except Exception as e:
            print(f"❌ ERROR: Exception occurred: {e}")
            import traceback
            print("\nFull traceback:")
            traceback.print_exc()

def suggest_setup():
    """Suggest what needs to be set up"""
    print("\n=== SETUP SUGGESTIONS ===")
    print("To send emails, you need to set these environment variables:")
    print("1. MAIL_USERNAME - Your Gmail address (e.g., yourname@gmail.com)")
    print("2. MAIL_PASSWORD - Your Gmail app password (not regular password)")
    print("3. MAIL_SERVER - Gmail SMTP server (default: smtp.gmail.com)")
    print("4. MAIL_PORT - Gmail SMTP port (default: 587)")
    print()
    print("For Gmail, you need to:")
    print("1. Enable 2-factor authentication")
    print("2. Generate an 'App Password' in your Google Account settings")
    print("3. Use that app password, not your regular Gmail password")
    print()
    print("Example PowerShell commands to set environment variables:")
    print('$env:MAIL_USERNAME = "yourname@gmail.com"')
    print('$env:MAIL_PASSWORD = "your_app_password_here"')
    print('$env:MAIL_SERVER = "smtp.gmail.com"')
    print('$env:MAIL_PORT = "587"')

if __name__ == '__main__':
    print("LifeVault Email Test - sachinprabhu@gmail.com")
    print("=" * 50)
    
    # Check current configuration
    check_email_config()
    
    # Try to send email
    test_email_send()
    
    # Provide setup suggestions
    suggest_setup()
    
    print("\n" + "=" * 50)
    print("Test completed.")
