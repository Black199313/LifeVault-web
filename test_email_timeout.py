#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from email_utils import email_service
from app import app
import logging
import time

# Set up logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TestUser:
    def __init__(self, email):
        self.username = 'TestUser'
        self.recovery_email = email

def test_email_with_timeout():
    with app.app_context():
        print("=== Email Configuration Check ===")
        print(f"MAIL_SERVER: {app.config.get('MAIL_SERVER', 'Not set')}")
        print(f"MAIL_PORT: {app.config.get('MAIL_PORT', 'Not set')}")
        print(f"MAIL_USERNAME: {app.config.get('MAIL_USERNAME', 'Not set')}")
        print(f"MAIL_PASSWORD: {'Set' if app.config.get('MAIL_PASSWORD') else 'Not set'}")
        print(f"MAIL_DEFAULT_SENDER: {app.config.get('MAIL_DEFAULT_SENDER', 'Not set')}")
        print(f"MAIL_USE_TLS: {app.config.get('MAIL_USE_TLS', 'Not set')}")
        print(f"MAIL_USE_SSL: {app.config.get('MAIL_USE_SSL', 'Not set')}")
        print()
        
        # Test with a test email
        user = TestUser('test@example.com')
        
        print(f"=== Testing email to: {user.recovery_email} ===")
        print("Starting email send test with 10-second timeout...")
        
        start_time = time.time()
        
        try:
            result = email_service.send_recovery_code_email(user, 'TEST12345')
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"Email send completed in {duration:.2f} seconds")
            print(f"Email send result: {result}")
            
            if result:
                print("✅ Email sent successfully!")
            else:
                print("❌ Email sending failed")
                
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            print(f"❌ Error sending email after {duration:.2f} seconds: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    test_email_with_timeout()
