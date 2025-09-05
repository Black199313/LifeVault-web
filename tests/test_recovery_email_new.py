#!/usr/bin/env python3
"""
Test email sending to sachinprabhu1993@gmail.com to verify the fix
"""

import os
from pathlib import Path

# Load environment variables from .env file
def load_env_file():
    """Load environment variables from .env file"""
    env_file = Path('.env')
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
        print("✅ Environment variables loaded from .env file")

# Load .env before importing Flask app
load_env_file()

from email_utils import email_service
from app import app
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class TestUser:
    def __init__(self, email):
        self.username = "Sachin"
        self.recovery_email = email

def test_recovery_email():
    """Test sending recovery email to sachinprabhu1993@gmail.com"""
    print("=== RECOVERY EMAIL TEST ===")
    
    with app.app_context():
        user = TestUser('sachinprabhu1993@gmail.com')
        test_password = 'RECOVERY12345TEST'
        
        print(f"Testing recovery email to: {user.recovery_email}")
        print(f"Recovery password: {test_password}")
        print()
        
        try:
            result = email_service.send_recovery_code_email(user, test_password)
            
            if result:
                print("✅ SUCCESS: Recovery email sent successfully!")
                print("📧 Check sachinprabhu1993@gmail.com for the recovery email.")
                print("📝 Subject: 'Email Recovery Password - LifeVault'")
                print(f"🔑 Recovery password in email: {test_password}")
                return True
            else:
                print("❌ FAILED: Email sending returned False")
                return False
                
        except Exception as e:
            print(f"❌ ERROR: Exception occurred: {e}")
            import traceback
            print("\nFull traceback:")
            traceback.print_exc()
            return False

if __name__ == '__main__':
    print("LifeVault Recovery Email Test")
    print("Target: sachinprabhu1993@gmail.com")
    print("Purpose: Verify email sending after recovery email update")
    print("=" * 60)
    
    success = test_recovery_email()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 RECOVERY EMAIL TEST SUCCESSFUL!")
        print("✅ Email sending to sachinprabhu1993@gmail.com works correctly.")
        print("📧 The E-DEK recovery system should now work properly.")
    else:
        print("❌ Recovery email test failed - check logs above for details.")
    
    print("\nRecovery email status: TESTED ✅")
