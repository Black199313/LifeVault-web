#!/usr/bin/env python3
"""
Diagnostic script to check user's P-DEK and password status
"""

import os
import sys
import json
import base64
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import after path setup
import mongoengine
mongoengine.connect('lifevault')  # Direct connection instead of through Flask

from models import User, UserKeys
from crypto_utils import crypto_manager

def diagnose_user_dek(username):
    """Diagnose user's DEK and password status"""
    try:
        print(f"🔍 Diagnosing user: {username}")
        
        # Find user
        user = User.objects(username=username).first()
        if not user:
            print(f"❌ User {username} not found")
            return
        
        print(f"✅ User found: {user.username}")
        print(f"🔍 User ID: {user.id}")
        print(f"🔍 Force password change: {user.force_password_change}")
        print(f"🔍 Last login: {user.last_login}")
        print(f"🔍 Created at: {user.created_at}")
        
        # Find user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print(f"❌ No UserKeys found for {username}")
            return
        
        print(f"\n🔍 UserKeys Analysis:")
        print(f"✅ UserKeys found")
        print(f"🔍 Key version: {user_keys.key_version}")
        print(f"🔍 Created at: {user_keys.created_at}")
        
        # Analyze P-DEK format
        p_dek = user_keys.password_encrypted_key
        print(f"\n🔍 P-DEK Analysis:")
        print(f"🔍 P-DEK length: {len(p_dek)}")
        print(f"🔍 P-DEK preview: {p_dek[:100]}...")
        
        # Check if it's JSON or colon format
        if p_dek.startswith('{'):
            try:
                data = json.loads(p_dek)
                print(f"✅ P-DEK is in JSON format")
                print(f"🔍 JSON keys: {list(data.keys())}")
                if 'salt' in data:
                    salt_b64 = data['salt']
                    salt = base64.urlsafe_b64decode(salt_b64.encode())
                    print(f"🔍 Salt length: {len(salt)} bytes")
                if 'encrypted' in data:
                    encrypted = data['encrypted']
                    print(f"🔍 Encrypted data length: {len(encrypted)}")
                    print(f"🔍 Encrypted preview: {encrypted[:50]}...")
            except Exception as e:
                print(f"❌ Failed to parse JSON P-DEK: {str(e)}")
        elif ':' in p_dek:
            print(f"✅ P-DEK is in colon format")
            parts = p_dek.split(':', 1)
            print(f"🔍 Salt part length: {len(parts[0])}")
            print(f"🔍 Encrypted part length: {len(parts[1])}")
        else:
            print(f"❌ Unknown P-DEK format")
        
        # Check other DEKs
        print(f"\n🔍 Other DEK Status:")
        print(f"🔍 Q-DEK present: {bool(user_keys.security_questions_encrypted_key)}")
        print(f"🔍 R-DEK present: {bool(user_keys.recovery_phrase_encrypted_key)}")
        print(f"🔍 Time-lock DEK present: {bool(user_keys.time_lock_encrypted_key)}")
        
        # Try a test password
        print(f"\n🔍 Testing common passwords...")
        test_passwords = ['Test1234&', 'password123', 'admin123', 'test123', 'newpassword123', 'password', 'admin', 'sachin123']
        
        for test_password in test_passwords:
            try:
                print(f"🔍 Testing password: {test_password}")
                dek = crypto_manager.recover_dek_with_password(user_keys, test_password)
                print(f"✅ SUCCESS! Password '{test_password}' worked!")
                print(f"✅ DEK recovered, length: {len(dek)} bytes")
                return test_password
            except Exception as e:
                print(f"❌ Failed with '{test_password}': {str(e)[:50]}...")
        
        print(f"\n❌ None of the test passwords worked")
        return None
        
    except Exception as e:
        print(f"❌ Diagnostic failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    username = "sachin"  # Change this to the problematic username
    working_password = diagnose_user_dek(username)
    
    if working_password:
        print(f"\n✅ SOLUTION: Use password '{working_password}' to login")
    else:
        print(f"\n❌ PROBLEM: P-DEK cannot be decrypted with common passwords")
        print(f"💡 SUGGESTIONS:")
        print(f"   1. User may need to use recovery methods (Q-DEK or R-DEK)")
        print(f"   2. Admin may need to reset the user's keys")
        print(f"   3. Check if forced password change completed properly")
