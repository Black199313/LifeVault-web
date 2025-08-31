#!/usr/bin/env python3
"""
Script to reset user's encryption keys with their current password
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
mongoengine.connect('lifevault')

from models import User, UserKeys
from crypto_utils import crypto_manager

def reset_user_keys(username, new_password):
    """Reset user's encryption keys with a new password"""
    try:
        print(f"🔧 Resetting encryption keys for user: {username}")
        
        # Find user
        user = User.objects(username=username).first()
        if not user:
            print(f"❌ User {username} not found")
            return False
        
        print(f"✅ User found: {user.username}")
        
        # Find or create user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print(f"🔧 Creating new UserKeys for {username}")
            user_keys = UserKeys(user=user)
        else:
            print(f"🔧 Updating existing UserKeys for {username}")
        
        # Generate a new DEK
        new_dek = crypto_manager.generate_key()
        print(f"✅ Generated new DEK: {len(new_dek)} bytes")
        
        # Create new encryption keys using the correct password
        print(f"🔧 Creating new P-DEK with password...")
        password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
        password_encrypted = crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), password_key)
        
        # Store in JSON format
        new_p_dek = json.dumps({
            'encrypted': password_encrypted,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        
        # Update user keys
        user_keys.password_encrypted_key = new_p_dek
        user_keys.key_version = (user_keys.key_version or 0) + 1
        user_keys.created_at = datetime.utcnow()
        
        # Clear other DEKs since they're invalid now
        user_keys.security_questions_encrypted_key = None
        user_keys.recovery_phrase_encrypted_key = None
        user_keys.time_lock_encrypted_key = None
        
        # Save
        user_keys.save()
        
        print(f"✅ UserKeys updated successfully!")
        print(f"✅ New key version: {user_keys.key_version}")
        print(f"✅ P-DEK length: {len(new_p_dek)}")
        
        # Test the new P-DEK
        print(f"\n🧪 Testing new P-DEK...")
        try:
            test_dek = crypto_manager.recover_dek_with_password(user_keys, new_password)
            print(f"✅ SUCCESS! P-DEK recovery works with password '{new_password}'")
            print(f"✅ Recovered DEK length: {len(test_dek)} bytes")
            
            # Verify DEK matches
            if test_dek == new_dek:
                print(f"✅ DEK integrity verified - matches original")
            else:
                print(f"❌ DEK mismatch - there may be an issue")
                
            return True
            
        except Exception as e:
            print(f"❌ P-DEK test failed: {str(e)}")
            return False
        
    except Exception as e:
        print(f"❌ Reset failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    username = "sachin"
    password = "Test1234&"
    
    print(f"🔧 RESETTING ENCRYPTION KEYS")
    print(f"🔧 User: {username}")
    print(f"🔧 Password: {password}")
    print(f"🔧 This will create new encryption keys and fix the login issue!")
    
    # Skip confirmation for debugging
    print(f"🔧 Proceeding with key reset...")
    
    success = reset_user_keys(username, password)
    
    if success:
        print(f"\n✅ SUCCESS! User encryption keys have been reset.")
        print(f"✅ User can now login with password: {password}")
        print(f"✅ All existing secrets will need to be re-entered (they cannot be recovered)")
        print(f"💡 Recommend setting up recovery methods (Q-DEK, R-DEK) immediately after login")
    else:
        print(f"\n❌ FAILED! User keys could not be reset.")
        print(f"💡 Check logs above for details")
