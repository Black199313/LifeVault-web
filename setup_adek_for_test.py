#!/usr/bin/env python3
"""
Setup A-DEK for finalization testing by encrypting with temporary password.
"""

import os
import sys
import base64
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mongoengine
from models import User, UserKeys
from crypto_utils import CryptoManager

def setup_adek_for_testing():
    """Setup A-DEK encrypted with temporary password for testing"""
    try:
        mongoengine.connect('lifevault', host='localhost', port=27017)
        print("✅ Connected to MongoDB")
        
        crypto_manager = CryptoManager()
        
        # Get existing user
        user = User.objects(username='sachin').first()
        if not user:
            print("❌ User 'sachin' not found")
            return False
            
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print("❌ User keys not found")
            return False
            
        print(f"✅ Found user: {user.username}")
        
        # Check if A-DEK exists and try to decrypt with admin password
        if user_keys.admin_master_encrypted_key:
            try:
                # Try to decrypt with admin master key first
                admin = User.objects(username='admin').first()
                admin_master_key = crypto_manager.get_or_create_admin_master_key(
                    admin_password_hash=admin.password_hash
                )
                user_dek_b64 = crypto_manager.decrypt_data(
                    user_keys.admin_master_encrypted_key, 
                    admin_master_key
                )
                user_dek = base64.urlsafe_b64decode(user_dek_b64)
                print("✅ A-DEK already encrypted with admin master key")
                
                # Re-encrypt with temporary password for testing
                temp_password = "Test1234*"
                temp_key, _ = crypto_manager.derive_key_from_password(temp_password)
                temp_encrypted_adek = crypto_manager.encrypt_data(user_dek_b64, temp_key)
                
                # Update with temporary encryption
                user_keys.admin_master_encrypted_key = temp_encrypted_adek
                user_keys.save()
                print(f"✅ Re-encrypted A-DEK with temporary password: {temp_password}")
                
                return True
                
            except Exception as e:
                print(f"⚠️ Could not decrypt with admin key: {e}")
                # Continue to try user password approach
        
        # Try to extract DEK from user's password
        try:
            user_dek = crypto_manager.recover_dek_with_password(user_keys, "Test1234*")
            user_dek_b64 = base64.urlsafe_b64encode(user_dek).decode()
            print("✅ Extracted DEK using user password")
            
        except Exception as e:
            print(f"❌ Failed to extract DEK with user password: {e}")
            return False
        
        # Encrypt DEK with temporary password
        temp_password = "Test1234*"
        temp_key, _ = crypto_manager.derive_key_from_password(temp_password)
        temp_encrypted_adek = crypto_manager.encrypt_data(user_dek_b64, temp_key)
        
        # Update A-DEK
        user_keys.admin_master_encrypted_key = temp_encrypted_adek
        user_keys.save()
        
        print(f"✅ Setup A-DEK encrypted with temporary password: {temp_password}")
        
        # Verify the setup
        test_dek_b64 = crypto_manager.decrypt_data(temp_encrypted_adek, temp_key)
        test_dek = base64.urlsafe_b64decode(test_dek_b64)
        
        if test_dek == user_dek:
            print("✅ Verification successful - A-DEK properly encrypted")
            return True
        else:
            print("❌ Verification failed - decryption mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        return False

if __name__ == "__main__":
    success = setup_adek_for_testing()
    if success:
        print("✅ A-DEK setup complete for testing")
    else:
        print("❌ A-DEK setup failed")
        sys.exit(1)
