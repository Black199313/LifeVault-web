#!/usr/bin/env python3
"""
Debug A-DEK finalization step by step to identify the issue.
"""

import os
import sys
import base64
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mongoengine
from models import User, UserKeys, RotationToken
from crypto_utils import CryptoManager

def debug_finalization():
    """Debug the A-DEK finalization process"""
    try:
        mongoengine.connect('lifevault', host='localhost', port=27017)
        print("✅ Connected to MongoDB")
        
        crypto_manager = CryptoManager()
        
        # Get user and admin
        user = User.objects(username='sachin').first()
        admin = User.objects(username='admin').first()
        user_keys = UserKeys.objects(user=user).first()
        
        print(f"✅ Found user: {user.username}")
        print(f"✅ Found admin: {admin.username}")
        
        # Setup test scenario
        temp_password = "Test1234*"
        admin_password = "Admin1234"
        
        print(f"\n🔧 Setting up test scenario...")
        
        # Get current DEK
        try:
            admin_master_key = crypto_manager.get_or_create_admin_master_key(
                admin_password_hash=admin.password_hash
            )
            user_dek_b64 = crypto_manager.decrypt_data(
                user_keys.admin_master_encrypted_key, 
                admin_master_key
            )
            user_dek = base64.urlsafe_b64decode(user_dek_b64)
            print(f"✅ Extracted DEK using admin master key")
        except Exception as e:
            print(f"⚠️ Admin key failed: {e}")
            # Try user password
            user_dek = crypto_manager.recover_dek_with_password(user_keys, "Test1234*")
            user_dek_b64 = base64.urlsafe_b64encode(user_dek).decode()
            print(f"✅ Extracted DEK using user password")
        
        print(f"DEK length: {len(user_dek)} bytes")
        print(f"DEK (b64) length: {len(user_dek_b64)} chars")
        
        # Encrypt with temporary password
        temp_key, salt = crypto_manager.derive_key_from_password(temp_password)
        temp_encrypted_adek = crypto_manager.encrypt_data(user_dek_b64, temp_key)
        
        print(f"Temp key length: {len(temp_key)} bytes")
        print(f"Salt: {salt.hex()[:20]}...")
        print(f"Encrypted A-DEK length: {len(temp_encrypted_adek)} chars")
        
        # Update A-DEK
        user_keys.admin_master_encrypted_key = temp_encrypted_adek
        user_keys.save()
        
        # Create token
        temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
        
        token = RotationToken(
            user_id=str(user.id),
            temporary_password_hash=temp_hash,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            status='completed',
            rotation_stage='completed',
            a_dek_finalized=False
        )
        token.save()
        
        print(f"✅ Created token: {token.id}")
        print(f"Token temp hash: {temp_hash[:20]}...")
        
        print(f"\n🧪 Testing finalization process...")
        
        # Step 1: Validate temp password hash
        test_hash = hashlib.sha256(temp_password.encode()).hexdigest()
        if token.temporary_password_hash == test_hash:
            print("✅ Temp password hash validation passed")
        else:
            print("❌ Temp password hash validation failed")
            print(f"Expected: {test_hash[:20]}...")
            print(f"Got: {token.temporary_password_hash[:20]}...")
        
        # Step 2: Try to decrypt A-DEK with temp password
        try:
            temp_key_2, salt_2 = crypto_manager.derive_key_from_password(temp_password)
            decrypted_dek_b64 = crypto_manager.decrypt_data(
                user_keys.admin_master_encrypted_key, 
                temp_key_2
            )
            decrypted_dek = base64.urlsafe_b64decode(decrypted_dek_b64)
            
            print("✅ A-DEK decryption with temp password successful")
            print(f"Decrypted DEK length: {len(decrypted_dek)} bytes")
            print(f"DEK match: {decrypted_dek == user_dek}")
            
            if salt != salt_2:
                print(f"⚠️ Salt mismatch!")
                print(f"Original salt: {salt.hex()[:20]}...")
                print(f"New salt: {salt_2.hex()[:20]}...")
            else:
                print("✅ Salt consistency verified")
            
        except Exception as e:
            print(f"❌ A-DEK decryption failed: {e}")
            print(f"Current A-DEK: {user_keys.admin_master_encrypted_key[:50]}...")
        
        # Step 3: Test admin re-encryption
        try:
            admin_master_key_2 = crypto_manager.get_or_create_admin_master_key(
                admin_password_hash=admin.password_hash
            )
            new_a_dek = crypto_manager.encrypt_data(user_dek_b64, admin_master_key_2)
            print(f"✅ Admin re-encryption successful")
            print(f"New A-DEK length: {len(new_a_dek)} chars")
            
            # Verify
            verify_dek_b64 = crypto_manager.decrypt_data(new_a_dek, admin_master_key_2)
            verify_dek = base64.urlsafe_b64decode(verify_dek_b64)
            print(f"✅ Verification successful: {verify_dek == user_dek}")
            
        except Exception as e:
            print(f"❌ Admin re-encryption failed: {e}")
        
        # Cleanup
        token.delete()
        print(f"\n🧹 Cleaned up test token")
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    from datetime import datetime, timedelta
    debug_finalization()
