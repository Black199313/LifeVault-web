#!/usr/bin/env python3
"""
Test the salt-based temporary password encryption/decryption workflow.
"""

import os
import sys
import base64
import hashlib
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mongoengine
from models import User, UserKeys, RotationToken
from crypto_utils import CryptoManager

def test_salt_workflow():
    """Test the complete salt-based encryption/decryption workflow"""
    try:
        mongoengine.connect('lifevault', host='localhost', port=27017)
        print("✅ Connected to MongoDB")
        
        crypto_manager = CryptoManager()
        
        # Get user
        user = User.objects(username='sachin').first()
        user_keys = UserKeys.objects(user=user).first()
        
        print(f"✅ Found user: {user.username}")
        
        # Test scenario
        temp_password = "Test1234*"
        
        print(f"\n🔧 Testing salt-based encryption/decryption...")
        
        # Get DEK (extract from current user)
        user_dek = crypto_manager.recover_dek_with_password(user_keys, "Test1234*")
        user_dek_b64 = base64.urlsafe_b64encode(user_dek).decode()
        
        print(f"✅ Extracted DEK, length: {len(user_dek)} bytes")
        
        # Step 1: Encrypt with temp password (store salt)
        temp_key, temp_salt = crypto_manager.derive_key_from_password(temp_password)
        temp_encrypted_adek = crypto_manager.encrypt_data(user_dek_b64, temp_key)
        
        print(f"✅ Encrypted with temp password")
        print(f"  Salt: {temp_salt.hex()[:20]}...")
        print(f"  Key: {temp_key[:20]}...")
        print(f"  Encrypted length: {len(temp_encrypted_adek)} chars")
        
        # Step 2: Decrypt with same salt
        temp_key_2, _ = crypto_manager.derive_key_from_password(temp_password, temp_salt)
        decrypted_dek_b64 = crypto_manager.decrypt_data(temp_encrypted_adek, temp_key_2)
        decrypted_dek = base64.urlsafe_b64decode(decrypted_dek_b64)
        
        print(f"✅ Decrypted with stored salt")
        print(f"  Key match: {temp_key == temp_key_2}")
        print(f"  DEK match: {user_dek == decrypted_dek}")
        
        if user_dek == decrypted_dek:
            print("✅ Salt-based encryption/decryption successful!")
        else:
            print("❌ Salt-based encryption/decryption failed!")
            return False
        
        # Step 3: Test the complete rotation token workflow
        print(f"\n🔄 Testing complete rotation token workflow...")
        
        # Create token with salt
        temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
        
        token = RotationToken(
            user_id=str(user.id),
            temporary_password_hash=temp_hash,
            temporary_password_salt=base64.urlsafe_b64encode(temp_salt).decode(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            status='completed',
            rotation_stage='completed',
            a_dek_finalized=False
        )
        token.save()
        
        print(f"✅ Created token with salt: {token.id}")
        
        # Update user keys with temp-encrypted A-DEK
        user_keys.admin_master_encrypted_key = temp_encrypted_adek
        user_keys.save()
        
        print(f"✅ Updated user keys with temp-encrypted A-DEK")
        
        # Step 4: Test finalization process
        print(f"\n🎯 Testing finalization process...")
        
        # Validate token
        if token.temporary_password_hash != temp_hash:
            print("❌ Token hash validation failed")
            return False
        print("✅ Token hash validation passed")
        
        # Decrypt with stored salt
        stored_salt = base64.urlsafe_b64decode(token.temporary_password_salt)
        final_temp_key, _ = crypto_manager.derive_key_from_password(temp_password, stored_salt)
        final_dek_b64 = crypto_manager.decrypt_data(user_keys.admin_master_encrypted_key, final_temp_key)
        final_dek = base64.urlsafe_b64decode(final_dek_b64)
        
        if final_dek == user_dek:
            print("✅ Finalization decryption successful!")
        else:
            print("❌ Finalization decryption failed!")
            return False
        
        # Test admin re-encryption
        admin = User.objects(username='admin').first()
        admin_master_key = crypto_manager.get_or_create_admin_master_key(
            admin_password_hash=admin.password_hash
        )
        final_a_dek = crypto_manager.encrypt_data(final_dek_b64, admin_master_key)
        
        # Verify admin encryption
        verify_dek_b64 = crypto_manager.decrypt_data(final_a_dek, admin_master_key)
        verify_dek = base64.urlsafe_b64decode(verify_dek_b64)
        
        if verify_dek == user_dek:
            print("✅ Admin re-encryption successful!")
        else:
            print("❌ Admin re-encryption failed!")
            return False
        
        # Cleanup
        token.delete()
        print(f"\n🧹 Cleaned up test token")
        
        print(f"\n🎉 Complete salt-based workflow test PASSED!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_salt_workflow()
    if success:
        print("✅ Salt workflow test completed successfully")
    else:
        print("❌ Salt workflow test failed")
        sys.exit(1)
