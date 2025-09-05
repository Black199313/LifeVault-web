#!/usr/bin/env python3
"""
Automated Key Rotation Test - Tests the complete workflow without user input
"""

import os
import sys
import json
import base64
import hashlib
import logging
import mongoengine
from datetime import datetime, timedelta
from secrets import token_urlsafe

# Add the parent directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Initialize MongoDB connection
try:
    mongoengine.connect('lifevault', host='localhost', port=27017)
    print("✅ Connected to MongoDB")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    sys.exit(1)

from models import User, UserKeys, RotationToken, Secret
from crypto_utils import CryptoManager

def test_automated_key_rotation():
    """Test key rotation with existing user credentials"""
    
    print("🚀 AUTOMATED KEY ROTATION TEST")
    print("=" * 50)
    
    # Use existing user
    username = 'sachin'
    user_password = 'Test1234*'
    admin_password = 'Admin1234'
    
    crypto_manager = CryptoManager()
    
    print(f"\n🔍 Step 1: Locate user '{username}'")
    user = User.objects(username=username).first()
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    print(f"✅ Found user: {user.username} (ID: {user.id})")
    
    # Get user keys
    user_keys = UserKeys.objects(user=user).first()
    if not user_keys:
        print("❌ User keys not found")
        return False
    
    print(f"✅ User keys found (version: {user_keys.key_version})")
    
    print(f"\n🔍 Step 2: Recover current DEK")
    try:
        current_dek = crypto_manager.recover_dek_with_password(user_keys, user_password)
        print(f"✅ Current DEK recovered, length: {len(current_dek)} bytes")
    except Exception as e:
        print(f"❌ Failed to recover current DEK: {e}")
        return False
    
    print(f"\n🔍 Step 3: Generate rotation credentials")
    temp_password = token_urlsafe(16)
    temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
    
    print(f"✅ Generated temporary password: {temp_password}")
    
    # Create rotation token
    rotation_token = RotationToken(
        user_id=str(user.id),
        temporary_password_hash=temp_hash,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        status='approved',
        request_reason='Automated test rotation'
    )
    rotation_token.save()
    
    print(f"✅ Created rotation token: {rotation_token.id}")
    
    print(f"\n🔍 Step 4: Generate new DEK")
    new_dek = crypto_manager.generate_key()
    print(f"✅ New DEK generated, length: {len(new_dek)} bytes")
    
    print(f"\n🔍 Step 5: Create new P-DEK")
    try:
        password_key, password_salt = crypto_manager.derive_key_from_password(user_password)
        new_pdek_encrypted = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(new_dek).decode(), 
            password_key
        )
        
        new_pdek_data = {
            'salt': base64.urlsafe_b64encode(password_salt).decode(),
            'encrypted': new_pdek_encrypted
        }
        
        print("✅ New P-DEK created")
        
    except Exception as e:
        print(f"❌ Failed to create new P-DEK: {e}")
        return False
    
    print(f"\n🔍 Step 6: Create temporary A-DEK with salt storage")
    try:
        # Encrypt with temporary password and store salt
        temp_key, temp_salt = crypto_manager.derive_key_from_password(temp_password)
        temp_adek_encrypted = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(new_dek).decode(), 
            temp_key
        )
        
        # Store salt in rotation token
        rotation_token.temporary_password_salt = base64.urlsafe_b64encode(temp_salt).decode()
        rotation_token.save()
        
        print("✅ Temporary A-DEK created with salt stored")
        print(f"   Salt length: {len(temp_salt)} bytes")
        print(f"   Encrypted A-DEK length: {len(temp_adek_encrypted)} chars")
        
    except Exception as e:
        print(f"❌ Failed to create temporary A-DEK: {e}")
        return False
    
    print(f"\n🔍 Step 7: Finalize A-DEK with admin master key")
    try:
        # Get admin user
        admin = User.objects(username='admin').first()
        if not admin:
            print("❌ Admin user not found")
            return False
            
        # Get admin master key
        admin_master_key = crypto_manager.get_or_create_admin_master_key(
            admin_password_hash=admin.password_hash
        )
        
        # Decrypt temporary A-DEK using stored salt
        stored_salt = base64.urlsafe_b64decode(rotation_token.temporary_password_salt)
        temp_key_for_decrypt, _ = crypto_manager.derive_key_from_password(temp_password, stored_salt)
        
        decrypted_dek_b64 = crypto_manager.decrypt_data(temp_adek_encrypted, temp_key_for_decrypt)
        recovered_dek = base64.urlsafe_b64decode(decrypted_dek_b64)
        
        print(f"✅ Decrypted DEK from temp A-DEK using stored salt")
        print(f"   DEK matches: {recovered_dek == new_dek}")
        
        # Re-encrypt with admin master key
        final_adek_encrypted = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(new_dek).decode(),
            admin_master_key
        )
        
        # Verify the finalization
        verify_dek_b64 = crypto_manager.decrypt_data(final_adek_encrypted, admin_master_key)
        verify_dek = base64.urlsafe_b64decode(verify_dek_b64)
        
        if verify_dek == new_dek:
            print("✅ A-DEK finalization verified")
            rotation_token.a_dek_finalized = True
            rotation_token.save()
        else:
            print("❌ A-DEK finalization verification failed")
            return False
        
    except Exception as e:
        print(f"❌ A-DEK finalization failed: {e}")
        return False
    
    print(f"\n🔍 Step 8: Update user keys in database")
    try:
        # Store the original version for rollback test
        original_version = user_keys.key_version
        original_pdek = user_keys.password_encrypted_key
        original_adek = user_keys.admin_master_encrypted_key
        
        # Update with new keys
        user_keys.password_encrypted_key = json.dumps(new_pdek_data)
        user_keys.admin_master_encrypted_key = final_adek_encrypted
        user_keys.key_version += 1
        user_keys.last_updated = datetime.utcnow()
        user_keys.save()
        
        print(f"✅ User keys updated (version: {original_version} → {user_keys.key_version})")
        
    except Exception as e:
        print(f"❌ Failed to update user keys: {e}")
        return False
    
    print(f"\n🔍 Step 9: Verify new key system works")
    try:
        # Test P-DEK recovery
        test_dek = crypto_manager.recover_dek_with_password(user_keys, user_password)
        print(f"✅ P-DEK recovery: DEK matches = {test_dek == new_dek}")
        
        # Test A-DEK recovery
        test_admin_dek = crypto_manager.recover_dek_with_admin_key(user_keys)
        print(f"✅ A-DEK recovery: DEK matches = {test_admin_dek == new_dek}")
        
        if test_dek != new_dek or test_admin_dek != new_dek:
            print("❌ Key verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Key verification failed: {e}")
        return False
    
    print(f"\n🔍 Step 10: Update rotation token status")
    rotation_token.status = 'completed'
    rotation_token.used_at = datetime.utcnow()
    rotation_token.save()
    
    print("\n" + "=" * 50)
    print("🎉 AUTOMATED KEY ROTATION TEST COMPLETED SUCCESSFULLY!")
    print("=" * 50)
    
    print(f"\n📊 SUMMARY:")
    print(f"   • User: {user.username}")
    print(f"   • Key Version: {original_version} → {user_keys.key_version}")
    print(f"   • Rotation Token: {rotation_token.id}")
    print(f"   • Token Status: {rotation_token.status}")
    print(f"   • A-DEK Finalized: {rotation_token.a_dek_finalized}")
    print(f"   • Temporary Password: {temp_password}")
    print(f"   • Salt Storage: ✅ Working")
    print(f"   • P-DEK Recovery: ✅ Working") 
    print(f"   • A-DEK Recovery: ✅ Working")
    
    print(f"\n🔧 Test Credentials for Manual Verification:")
    print(f"   • Username: {username}")
    print(f"   • Password: {user_password}")
    print(f"   • Admin Password: {admin_password}")
    print(f"   • Token ID: {rotation_token.id}")
    print(f"   • Temp Password: {temp_password}")
    
    return True

if __name__ == "__main__":
    try:
        success = test_automated_key_rotation()
        if success:
            print("\n✅ All tests passed!")
            sys.exit(0)
        else:
            print("\n❌ Test failed!")
            sys.exit(1)
    except Exception as e:
        print(f"\n💥 Test crashed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
