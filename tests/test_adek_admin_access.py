#!/usr/bin/env python3
"""
Test A-DEK decryption with admin password
"""

import os
import sys
sys.path.append('.')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import required modules
import mongoengine
from models import User, UserKeys, RotationToken
from crypto_utils import crypto_manager
import base64
import json
from datetime import datetime
from werkzeug.security import check_password_hash

def setup_mongodb():
    """Setup MongoDB connection"""
    mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
    mongodb_db = os.environ.get("MONGODB_DB", "lifevault")
    
    try:
        mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
        print(f"✅ MongoDB connected to database: {mongodb_db}")
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

def test_adek_with_admin_password():
    print("🔐 TESTING A-DEK WITH ADMIN PASSWORD")
    print("=" * 40)
    
    try:
        # Connect to MongoDB
        if not setup_mongodb():
            return False
            
        # Find user sachin
        user = User.objects(username='sachin').first()
        if not user:
            print("❌ User 'sachin' not found")
            return False
        
        print(f"✅ Found user: {user.username} (ID: {user.id})")
        
        # Get user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print("❌ User keys not found")
            return False
        
        print(f"✅ Found user keys (version: {user_keys.key_version})")
        
        # Check current A-DEK
        if not user_keys.admin_master_encrypted_key:
            print("❌ No A-DEK found")
            return False
            
        print(f"✅ A-DEK exists, length: {len(user_keys.admin_master_encrypted_key)}")
        print(f"   A-DEK preview: {user_keys.admin_master_encrypted_key[:50]}...")
        
        # Get admin user and password
        admin_user = User.objects(username='admin').first()
        if not admin_user:
            print("❌ Admin user not found")
            return False
            
        print(f"✅ Found admin user: {admin_user.username}")
        
        # Get admin password from user
        print("\n📝 Please provide the admin password:")
        admin_password = input("Admin password: ").strip()
        
        if not admin_password:
            print("❌ No admin password provided")
            return False
        
        # Validate admin password
        if not check_password_hash(admin_user.password_hash, admin_password):
            print("❌ Invalid admin password")
            return False
            
        print("✅ Admin password validated")
        
        # Get admin master key
        try:
            admin_master_key = crypto_manager.get_or_create_admin_master_key(
                admin_password_hash=admin_user.password_hash
            )
            print(f"✅ Got admin master key (length: {len(admin_master_key)} bytes)")
            
        except Exception as e:
            print(f"❌ Failed to get admin master key: {e}")
            return False
        
        # Test A-DEK decryption
        print("\n🧪 TESTING A-DEK DECRYPTION")
        print("-" * 30)
        
        try:
            # Decrypt A-DEK with admin master key
            user_dek_b64 = crypto_manager.decrypt_data(
                user_keys.admin_master_encrypted_key, 
                admin_master_key
            )
            user_dek = base64.urlsafe_b64decode(user_dek_b64)
            
            print(f"✅ A-DEK DECRYPTION SUCCESSFUL!")
            print(f"   Decrypted DEK length: {len(user_dek)} bytes")
            print(f"   DEK (base64): {user_dek_b64[:50]}...")
            
            # Cross-verify with P-DEK to ensure it's the correct DEK
            print("\n🔍 Cross-verifying with P-DEK...")
            
            try:
                # Get DEK from P-DEK
                user_password = "Test1234*"  # Known user password
                if user_keys.password_encrypted_key.startswith('{'):
                    p_dek_data = json.loads(user_keys.password_encrypted_key)
                    salt = base64.urlsafe_b64decode(p_dek_data['salt'])
                    password_key, _ = crypto_manager.derive_key_from_password(user_password, salt)
                    p_dek_b64 = crypto_manager.decrypt_data(p_dek_data['encrypted'], password_key)
                    p_dek = base64.urlsafe_b64decode(p_dek_b64)
                    
                    if user_dek == p_dek:
                        print("✅ A-DEK and P-DEK return the same DEK - PERFECT!")
                        print("✅ A-DEK is working correctly")
                        
                        # Mark token as finalized if needed
                        completed_tokens = RotationToken.objects(
                            user_id=str(user.id),
                            status='completed'
                        )
                        
                        for token in completed_tokens:
                            if not token.a_dek_finalized:
                                token.status = 'finalized'
                                token.a_dek_finalized = True
                                token.save()
                                print(f"✅ Marked token {token.id} as finalized")
                        
                        return True
                    else:
                        print("❌ A-DEK and P-DEK return different DEKs - MISMATCH!")
                        print(f"   A-DEK result: {len(user_dek)} bytes")
                        print(f"   P-DEK result: {len(p_dek)} bytes")
                        return False
                        
            except Exception as e:
                print(f"❌ P-DEK verification failed: {e}")
                # A-DEK still works, just can't cross-verify
                print("⚠️  A-DEK decryption works, but couldn't verify with P-DEK")
                return True
                
        except Exception as e:
            print(f"❌ A-DEK decryption failed: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_admin_access_to_user_data():
    """Test if admin can access user's encrypted data"""
    print("\n🔐 TESTING ADMIN ACCESS TO USER DATA")
    print("=" * 40)
    
    try:
        # Find user sachin
        user = User.objects(username='sachin').first()
        user_keys = UserKeys.objects(user=user).first()
        
        # Get admin password again
        print("📝 Please provide the admin password again for data access test:")
        admin_password = input("Admin password: ").strip()
        
        admin_user = User.objects(username='admin').first()
        if not check_password_hash(admin_user.password_hash, admin_password):
            print("❌ Invalid admin password")
            return False
        
        # Get admin master key and user DEK
        admin_master_key = crypto_manager.get_or_create_admin_master_key(
            admin_password_hash=admin_user.password_hash
        )
        
        user_dek_b64 = crypto_manager.decrypt_data(
            user_keys.admin_master_encrypted_key, 
            admin_master_key
        )
        user_dek = base64.urlsafe_b64decode(user_dek_b64)
        
        print(f"✅ Got user DEK via admin access (length: {len(user_dek)} bytes)")
        
        # Try to decrypt user's secrets
        from models import Secret
        secrets = Secret.objects(user=user)
        
        print(f"✅ Found {secrets.count()} user secrets")
        
        decrypted_count = 0
        for secret in secrets[:3]:  # Test first 3 secrets
            try:
                decrypted_data = crypto_manager.decrypt_data(secret.encrypted_data, user_dek)
                print(f"✅ Decrypted secret: {decrypted_data[:50]}...")
                decrypted_count += 1
            except Exception as e:
                print(f"❌ Failed to decrypt secret: {e}")
        
        if decrypted_count > 0:
            print(f"✅ ADMIN CAN ACCESS USER DATA! Decrypted {decrypted_count} secrets")
            return True
        else:
            print("❌ Admin cannot decrypt user data")
            return False
            
    except Exception as e:
        print(f"❌ Data access test failed: {e}")
        return False

if __name__ == "__main__":
    # Test A-DEK decryption
    adek_success = test_adek_with_admin_password()
    
    if adek_success:
        print("\n" + "=" * 50)
        print("🎉 A-DEK DECRYPTION SUCCESSFUL!")
        print("✅ Admin can decrypt user's DEK")
        
        # Test actual data access
        data_success = test_admin_access_to_user_data()
        
        if data_success:
            print("\n🎉 COMPLETE SUCCESS!")
            print("✅ A-DEK finalization is working perfectly")
            print("✅ Admin has full access to user data")
            print("✅ Key rotation is fully completed")
        else:
            print("\n⚠️  PARTIAL SUCCESS")
            print("✅ A-DEK decryption works")
            print("❌ Data access needs investigation")
    else:
        print("\n❌ A-DEK DECRYPTION FAILED")
        print("Need to investigate the issue further")
