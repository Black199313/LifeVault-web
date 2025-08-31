#!/usr/bin/env python3
"""
Decrypt A-DEK using admin password and retrieve sachin's secret
"""

import os
import sys
import base64
from dotenv import load_dotenv
import mongoengine
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, UserKeys, Secret
from crypto_utils import CryptoManager

def decrypt_sachin_secret_with_admin():
    """Use admin password to decrypt A-DEK and get sachin's secret"""
    
    print("🔍 ADMIN A-DEK DECRYPTION AND SECRET RETRIEVAL")
    print("=" * 60)
    
    # Load environment
    load_dotenv()
    
    # Connect to MongoDB
    try:
        mongoengine.connect(
            db=os.getenv('MONGODB_DATABASE', 'lifevault'),
            host=os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
        )
        print("✅ Connected to MongoDB")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False
    
    # Initialize crypto manager
    crypto = CryptoManager()
    admin_password = "Admin1234"
    
    try:
        # Step 1: Find sachin user
        print("\n🔍 Step 1: Finding user sachin...")
        user = User.objects(username="sachin").first()
        if not user:
            print("❌ User sachin not found")
            return False
        print(f"✅ Found user: {user.username}")
        
        # Step 2: Get user keys
        print("\n🔍 Step 2: Getting user keys...")
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print("❌ User keys not found")
            return False
        print("✅ User keys found")
        
        # Step 3: Check A-DEK availability
        print("\n🔍 Step 3: Checking A-DEK...")
        if not user_keys.admin_master_encrypted_key:
            print("❌ A-DEK not found for user")
            return False
        print("✅ A-DEK found")
        
        # Step 4: Decrypt A-DEK with admin password
        print("\n🔍 Step 4: Finding admin user and verifying password...")
        try:
            # Find the admin user
            admin_user = User.objects(is_admin=True).first()
            if not admin_user:
                print("❌ Admin user not found")
                return False
            
            print(f"✅ Found admin user: {admin_user.username}")
            
            # Verify the admin password
            from werkzeug.security import check_password_hash
            if not check_password_hash(admin_user.password_hash, admin_password):
                print("❌ Admin password verification failed")
                return False
            
            print("✅ Admin password verified")
            
            # Use the admin user's password hash to get admin master key
            admin_master_key = crypto.get_or_create_admin_master_key(admin_user.password_hash)
            print(f"✅ Retrieved admin master key, length: {len(admin_master_key)}")
            
            # Now decrypt the A-DEK using the admin master key
            a_dek_b64 = crypto.decrypt_data(user_keys.admin_master_encrypted_key, admin_master_key)
            a_dek = base64.b64decode(a_dek_b64)
            
            print(f"✅ A-DEK decrypted successfully, length: {len(a_dek)}")
            
        except Exception as e:
            print(f"❌ A-DEK decryption failed: {e}")
            return False
        
        # Step 5: Find sachin's secrets
        print("\n🔍 Step 5: Finding secrets for sachin...")
        secrets = Secret.objects(user=user)
        if not secrets:
            print("❌ No secrets found for user")
            return False
        
        print(f"✅ Found {len(secrets)} secret(s)")
        
        # Step 6: Try to decrypt the first secret
        print("\n🔍 Step 6: Decrypting first secret...")
        first_secret = secrets.first()
        print(f"🔍 Secret title: {first_secret.title}")
        print(f"🔍 Secret category: {first_secret.category}")
        print(f"🔍 Secret created: {first_secret.created_at}")
        
        try:
            # Decrypt the secret data using A-DEK
            encrypted_data = base64.b64decode(first_secret.encrypted_data)
            decrypted_data = crypto.decrypt_data(first_secret.encrypted_data, a_dek)
            
            print("✅ Secret decrypted successfully!")
            print("\n📋 DECRYPTED SECRET CONTENT:")
            print("-" * 40)
            print(f"Title: {first_secret.title}")
            print(f"Category: {first_secret.category}")
            print(f"Content: {decrypted_data}")
            print("-" * 40)
            
            return True
            
        except Exception as e:
            print(f"❌ Secret decryption failed: {e}")
            print("🔍 This might be due to key version mismatch after rotation")
            
            # Try to list all secrets and their status
            print("\n🔍 Checking all secrets...")
            for i, secret in enumerate(secrets):
                try:
                    decrypted_data = crypto.decrypt_data(secret.encrypted_data, a_dek)
                    print(f"✅ Secret {i+1} ({secret.title}): Decryption successful")
                    print(f"   Content preview: {decrypted_data[:50]}...")
                except Exception as se:
                    print(f"❌ Secret {i+1} ({secret.title}): Decryption failed - {se}")
            
            return False
    
    except Exception as e:
        print(f"❌ General error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 Starting Admin A-DEK Secret Decryption Test")
    print("=" * 60)
    
    success = decrypt_sachin_secret_with_admin()
    
    if success:
        print("\n🎯 SUCCESS: Admin A-DEK decryption and secret retrieval completed!")
    else:
        print("\n❌ FAILED: Could not complete admin A-DEK decryption and secret retrieval")
