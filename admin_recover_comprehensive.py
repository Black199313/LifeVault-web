#!/usr/bin/env python3
"""
Try admin recovery using the method from the working finalization test
"""

import os
import sys
import base64
import json
from dotenv import load_dotenv
import mongoengine
from werkzeug.security import check_password_hash
from models import User, UserKeys, Secret, RotationToken
from crypto_utils import CryptoManager

def admin_decrypt_with_finalization_method():
    """Use the same method that worked in the finalization test"""
    
    print("🔍 ADMIN A-DEK RECOVERY (FINALIZATION METHOD)")
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
        # Find sachin user
        user = User.objects(username="sachin").first()
        if not user:
            print("❌ User sachin not found")
            return False
        print(f"✅ Found user: {user.username}")
        
        # Get user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print("❌ User keys not found")
            return False
        print("✅ User keys found")
        
        # Look for any rotation tokens with stored salt
        print("\n🔍 Checking for rotation tokens with A-DEK salt...")
        tokens = RotationToken.objects(user_id=user.id).order_by('-created_at')
        
        salt_found = False
        stored_salt = None
        
        for token in tokens:
            if hasattr(token, 'salt') and token.salt:
                print(f"✅ Found rotation token with salt: {token.id}")
                stored_salt = base64.b64decode(token.salt)
                salt_found = True
                break
        
        if not salt_found:
            print("❌ No rotation token with salt found")
            print("🔍 Trying direct A-DEK decryption methods...")
            
            # Method 1: Try to use the current A-DEK format
            admin_user = User.objects(is_admin=True).first()
            if admin_user and check_password_hash(admin_user.password_hash, admin_password):
                print("✅ Admin password verified")
                
                try:
                    admin_master_key = crypto.get_or_create_admin_master_key(admin_user.password_hash)
                    print(f"✅ Got admin master key: {len(admin_master_key)} bytes")
                    
                    # The A-DEK might be in base64 format directly
                    a_dek_data = user_keys.admin_master_encrypted_key
                    print(f"🔍 A-DEK data length: {len(a_dek_data)} chars")
                    
                    # Try different approaches
                    print("🔍 Trying direct admin master key decryption...")
                    try:
                        dek_b64 = crypto.decrypt_data(a_dek_data, admin_master_key)
                        dek_bytes = base64.b64decode(dek_b64)
                        print(f"✅ Method 1 SUCCESS: DEK recovered, {len(dek_bytes)} bytes")
                        
                        # Try to decrypt a secret
                        return try_decrypt_secrets(user, dek_bytes, "Method 1 (Direct Admin Master Key)")
                        
                    except Exception as e:
                        print(f"❌ Method 1 failed: {e}")
                    
                    # Method 2: Maybe the A-DEK was encrypted with password directly
                    print("🔍 Trying password-based decryption on A-DEK...")
                    try:
                        # Check if A-DEK looks like JSON
                        if a_dek_data.startswith('{'): 
                            dek = crypto.decrypt_with_password(a_dek_data, admin_password)
                            if isinstance(dek, str):
                                dek_bytes = base64.b64decode(dek)
                            else:
                                dek_bytes = dek
                            print(f"✅ Method 2 SUCCESS: DEK recovered, {len(dek_bytes)} bytes")
                            
                            return try_decrypt_secrets(user, dek_bytes, "Method 2 (Password Decryption)")
                            
                    except Exception as e:
                        print(f"❌ Method 2 failed: {e}")
                    
                except Exception as e:
                    print(f"❌ Admin authentication failed: {e}")
            
            return False
        
        else:
            print(f"✅ Using stored salt from rotation token, length: {len(stored_salt)}")
            
            # Method 3: Use salt-based decryption like in finalization test
            print("🔍 Trying salt-based A-DEK finalization method...")
            try:
                # Try to decrypt A-DEK using admin password with stored salt
                a_dek_data = user_keys.admin_master_encrypted_key
                
                # Assume it's base64 encoded
                encrypted_a_dek = base64.b64decode(a_dek_data)
                
                # Try password-based decryption with stored salt
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.fernet import Fernet
                import base64
                
                # Derive key from admin password and stored salt
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=stored_salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(admin_password.encode()))
                f = Fernet(key)
                
                # Try to decrypt
                dek_bytes = f.decrypt(encrypted_a_dek)
                print(f"✅ Method 3 SUCCESS: A-DEK decrypted with stored salt, {len(dek_bytes)} bytes")
                
                return try_decrypt_secrets(user, dek_bytes, "Method 3 (Salt-based)")
                
            except Exception as e:
                print(f"❌ Method 3 failed: {e}")
                
        return False
        
    except Exception as e:
        print(f"❌ General error: {e}")
        import traceback
        traceback.print_exc()
        return False

def try_decrypt_secrets(user, dek_bytes, method_name):
    """Try to decrypt secrets with the given DEK"""
    print(f"\n🔍 Trying to decrypt secrets using {method_name}...")
    
    crypto = CryptoManager()
    secrets = Secret.objects(user=user)
    
    if not secrets:
        print("❌ No secrets found")
        return False
    
    print(f"✅ Found {len(secrets)} secret(s)")
    
    success_count = 0
    for i, secret in enumerate(secrets):
        try:
            decrypted_data = crypto.decrypt_data(secret.encrypted_data, dek_bytes)
            print(f"✅ Secret {i+1} ({secret.title}): SUCCESS")
            print(f"   📋 Content: {decrypted_data}")
            print(f"   📅 Created: {secret.created_at}")
            print(f"   📂 Category: {secret.category}")
            success_count += 1
        except Exception as se:
            print(f"❌ Secret {i+1} ({secret.title}): FAILED - {se}")
    
    print(f"\n📊 Summary: {success_count}/{len(secrets)} secrets decrypted successfully with {method_name}")
    return success_count > 0

if __name__ == "__main__":
    print("🚀 Starting Admin A-DEK Recovery")
    print("=" * 60)
    
    success = admin_decrypt_with_finalization_method()
    
    if success:
        print("\n🎯 SUCCESS: Admin A-DEK recovery and secret decryption completed!")
    else:
        print("\n❌ FAILED: Could not complete admin A-DEK recovery")
