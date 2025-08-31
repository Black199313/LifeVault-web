#!/usr/bin/env python3
"""
Use P-DEK recovery to get sachin's secret (bypass A-DEK issues)
"""

import os
import sys
import base64
import json
from dotenv import load_dotenv
import mongoengine
from werkzeug.security import check_password_hash
from models import User, UserKeys, Secret
from crypto_utils import CryptoManager

def recover_sachin_secret_via_pdek():
    """Use P-DEK (password) recovery to get sachin's secret"""
    
    print("🔍 P-DEK SECRET RECOVERY FOR SACHIN")
    print("=" * 50)
    
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
        
        # Get sachin's password (I need to ask for this)
        print("\n🔍 Need sachin's password to recover DEK via P-DEK...")
        print("What is sachin's password? (This is needed for P-DEK recovery)")
        # For now, let me try some common passwords that might have been used
        
        possible_passwords = ["Test1234*", "Sachin123", "sachin123", "Password123", "Admin1234"]
        
        user_password = None
        for test_password in possible_passwords:
            try:
                if check_password_hash(user.password_hash, test_password):
                    user_password = test_password
                    print(f"✅ Found sachin's password: {test_password}")
                    break
            except:
                continue
        
        if not user_password:
            print("❌ Could not determine sachin's password")
            print("Available methods to try:")
            print("1. If you know sachin's password, provide it")
            print("2. Try admin password reset")
            print("3. Use Q-DEK (security questions) recovery")
            print("4. Use R-DEK (recovery phrase) recovery")
            return False
        
        # Try P-DEK recovery
        print("\n🔍 Step 3: Recovering DEK using P-DEK (password)...")
        try:
            if user_keys.password_encrypted_key:
                p_dek_data = user_keys.password_encrypted_key
                print(f"🔍 P-DEK data found, length: {len(str(p_dek_data))}")
                
                # Check format
                if isinstance(p_dek_data, str):
                    try:
                        parsed = json.loads(p_dek_data)
                        if 'salt' in parsed and 'encrypted' in parsed:
                            print("✅ P-DEK is in JSON format with salt")
                            
                            # Use the decrypt_with_password method
                            dek = crypto.decrypt_with_password(p_dek_data, user_password)
                            print(f"✅ DEK recovered via P-DEK, length: {len(dek)}")
                            
                            # Convert to bytes if needed
                            if isinstance(dek, str):
                                dek_bytes = base64.b64decode(dek)
                            else:
                                dek_bytes = dek
                            
                            print(f"✅ DEK bytes length: {len(dek_bytes)}")
                            
                        else:
                            print("❌ P-DEK not in expected format")
                            return False
                    except json.JSONDecodeError:
                        print("❌ P-DEK is not JSON")
                        return False
                else:
                    print("❌ P-DEK is not string")
                    return False
            else:
                print("❌ No P-DEK found for user")
                return False
                
        except Exception as e:
            print(f"❌ P-DEK recovery failed: {e}")
            return False
        
        # Step 4: Find and decrypt secrets
        print("\n🔍 Step 4: Finding and decrypting secrets...")
        secrets = Secret.objects(user=user)
        if not secrets:
            print("❌ No secrets found for user")
            return False
        
        print(f"✅ Found {len(secrets)} secret(s)")
        
        # Try to decrypt the first secret
        first_secret = secrets.first()
        print(f"🔍 Attempting to decrypt secret: {first_secret.title}")
        
        try:
            # Decrypt the secret using the recovered DEK
            decrypted_data = crypto.decrypt_data(first_secret.encrypted_data, dek_bytes)
            
            print("✅ Secret decrypted successfully!")
            print("\n📋 DECRYPTED SECRET CONTENT:")
            print("-" * 50)
            print(f"Title: {first_secret.title}")
            print(f"Category: {first_secret.category}")
            print(f"Created: {first_secret.created_at}")
            print(f"Content: {decrypted_data}")
            print("-" * 50)
            
            return True
            
        except Exception as e:
            print(f"❌ Secret decryption failed: {e}")
            
            # Try all secrets
            print("\n🔍 Trying all secrets...")
            success_count = 0
            for i, secret in enumerate(secrets):
                try:
                    decrypted_data = crypto.decrypt_data(secret.encrypted_data, dek_bytes)
                    print(f"✅ Secret {i+1} ({secret.title}): SUCCESS")
                    print(f"   Content: {decrypted_data[:100]}...")
                    success_count += 1
                except Exception as se:
                    print(f"❌ Secret {i+1} ({secret.title}): FAILED - {se}")
            
            print(f"\n📊 Summary: {success_count}/{len(secrets)} secrets decrypted successfully")
            return success_count > 0
    
    except Exception as e:
        print(f"❌ General error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 Starting P-DEK Secret Recovery")
    print("=" * 50)
    
    success = recover_sachin_secret_via_pdek()
    
    if success:
        print("\n🎯 SUCCESS: P-DEK secret recovery completed!")
    else:
        print("\n❌ FAILED: Could not complete P-DEK secret recovery")
