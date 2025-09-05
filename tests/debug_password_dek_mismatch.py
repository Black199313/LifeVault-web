#!/usr/bin/env python3
"""
Debug password validation vs DEK recovery mismatch
"""

import os
import sys
sys.path.append('.')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

import mongoengine
from models import User, UserKeys
from crypto_utils import crypto_manager
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

def debug_password_mismatch():
    """Debug the password validation vs DEK recovery issue"""
    print("🔍 DEBUGGING PASSWORD/DEK MISMATCH")
    print("=" * 50)
    
    try:
        # Connect to MongoDB
        if not setup_mongodb():
            return False
        
        # Find user sachin
        user = User.objects(username='sachin').first()
        if not user:
            print("❌ User 'sachin' not found")
            return False
        
        print(f"✅ Found user: {user.username}")
        print(f"   User ID: {user.id}")
        
        # Get user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print("❌ User keys not found")
            return False
        
        print(f"✅ Found user keys (version: {user_keys.key_version})")
        
        # Test different passwords
        test_passwords = [
            "Test1234*",      # Current known password
            "test1234*",      # lowercase
            "TEST1234*",      # uppercase
            "Test1234",       # without *
            "Test1234!",      # with !
        ]
        
        print("\n🧪 TESTING PASSWORD VALIDATION")
        print("-" * 30)
        
        valid_passwords = []
        
        for password in test_passwords:
            is_valid = check_password_hash(user.password_hash, password)
            print(f"Password '{password}': {'✅ VALID' if is_valid else '❌ INVALID'}")
            if is_valid:
                valid_passwords.append(password)
        
        if not valid_passwords:
            print("\n❌ No valid passwords found!")
            return False
        
        print(f"\n✅ Found {len(valid_passwords)} valid password(s)")
        
        # Test DEK recovery with each valid password
        print("\n🧪 TESTING DEK RECOVERY")
        print("-" * 30)
        
        successful_dek_recoveries = []
        
        for password in valid_passwords:
            print(f"\nTesting DEK recovery with: '{password}'")
            try:
                dek = crypto_manager.recover_dek_with_password(user_keys, password)
                print(f"✅ DEK recovery SUCCESS! DEK length: {len(dek)} bytes")
                successful_dek_recoveries.append(password)
            except Exception as e:
                print(f"❌ DEK recovery FAILED: {e}")
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 SUMMARY")
        print("-" * 20)
        print(f"Valid passwords (hash check): {len(valid_passwords)}")
        print(f"Successful DEK recoveries: {len(successful_dek_recoveries)}")
        
        if len(valid_passwords) > 0 and len(successful_dek_recoveries) == 0:
            print("\n🚨 ISSUE IDENTIFIED:")
            print("   Password validation passes but DEK recovery fails")
            print("   This suggests a problem with the P-DEK or recovery process")
            
            # Additional diagnostics
            print("\n🔍 ADDITIONAL DIAGNOSTICS")
            print("-" * 30)
            
            password = valid_passwords[0]
            print(f"Using password: '{password}'")
            
            # Check P-DEK structure
            import json
            import base64
            
            p_dek_data = user_keys.password_encrypted_key
            try:
                key_data = json.loads(p_dek_data)
                salt = base64.urlsafe_b64decode(key_data['salt'].encode())
                encrypted_data = key_data['encrypted']
                
                print(f"P-DEK salt: {key_data['salt']}")
                print(f"P-DEK encrypted data: {encrypted_data[:50]}...")
                
                # Test password key derivation
                password_key, _ = crypto_manager.derive_key_from_password(password, salt)
                print(f"Derived password key: {password_key[:50]}...")
                
                # Test direct decryption
                try:
                    decrypted_dek_b64 = crypto_manager.decrypt_data(encrypted_data, password_key)
                    print(f"✅ Direct decryption works!")
                    print(f"   Decrypted DEK (b64): {decrypted_dek_b64[:50]}...")
                except Exception as e:
                    print(f"❌ Direct decryption fails: {e}")
                    
                    # Check if it's a key format issue
                    print("\n🔧 Testing key format fix...")
                    try:
                        # Try different key format
                        from cryptography.fernet import Fernet
                        
                        # Method 1: Use password_key directly
                        f = Fernet(password_key)
                        decoded_encrypted = base64.urlsafe_b64decode(encrypted_data.encode())
                        decrypted = f.decrypt(decoded_encrypted)
                        print(f"✅ Method 1 (direct key) works: {decrypted.decode()[:50]}...")
                        
                    except Exception as e2:
                        print(f"❌ Method 1 failed: {e2}")
                        
                        try:
                            # Method 2: Convert key format
                            raw_key = base64.urlsafe_b64decode(password_key.encode())
                            fernet_key = base64.urlsafe_b64encode(raw_key)
                            f = Fernet(fernet_key)
                            decoded_encrypted = base64.urlsafe_b64decode(encrypted_data.encode())
                            decrypted = f.decrypt(decoded_encrypted)
                            print(f"✅ Method 2 (converted key) works: {decrypted.decode()[:50]}...")
                            
                        except Exception as e3:
                            print(f"❌ Method 2 failed: {e3}")
                            
            except Exception as e:
                print(f"❌ P-DEK analysis failed: {e}")
            
            return False
            
        elif len(successful_dek_recoveries) > 0:
            print("\n✅ SYSTEM WORKING CORRECTLY")
            print("   Both password validation and DEK recovery work")
            return True
        else:
            print("\n❌ BOTH SYSTEMS FAILING")
            print("   Neither password validation nor DEK recovery work")
            return False
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = debug_password_mismatch()
    
    if success:
        print("\n🎉 DEBUG COMPLETE - SYSTEM OK")
    else:
        print("\n🚨 DEBUG COMPLETE - ISSUE FOUND")
        print("Check the analysis above for details")
