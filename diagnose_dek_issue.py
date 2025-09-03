#!/usr/bin/env python3
"""
Diagnose DEK recovery failure for user 'sachin'
"""

import os
import sys
import json
import base64
sys.path.append('.')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

import mongoengine
from models import User, UserKeys
from crypto_utils import crypto_manager
from cryptography.fernet import Fernet

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

def analyze_user_keys():
    """Analyze user keys and P-DEK structure"""
    print("🔍 ANALYZING DEK RECOVERY ISSUE")
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
        
        print(f"✅ Found user: {user.username} (ID: {user.id})")
        
        # Get user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print("❌ User keys not found")
            return False
        
        print(f"✅ Found user keys (version: {user_keys.key_version})")
        
        # Analyze P-DEK data structure
        print("\n🔍 ANALYZING P-DEK DATA")
        print("-" * 30)
        
        p_dek_data = user_keys.password_encrypted_key
        print(f"P-DEK data length: {len(p_dek_data)}")
        print(f"P-DEK data preview: {p_dek_data[:100]}...")
        
        # Check if it's JSON format
        is_json = False
        try:
            parsed_json = json.loads(p_dek_data)
            is_json = True
            print("✅ P-DEK is in JSON format")
            print(f"   JSON keys: {list(parsed_json.keys())}")
            
            if 'salt' in parsed_json:
                salt_b64 = parsed_json['salt']
                print(f"   Salt (base64): {salt_b64}")
                try:
                    salt = base64.urlsafe_b64decode(salt_b64.encode())
                    print(f"   Salt length: {len(salt)} bytes")
                except Exception as e:
                    print(f"   ❌ Invalid salt encoding: {e}")
            
            if 'encrypted' in parsed_json:
                encrypted_data = parsed_json['encrypted']
                print(f"   Encrypted data length: {len(encrypted_data)}")
                print(f"   Encrypted data preview: {encrypted_data[:50]}...")
                
        except json.JSONDecodeError:
            print("🔍 P-DEK is NOT in JSON format")
            if ':' in p_dek_data:
                parts = p_dek_data.split(':', 1)
                print(f"   Colon-separated format: {len(parts)} parts")
                if len(parts) == 2:
                    salt_b64, encrypted_data = parts
                    print(f"   Salt part: {salt_b64}")
                    print(f"   Encrypted part: {encrypted_data[:50]}...")
                    
                    try:
                        salt = base64.urlsafe_b64decode(salt_b64.encode())
                        print(f"   Salt length: {len(salt)} bytes")
                    except Exception as e:
                        print(f"   ❌ Invalid salt encoding: {e}")
            else:
                print("   ❌ Unknown format (no colon separator)")
        
        # Test password recovery manually
        print("\n🧪 MANUAL DEK RECOVERY TEST")
        print("-" * 30)
        
        # Get password from user
        print("📝 Please enter the user's password:")
        password = input("Password for 'sachin': ").strip()
        
        if not password:
            print("❌ No password provided")
            return False
        
        # Manual recovery attempt
        try:
            if is_json:
                print("🔍 Testing JSON format recovery...")
                key_data = json.loads(p_dek_data)
                salt = base64.urlsafe_b64decode(key_data['salt'].encode())
                encrypted_data = key_data['encrypted']
                
                print(f"   Salt: {len(salt)} bytes")
                print(f"   Encrypted data: {len(encrypted_data)} chars")
                
                # Derive password key
                password_key, _ = crypto_manager.derive_key_from_password(password, salt)
                print(f"   Password key derived: {len(password_key)} bytes")
                
                # Test decryption with decrypt_data method
                try:
                    decrypted_dek_b64 = crypto_manager.decrypt_data(encrypted_data, password_key)
                    print(f"✅ decrypt_data() worked! DEK (b64): {decrypted_dek_b64[:50]}...")
                    
                    # Decode to final DEK
                    final_dek = base64.urlsafe_b64decode(decrypted_dek_b64.encode())
                    print(f"✅ Final DEK: {len(final_dek)} bytes")
                    return True
                    
                except Exception as e:
                    print(f"❌ decrypt_data() failed: {e}")
                    print("   Trying direct Fernet decryption...")
                    
                    # Try direct Fernet approach
                    try:
                        f = Fernet(password_key)
                        decoded_encrypted = base64.urlsafe_b64decode(encrypted_data.encode())
                        decrypted = f.decrypt(decoded_encrypted)
                        decrypted_dek_b64 = decrypted.decode()
                        print(f"✅ Direct Fernet worked! DEK (b64): {decrypted_dek_b64[:50]}...")
                        
                        final_dek = base64.urlsafe_b64decode(decrypted_dek_b64.encode())
                        print(f"✅ Final DEK: {len(final_dek)} bytes")
                        
                        print("\n🔧 ISSUE IDENTIFIED:")
                        print("   The decrypt_data() method is incompatible with the encrypted data format")
                        print("   Direct Fernet decryption works correctly")
                        return True
                        
                    except Exception as e2:
                        print(f"❌ Direct Fernet also failed: {e2}")
                        
                        # Check if the password_key format is wrong
                        print("\n🔍 Checking password key format...")
                        print(f"   Password key length: {len(password_key)}")
                        print(f"   Password key type: {type(password_key)}")
                        
                        if isinstance(password_key, str):
                            print("   Converting string key to bytes...")
                            try:
                                raw_key = base64.urlsafe_b64decode(password_key.encode())
                                if len(raw_key) != 32:
                                    print(f"   ❌ Key length wrong: {len(raw_key)} (should be 32)")
                                else:
                                    print(f"   ✅ Key length correct: {len(raw_key)} bytes")
                                    f = Fernet(base64.urlsafe_b64encode(raw_key))
                                    decoded_encrypted = base64.urlsafe_b64decode(encrypted_data.encode())
                                    decrypted = f.decrypt(decoded_encrypted)
                                    decrypted_dek_b64 = decrypted.decode()
                                    print(f"✅ Fixed key format worked! DEK: {decrypted_dek_b64[:50]}...")
                                    return True
                            except Exception as e3:
                                print(f"   ❌ Key conversion failed: {e3}")
            else:
                print("🔍 Testing colon format recovery...")
                parts = p_dek_data.split(':', 1)
                if len(parts) != 2:
                    print("❌ Invalid colon format")
                    return False
                
                salt_b64, encrypted_data = parts
                salt = base64.urlsafe_b64decode(salt_b64.encode())
                
                # Derive password key
                password_key, _ = crypto_manager.derive_key_from_password(password, salt)
                
                # For old format, use direct Fernet
                raw_password_key = base64.urlsafe_b64decode(password_key.encode())
                f = Fernet(base64.urlsafe_b64encode(raw_password_key))
                decrypted = f.decrypt(encrypted_data.encode())
                decrypted_dek_b64 = decrypted.decode()
                
                final_dek = base64.urlsafe_b64decode(decrypted_dek_b64.encode())
                print(f"✅ Colon format recovery worked! DEK: {len(final_dek)} bytes")
                return True
                
        except Exception as e:
            print(f"❌ Manual recovery failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = analyze_user_keys()
    
    if success:
        print("\n🎉 DIAGNOSIS COMPLETE")
        print("✅ Found the issue and potential fix")
    else:
        print("\n❌ DIAGNOSIS FAILED")
        print("Need further investigation")
