#!/usr/bin/env python3
"""
Debug A-DEK format and try different decryption methods
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

def debug_adek_format():
    """Debug A-DEK format and decryption"""
    
    print("🔍 A-DEK FORMAT DEBUG")
    print("=" * 40)
    
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
        
        # Examine A-DEK data
        a_dek_data = user_keys.admin_master_encrypted_key
        print(f"\n🔍 A-DEK DATA ANALYSIS:")
        print(f"Type: {type(a_dek_data)}")
        print(f"Length: {len(str(a_dek_data))}")
        print(f"First 200 chars: {str(a_dek_data)[:200]}")
        
        # Check if it's JSON
        try:
            if isinstance(a_dek_data, str):
                parsed = json.loads(a_dek_data)
                print(f"✅ A-DEK is JSON format")
                print(f"Keys: {list(parsed.keys())}")
                if 'salt' in parsed:
                    print(f"Has salt: {parsed['salt'][:20]}...")
                if 'encrypted' in parsed:
                    print(f"Has encrypted: {parsed['encrypted'][:20]}...")
            else:
                print("❌ A-DEK is not JSON string")
        except:
            print("❌ A-DEK is not valid JSON")
        
        # Try to find admin user
        admin_user = User.objects(is_admin=True).first()
        if not admin_user:
            print("❌ Admin user not found")
            return False
        
        print(f"✅ Found admin user: {admin_user.username}")
        
        # Verify admin password
        if not check_password_hash(admin_user.password_hash, admin_password):
            print("❌ Admin password verification failed")
            return False
        
        print("✅ Admin password verified")
        
        # Try different decryption methods
        print(f"\n🧪 TRYING DIFFERENT DECRYPTION METHODS:")
        
        # Method 1: Standard admin master key decryption
        try:
            print("🔍 Method 1: Standard admin master key...")
            admin_master_key = crypto.get_or_create_admin_master_key(admin_user.password_hash)
            print(f"   Admin master key length: {len(admin_master_key)}")
            
            # Try direct decryption
            a_dek_b64 = crypto.decrypt_data(a_dek_data, admin_master_key)
            a_dek = base64.b64decode(a_dek_b64)
            print(f"   ✅ Method 1 SUCCESS: A-DEK length {len(a_dek)}")
            return a_dek
            
        except Exception as e:
            print(f"   ❌ Method 1 failed: {e}")
        
        # Method 2: Check if it's salt-based format
        try:
            print("🔍 Method 2: Salt-based format...")
            if isinstance(a_dek_data, str):
                try:
                    parsed = json.loads(a_dek_data)
                    if 'salt' in parsed and 'encrypted' in parsed:
                        print("   Found salt-based format")
                        salt = base64.b64decode(parsed['salt'])
                        encrypted = parsed['encrypted']
                        
                        # Try with admin password directly
                        a_dek = crypto.decrypt_with_password(a_dek_data, admin_password)
                        print(f"   ✅ Method 2 SUCCESS: A-DEK length {len(a_dek)}")
                        return a_dek
                    
                except json.JSONDecodeError:
                    print("   Not JSON format")
            
        except Exception as e:
            print(f"   ❌ Method 2 failed: {e}")
        
        # Method 3: Try old format direct password decryption
        try:
            print("🔍 Method 3: Legacy password decryption...")
            
            # Try to decrypt with admin password directly 
            if isinstance(a_dek_data, str):
                # Might be base64 encoded
                try:
                    encrypted_bytes = base64.b64decode(a_dek_data)
                    print(f"   Decoded as base64, length: {len(encrypted_bytes)}")
                    
                    # This won't work without proper salt, but let's see the error
                    from cryptography.fernet import Fernet
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    
                    # This is just diagnostic
                    print(f"   Data appears to be raw encrypted bytes")
                    
                except Exception as decode_e:
                    print(f"   Not base64: {decode_e}")
            
        except Exception as e:
            print(f"   ❌ Method 3 failed: {e}")
        
        print("\n❌ All decryption methods failed")
        return None
        
    except Exception as e:
        print(f"❌ General error: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    debug_adek_format()
