#!/usr/bin/env python3
"""
Check the user's password and try to recover DEK
"""

import os
import sys
import json
import base64
import getpass
import mongoengine
from werkzeug.security import check_password_hash

# Add the parent directory to Python path so we can import modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ Environment variables loaded from .env file")
except ImportError:
    print("⚠️ python-dotenv not installed, using system environment variables")

# Initialize MongoDB connection
mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
mongodb_db = os.environ.get("MONGODB_DB", "lifevault")

try:
    mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
    print(f"✅ MongoDB connection configured for database: {mongodb_db}")
except Exception as e:
    print(f"❌ Failed to configure MongoDB connection: {str(e)}")
    sys.exit(1)

from models import User, UserKeys
from crypto_utils import CryptoManager

def main():
    username = "sachin"
    
    # Find user
    user = User.objects(username=username).first()
    if not user:
        print(f"❌ User '{username}' not found")
        return
    
    print(f"✅ Found user: {user.username}")
    print(f"🔍 Password hash: {user.password_hash[:50]}...")
    
    # Get user keys
    user_keys = UserKeys.objects(user=user).first()
    if not user_keys:
        print("❌ User keys not found")
        return
    
    print(f"✅ User keys found, version: {user_keys.key_version}")
    
    # Try to guess the password
    test_passwords = [
        "Test1234&",
        "password123", 
        "admin123",
        "test123",
        "sachin123",
        "sachin",
        "Sachin123",
        "Sachin1234",
        "Test123",
        "Test1234",
        # Add any other passwords you might have used
    ]
    
    print(f"\n🔍 Testing password hash against common passwords...")
    
    for password in test_passwords:
        if check_password_hash(user.password_hash, password):
            print(f"✅ PASSWORD FOUND: '{password}'")
            
            # Now test if this password can decrypt the P-DEK
            crypto_manager = CryptoManager()
            try:
                recovered_dek = crypto_manager.recover_dek_with_password(user_keys, password)
                print(f"✅ P-DEK WORKS: DEK recovered with password '{password}', length: {len(recovered_dek)} bytes")
                return password
            except Exception as e:
                print(f"❌ P-DEK BROKEN: Password '{password}' matches hash but cannot decrypt P-DEK: {str(e)}")
                return password
    
    print(f"❌ No matching password found in test list")
    
    # Interactive password testing
    print(f"\n🔧 Manual password testing:")
    while True:
        try:
            test_password = getpass.getpass("Enter password to test (or 'quit' to exit): ")
            if test_password.lower() == 'quit':
                break
                
            # Test password hash
            if check_password_hash(user.password_hash, test_password):
                print(f"✅ PASSWORD HASH MATCH: '{test_password}'")
                
                # Test P-DEK
                crypto_manager = CryptoManager()
                try:
                    recovered_dek = crypto_manager.recover_dek_with_password(user_keys, test_password)
                    print(f"✅ P-DEK WORKS: DEK recovered, length: {len(recovered_dek)} bytes")
                    return test_password
                except Exception as e:
                    print(f"❌ P-DEK BROKEN: Cannot decrypt P-DEK: {str(e)}")
                    return test_password
            else:
                print(f"❌ Password hash does not match")
                
        except KeyboardInterrupt:
            print(f"\n👋 Goodbye!")
            break
    
    return None

if __name__ == "__main__":
    main()
