#!/usr/bin/env python3
"""
Create test user for A-DEK finalization testing
"""

import os
import sys
import base64
from werkzeug.security import generate_password_hash

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mongoengine
from models import User, UserKeys
from crypto_utils import CryptoManager

def setup_test_user():
    """Create test user with all necessary keys"""
    try:
        mongoengine.connect('lifevault_test', host='localhost', port=27017)
        print("✅ Connected to MongoDB")
        
        crypto_manager = CryptoManager()
        
        # Check if test user already exists
        existing_user = User.objects(username='testuser').first()
        if existing_user:
            print("✅ Test user already exists")
            return existing_user
        
        # Create test user
        user = User(
            username='testuser',
            email='test@example.com',
            password_hash=generate_password_hash('Test1234*'),
            is_active=True
        )
        user.save()
        print(f"✅ Created test user: {user.username}")
        
        # Generate a DEK for the user
        user_dek = crypto_manager.generate_key()  # This generates a Fernet key
        user_dek_b64 = base64.urlsafe_b64encode(user_dek).decode()
        
        # Create temporary password encryption for A-DEK
        temp_password = "Test1234*"
        temp_key, _ = crypto_manager.derive_key_from_password(temp_password)
        a_dek_temp_encrypted = crypto_manager.encrypt_data(user_dek_b64, temp_key)
        
        # Create user keys
        user_keys = UserKeys(
            user=user,
            admin_master_encrypted_key=a_dek_temp_encrypted  # Start with temp password encryption
        )
        user_keys.save()
        print(f"✅ Created user keys with temporary A-DEK encryption")
        
        return user
        
    except Exception as e:
        print(f"❌ Failed to create test user: {e}")
        return None

if __name__ == "__main__":
    user = setup_test_user()
    if user:
        print(f"✅ Test user setup complete: {user.id}")
    else:
        print("❌ Test user setup failed")
        sys.exit(1)
