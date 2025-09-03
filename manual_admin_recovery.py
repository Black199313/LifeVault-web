#!/usr/bin/env python3
"""
Manual admin user recovery test - simulates admin panel password reset
"""

import os
import sys
import json
import base64
from datetime import datetime
sys.path.append('.')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

import mongoengine
from models import User, UserKeys
from crypto_utils import crypto_manager
from werkzeug.security import check_password_hash, generate_password_hash

def setup_mongodb():
    """Setup MongoDB connection"""
    mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
    mongodb_db = os.environ.get("MONGODB_DB", "lifevault")
    
    try:
        mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
        print(f"✅ MongoDB connected")
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

def manual_admin_password_reset(target_username, new_password, admin_password):
    """
    Manually perform admin password reset (simulates admin panel functionality)
    
    This is what happens when admin resets a user's password via the web interface:
    1. Admin provides their password for verification
    2. System uses A-DEK to recover user's current DEK
    3. System updates user's password hash
    4. System creates new P-DEK with new password
    5. User can login with new password, keeping all their data
    """
    print(f"🔧 MANUAL ADMIN PASSWORD RESET")
    print(f"Target user: {target_username}")
    print(f"New password: {new_password}")
    print("-" * 40)
    
    try:
        # Step 1: Find users
        user = User.objects(username=target_username).first()
        admin = User.objects(username='admin').first()
        
        if not user or not admin:
            raise ValueError("User or admin not found")
        
        print(f"✅ Target user: {user.username} (ID: {user.id})")
        print(f"✅ Admin user: {admin.username}")
        
        # Step 2: Verify admin password
        if not check_password_hash(admin.password_hash, admin_password):
            raise ValueError("Invalid admin password")
        
        print(f"✅ Admin password verified")
        
        # Step 3: Get user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys or not user_keys.admin_master_encrypted_key:
            raise ValueError("User keys or A-DEK not found")
        
        print(f"✅ User keys found (version: {user_keys.key_version})")
        print(f"✅ A-DEK exists: {len(user_keys.admin_master_encrypted_key)} chars")
        
        # Step 4: Recover user's DEK using A-DEK
        print(f"\n🔐 Recovering user's DEK using admin access...")
        
        # Get admin master key using admin password hash
        admin_master_key = crypto_manager.get_or_create_admin_master_key(
            admin_password_hash=admin.password_hash
        )
        print(f"✅ Admin master key obtained: {len(admin_master_key)} bytes")
        
        # Decrypt A-DEK to get user's DEK
        a_dek_data = user_keys.admin_master_encrypted_key
        
        if a_dek_data.startswith('{'):
            # JSON format
            parsed_data = json.loads(a_dek_data)
            encrypted_a_dek = parsed_data['encrypted']
            print(f"✅ Using JSON format A-DEK")
        else:
            # Direct format
            encrypted_a_dek = a_dek_data
            print(f"✅ Using direct format A-DEK")
        
        # Decrypt to get user's DEK
        dek_b64 = crypto_manager.decrypt_data(encrypted_a_dek, admin_master_key)
        user_dek = base64.urlsafe_b64decode(dek_b64.encode())
        print(f"✅ User DEK recovered: {len(user_dek)} bytes")
        
        # Step 5: Update user's password hash
        print(f"\n🔧 Updating user password...")
        user.password_hash = generate_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        user.force_password_change = False
        user.save()
        print(f"✅ Password hash updated")
        
        # Step 6: Create new P-DEK with new password
        print(f"🔧 Creating new P-DEK with new password...")
        password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
        password_encrypted_dek = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(user_dek).decode(),
            password_key
        )
        
        # Update P-DEK in JSON format
        user_keys.password_encrypted_key = json.dumps({
            'encrypted': password_encrypted_dek,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        user_keys.save()
        print(f"✅ New P-DEK created and saved")
        
        print(f"\n🎉 ADMIN PASSWORD RESET COMPLETE!")
        print(f"✅ User '{target_username}' password reset to '{new_password}'")
        print(f"✅ User's data is preserved (same DEK)")
        print(f"✅ Admin still has access via A-DEK")
        
        return True
        
    except Exception as e:
        print(f"❌ Admin password reset failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_recovered_login(username, password):
    """Test that the user can now login with the new password"""
    print(f"\n🧪 TESTING RECOVERED LOGIN")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print("-" * 30)
    
    try:
        # Find user
        user = User.objects(username=username).first()
        if not user:
            print(f"❌ User not found")
            return False
        
        # Test password validation
        if check_password_hash(user.password_hash, password):
            print(f"✅ Password validation: SUCCESS")
        else:
            print(f"❌ Password validation: FAILED")
            return False
        
        # Test DEK recovery
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print(f"❌ User keys not found")
            return False
        
        dek = crypto_manager.recover_dek_with_password(user_keys, password)
        print(f"✅ DEK recovery: SUCCESS ({len(dek)} bytes)")
        
        # Simulate session creation (like in login route)
        dek_hex = dek.hex()
        print(f"✅ Session DEK created: {len(dek_hex)} chars")
        
        print(f"\n🎉 USER LOGIN FULLY RECOVERED!")
        print(f"✅ User can login successfully")
        print(f"✅ User can access their encrypted data")
        
        return True
        
    except Exception as e:
        print(f"❌ Login test failed: {e}")
        return False

if __name__ == "__main__":
    print("🔐 ADMIN USER LOGIN RECOVERY")
    print("=" * 50)
    print("This simulates admin resetting a user's password via the admin panel")
    print()
    
    # Connect to database
    if not setup_mongodb():
        sys.exit(1)
    
    # Test parameters
    target_username = "sachin"
    
    # Get admin password
    print("📝 Admin authentication:")
    admin_password = input("Enter admin password: ").strip()
    
    if not admin_password:
        print("❌ Admin password required")
        sys.exit(1)
    
    # Get new password for user
    print(f"\n📝 New password for user '{target_username}':")
    new_password = input("Enter new password: ").strip()
    
    if not new_password or len(new_password) < 8:
        print("❌ Password must be at least 8 characters")
        sys.exit(1)
    
    print(f"\n🚀 STARTING ADMIN RECOVERY PROCESS")
    print("=" * 50)
    
    # Perform admin password reset
    reset_success = manual_admin_password_reset(target_username, new_password, admin_password)
    
    if reset_success:
        # Test the recovered login
        login_success = test_recovered_login(target_username, new_password)
        
        if login_success:
            print(f"\n" + "🎉" * 20)
            print("ADMIN USER RECOVERY SUCCESSFUL!")
            print("🎉" * 20)
            print()
            print(f"✅ Admin successfully reset user's password")
            print(f"✅ User can now login with: {new_password}")
            print(f"✅ User's encrypted data is preserved")
            print(f"✅ Admin retains access via A-DEK")
            print()
            print("💡 This is exactly what happens in the web interface!")
            print("💡 Start the app and use Admin → Users → Reset Password")
        else:
            print(f"\n❌ Password reset succeeded but login test failed")
    else:
        print(f"\n❌ Admin password reset failed")
        print("Check the error messages above for details")
