#!/usr/bin/env python3
"""
Fix user 'sachin' login issue by resetting password and encryption keys
"""

import os
import sys
import json
import base64
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

import mongoengine
from models import User, UserKeys
from crypto_utils import crypto_manager
from werkzeug.security import generate_password_hash, check_password_hash

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

def fix_user_login(username, target_password):
    """Fix user login by resetting both password hash and encryption keys"""
    try:
        print(f"🔧 FIXING LOGIN FOR USER: {username}")
        print(f"🔧 Target password: {target_password}")
        print("=" * 50)
        
        # Connect to MongoDB
        if not setup_mongodb():
            return False
        
        # Find user
        user = User.objects(username=username).first()
        if not user:
            print(f"❌ User {username} not found")
            return False
        
        print(f"✅ User found: {user.username}")
        print(f"   User ID: {user.id}")
        
        # Step 1: Update user's password hash
        print(f"\n🔧 STEP 1: Updating password hash...")
        new_password_hash = generate_password_hash(target_password)
        user.password_hash = new_password_hash
        user.save()
        
        print(f"✅ Password hash updated")
        
        # Verify new password hash works
        if check_password_hash(user.password_hash, target_password):
            print(f"✅ Password hash verification: SUCCESS")
        else:
            print(f"❌ Password hash verification: FAILED")
            return False
        
        # Step 2: Reset encryption keys
        print(f"\n🔧 STEP 2: Resetting encryption keys...")
        
        # Find or create user keys
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            print(f"🔧 Creating new UserKeys for {username}")
            user_keys = UserKeys(user=user)
        else:
            print(f"🔧 Updating existing UserKeys for {username}")
            print(f"   Current key version: {user_keys.key_version}")
        
        # Generate a new DEK
        new_dek = crypto_manager.generate_key()
        print(f"✅ Generated new DEK: {len(new_dek)} bytes")
        
        # Create new P-DEK with the target password
        print(f"🔧 Creating new P-DEK...")
        password_key, password_salt = crypto_manager.derive_key_from_password(target_password)
        password_encrypted = crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), password_key)
        
        # Store in JSON format
        new_p_dek = json.dumps({
            'encrypted': password_encrypted,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        
        print(f"✅ P-DEK created, length: {len(new_p_dek)}")
        
        # Update user keys
        user_keys.password_encrypted_key = new_p_dek
        user_keys.key_version = (user_keys.key_version or 0) + 1
        user_keys.created_at = datetime.utcnow()
        
        # Clear other DEKs since they're invalid now (but keep A-DEK if it exists)
        user_keys.security_questions_encrypted_key = None
        user_keys.recovery_phrase_encrypted_key = None
        user_keys.time_lock_encrypted_key = None
        user_keys.email_encrypted_key = None
        
        # Note: Keep admin_master_encrypted_key if it exists
        if user_keys.admin_master_encrypted_key:
            print(f"⚠️  Keeping existing A-DEK (will be updated separately)")
        
        # Save user keys
        user_keys.save()
        
        print(f"✅ UserKeys updated successfully!")
        print(f"✅ New key version: {user_keys.key_version}")
        
        # Step 3: Test the fix
        print(f"\n🧪 STEP 3: Testing the fix...")
        
        # Test password validation
        print(f"Testing password validation...")
        user_refreshed = User.objects(username=username).first()
        if check_password_hash(user_refreshed.password_hash, target_password):
            print(f"✅ Password validation: SUCCESS")
        else:
            print(f"❌ Password validation: FAILED")
            return False
        
        # Test DEK recovery
        print(f"Testing DEK recovery...")
        try:
            user_keys_refreshed = UserKeys.objects(user=user).first()
            test_dek = crypto_manager.recover_dek_with_password(user_keys_refreshed, target_password)
            print(f"✅ DEK recovery: SUCCESS")
            print(f"✅ Recovered DEK length: {len(test_dek)} bytes")
            
            # Verify DEK matches
            if test_dek == new_dek:
                print(f"✅ DEK integrity: VERIFIED")
            else:
                print(f"❌ DEK integrity: FAILED")
                return False
                
        except Exception as e:
            print(f"❌ DEK recovery: FAILED - {e}")
            return False
        
        # Step 4: Update A-DEK if needed
        if user_keys.admin_master_encrypted_key:
            print(f"\n🔧 STEP 4: Updating A-DEK with new DEK...")
            try:
                # Get admin master key
                admin_user = User.objects(username='admin').first()
                if admin_user:
                    admin_master_key = crypto_manager.get_or_create_admin_master_key(
                        admin_password_hash=admin_user.password_hash
                    )
                    
                    # Encrypt new DEK with admin master key
                    new_a_dek = crypto_manager.encrypt_data(
                        base64.urlsafe_b64encode(new_dek).decode(), 
                        admin_master_key
                    )
                    
                    # Update A-DEK
                    user_keys.admin_master_encrypted_key = new_a_dek
                    user_keys.save()
                    
                    print(f"✅ A-DEK updated with new DEK")
                else:
                    print(f"⚠️  Admin user not found - A-DEK not updated")
                    
            except Exception as e:
                print(f"⚠️  A-DEK update failed: {e}")
                print(f"   (This is not critical - P-DEK is working)")
        
        print(f"\n✅ USER LOGIN FIX COMPLETE!")
        print(f"✅ User: {username}")
        print(f"✅ Password: {target_password}")
        print(f"✅ Both password validation and DEK recovery are working")
        
        return True
        
    except Exception as e:
        print(f"❌ Fix failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    username = "sachin"
    target_password = "Test1234*"
    
    print(f"🚨 USER LOGIN FIX TOOL")
    print(f"=" * 30)
    print(f"This will fix the login issue for user '{username}'")
    print(f"Target password: '{target_password}'")
    print(f"")
    print(f"⚠️  WARNING: This will reset the user's encryption keys!")
    print(f"⚠️  All existing secrets will be lost and need to be re-entered!")
    print(f"")
    
    # Proceed with fix
    success = fix_user_login(username, target_password)
    
    if success:
        print(f"\n🎉 SUCCESS!")
        print(f"✅ User '{username}' can now login with password '{target_password}'")
        print(f"✅ The DEK recovery issue has been resolved")
        print(f"")
        print(f"📝 NEXT STEPS:")
        print(f"1. Test login in the web application")
        print(f"2. Re-enter any important secrets/passwords")
        print(f"3. Set up recovery methods (security questions, recovery phrase)")
        print(f"4. Consider setting up email recovery")
    else:
        print(f"\n❌ FAILED!")
        print(f"The login issue could not be fixed automatically")
        print(f"Check the error messages above for details")
