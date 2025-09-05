#!/usr/bin/env python3
"""
Quick diagnostic to check what's not working
"""

import os
import sys
import base64
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
        print(f"✅ MongoDB connected")
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

def test_user_login():
    """Test user login functionality"""
    print("🔐 TESTING USER LOGIN")
    print("-" * 30)
    
    username = "sachin"
    password = "Test1234*"
    
    try:
        user = User.objects(username=username).first()
        if not user:
            print(f"❌ User '{username}' not found")
            return False
        
        print(f"✅ User found: {user.username}")
        
        # Test password validation
        if check_password_hash(user.password_hash, password):
            print(f"✅ Password validation: SUCCESS")
        else:
            print(f"❌ Password validation: FAILED")
            return False
        
        # Test DEK recovery
        try:
            user_keys = crypto_manager.get_user_keys(str(user.id))
            if not user_keys:
                print(f"❌ User keys not found")
                return False
            
            dek = crypto_manager.recover_dek_with_password(user_keys, password)
            print(f"✅ DEK recovery: SUCCESS ({len(dek)} bytes)")
            return True
            
        except Exception as e:
            print(f"❌ DEK recovery: FAILED - {e}")
            return False
        
    except Exception as e:
        print(f"❌ Login test failed: {e}")
        return False

def test_admin_recovery():
    """Test admin recovery functionality"""
    print("\n🔐 TESTING ADMIN RECOVERY")
    print("-" * 30)
    
    try:
        # Find user and admin
        user = User.objects(username='sachin').first()
        admin = User.objects(username='admin').first()
        
        if not user or not admin:
            print(f"❌ Missing user or admin")
            return False
        
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys or not user_keys.admin_master_encrypted_key:
            print(f"❌ No A-DEK found")
            return False
        
        print(f"✅ A-DEK exists: {len(user_keys.admin_master_encrypted_key)} chars")
        
        # Test admin password
        admin_password = "Admin1234"
        if check_password_hash(admin.password_hash, admin_password):
            print(f"✅ Admin password validation: SUCCESS")
        else:
            print(f"❌ Admin password validation: FAILED")
            return False
        
        # Test admin master key retrieval
        try:
            admin_master_key = crypto_manager.get_or_create_admin_master_key(
                admin_password_hash=admin.password_hash
            )
            print(f"✅ Admin master key: SUCCESS ({len(admin_master_key)} bytes)")
        except Exception as e:
            print(f"❌ Admin master key: FAILED - {e}")
            return False
        
        # Test A-DEK decryption
        try:
            a_dek_data = user_keys.admin_master_encrypted_key
            
            if a_dek_data.startswith('{'):
                import json
                parsed_data = json.loads(a_dek_data)
                encrypted_a_dek = parsed_data['encrypted']
            else:
                encrypted_a_dek = a_dek_data
            
            dek_b64 = crypto_manager.decrypt_data(encrypted_a_dek, admin_master_key)
            recovered_dek = base64.urlsafe_b64decode(dek_b64.encode())
            print(f"✅ A-DEK decryption: SUCCESS ({len(recovered_dek)} bytes)")
            return True
            
        except Exception as e:
            print(f"❌ A-DEK decryption: FAILED - {e}")
            return False
        
    except Exception as e:
        print(f"❌ Admin recovery test failed: {e}")
        return False

def check_application_startup():
    """Check if the Flask application can start properly"""
    print("\n🚀 TESTING APPLICATION STARTUP")
    print("-" * 30)
    
    try:
        # Try importing the main app
        from app import app
        print(f"✅ App import: SUCCESS")
        
        # Check app configuration
        with app.app_context():
            print(f"✅ App context: SUCCESS")
            print(f"   Debug mode: {app.debug}")
            print(f"   Secret key set: {'Yes' if app.secret_key else 'No'}")
            
        return True
        
    except Exception as e:
        print(f"❌ App startup failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🔍 COMPREHENSIVE SYSTEM DIAGNOSTIC")
    print("=" * 50)
    
    # Connect to database
    if not setup_mongodb():
        print("❌ Cannot proceed without database connection")
        sys.exit(1)
    
    # Test 1: User login
    login_ok = test_user_login()
    
    # Test 2: Admin recovery
    admin_ok = test_admin_recovery()
    
    # Test 3: Application startup
    app_ok = check_application_startup()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 DIAGNOSTIC SUMMARY")
    print("-" * 20)
    print(f"User Login:      {'✅ OK' if login_ok else '❌ FAILED'}")
    print(f"Admin Recovery:  {'✅ OK' if admin_ok else '❌ FAILED'}")
    print(f"App Startup:     {'✅ OK' if app_ok else '❌ FAILED'}")
    
    if all([login_ok, admin_ok, app_ok]):
        print("\n🎉 ALL SYSTEMS OPERATIONAL!")
        print("If something is 'not working', please specify what you're trying to do.")
    else:
        print("\n🚨 ISSUES DETECTED!")
        print("Check the error messages above for details.")
        
        if not login_ok:
            print("💡 Try running: python fix_user_login.py")
        if not admin_ok:
            print("💡 Check admin password and A-DEK setup")
        if not app_ok:
            print("💡 Check app.py and requirements")
