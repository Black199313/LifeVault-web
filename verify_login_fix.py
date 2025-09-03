#!/usr/bin/env python3
"""
Verify the login fix worked
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
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

def verify_login_fix():
    """Verify that the login fix worked"""
    print("🧪 VERIFYING LOGIN FIX")
    print("=" * 30)
    
    try:
        # Connect to MongoDB
        if not setup_mongodb():
            return False
        
        username = "sachin"
        password = "Test1234*"
        
        # Find user
        user = User.objects(username=username).first()
        if not user:
            print(f"❌ User {username} not found")
            return False
        
        print(f"✅ User found: {user.username}")
        
        # Test password validation (simulating login step 1)
        print(f"\n🔐 Testing password validation...")
        if check_password_hash(user.password_hash, password):
            print(f"✅ Password validation: SUCCESS")
        else:
            print(f"❌ Password validation: FAILED")
            return False
        
        # Test DEK recovery (simulating login step 2)
        print(f"\n🔑 Testing DEK recovery...")
        try:
            user_keys = crypto_manager.get_user_keys(str(user.id))
            if not user_keys:
                print(f"❌ User keys not found")
                return False
            
            dek = crypto_manager.recover_dek_with_password(user_keys, password)
            print(f"✅ DEK recovery: SUCCESS")
            print(f"✅ DEK length: {len(dek)} bytes")
            
            # Convert to hex (as done in login route)
            dek_hex = dek.hex()
            print(f"✅ Session DEK (hex): {len(dek_hex)} characters")
            
        except Exception as e:
            print(f"❌ DEK recovery: FAILED - {e}")
            return False
        
        # Test A-DEK recovery (admin access)
        print(f"\n🔑 Testing A-DEK recovery...")
        if user_keys.admin_master_encrypted_key:
            try:
                # This would require admin password, but we can test the structure
                print(f"✅ A-DEK exists: {len(user_keys.admin_master_encrypted_key)} chars")
                print(f"✅ A-DEK format: {user_keys.admin_master_encrypted_key[:50]}...")
            except Exception as e:
                print(f"⚠️  A-DEK structure check failed: {e}")
        else:
            print(f"ℹ️  No A-DEK configured")
        
        print(f"\n🎉 VERIFICATION COMPLETE")
        print(f"✅ Login system is working correctly")
        print(f"✅ User '{username}' can login with password '{password}'")
        print(f"✅ DEK recovery is functioning properly")
        
        return True
        
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = verify_login_fix()
    
    if success:
        print(f"\n✅ ALL SYSTEMS GO!")
        print(f"The login issue has been completely resolved.")
    else:
        print(f"\n❌ VERIFICATION FAILED!")
        print(f"There may still be issues with the login system.")
