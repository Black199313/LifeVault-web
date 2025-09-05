#!/usr/bin/env python3
"""
Test admin recovery of user login through password reset
This simulates what happens when admin resets a user's password via the admin panel
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
from admin_escrow import AdminKeyEscrow
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

def test_admin_password_reset():
    """Test admin password reset functionality"""
    print("🔐 TESTING ADMIN PASSWORD RESET FOR USER RECOVERY")
    print("=" * 60)
    
    try:
        # Connect to MongoDB
        if not setup_mongodb():
            return False
        
        # Find the user we want to reset
        target_username = "sachin"
        user = User.objects(username=target_username).first()
        if not user:
            print(f"❌ User '{target_username}' not found")
            return False
        
        print(f"✅ Target user found: {user.username} (ID: {user.id})")
        
        # Find admin user
        admin = User.objects(username='admin').first()
        if not admin:
            print("❌ Admin user not found")
            return False
        
        print(f"✅ Admin user found: {admin.username}")
        
        # Get admin credentials
        print("\n📝 Admin authentication required:")
        admin_password = input("Enter admin password: ").strip()
        
        if not admin_password:
            print("❌ Admin password required")
            return False
        
        # Validate admin password
        if not check_password_hash(admin.password_hash, admin_password):
            print("❌ Invalid admin password")
            return False
        
        print("✅ Admin authenticated")
        
        # Get new password for user
        print(f"\n📝 New password for user '{target_username}':")
        new_password = input("Enter new password for user: ").strip()
        
        if not new_password or len(new_password) < 8:
            print("❌ Password must be at least 8 characters long")
            return False
        
        # Test the admin password reset process
        print(f"\n🔄 PERFORMING ADMIN PASSWORD RESET")
        print("-" * 40)
        
        try:
            # Initialize admin escrow manager
            admin_escrow = AdminKeyEscrow()
            
            # Perform the reset
            print(f"🔧 Resetting password for user '{target_username}'...")
            success = admin_escrow.admin_password_reset_with_escrow(
                str(user.id), 
                new_password, 
                admin_password
            )
            
            if success:
                print(f"✅ PASSWORD RESET SUCCESSFUL!")
                print(f"   User: {target_username}")
                print(f"   New password: {new_password}")
                print(f"   Reset by admin: {admin.username}")
            else:
                print(f"❌ Password reset failed")
                return False
                
        except Exception as e:
            print(f"❌ Password reset failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Test the new login credentials
        print(f"\n🧪 TESTING NEW LOGIN CREDENTIALS")
        print("-" * 40)
        
        try:
            # Refresh user data
            user_updated = User.objects(username=target_username).first()
            
            # Test password validation
            if check_password_hash(user_updated.password_hash, new_password):
                print(f"✅ Password validation: SUCCESS")
            else:
                print(f"❌ Password validation: FAILED")
                return False
            
            # Test DEK recovery
            user_keys = UserKeys.objects(user=user_updated).first()
            if not user_keys:
                print(f"❌ User keys not found")
                return False
            
            recovered_dek = crypto_manager.recover_dek_with_password(user_keys, new_password)
            print(f"✅ DEK recovery: SUCCESS ({len(recovered_dek)} bytes)")
            
            # Verify A-DEK still works (admin can still access user data)
            print(f"\n🔍 VERIFYING A-DEK STILL WORKS")
            print("-" * 30)
            
            if user_keys.admin_master_encrypted_key:
                try:
                    admin_master_key = crypto_manager.get_or_create_admin_master_key_with_password(admin_password)
                    
                    a_dek_data = user_keys.admin_master_encrypted_key
                    if a_dek_data.startswith('{'):
                        parsed_data = json.loads(a_dek_data)
                        encrypted_a_dek = parsed_data['encrypted']
                    else:
                        encrypted_a_dek = a_dek_data
                    
                    dek_b64 = crypto_manager.decrypt_data(encrypted_a_dek, admin_master_key)
                    admin_recovered_dek = base64.urlsafe_b64decode(dek_b64.encode())
                    
                    if admin_recovered_dek == recovered_dek:
                        print(f"✅ A-DEK verification: SUCCESS (DEKs match)")
                    else:
                        print(f"❌ A-DEK verification: FAILED (DEK mismatch)")
                        return False
                        
                except Exception as e:
                    print(f"❌ A-DEK verification: FAILED - {e}")
                    return False
            else:
                print(f"ℹ️  No A-DEK configured")
            
            return True
            
        except Exception as e:
            print(f"❌ Login test failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def simulate_web_interface():
    """Simulate what happens in the web interface"""
    print("\n" + "=" * 60)
    print("🌐 WEB INTERFACE SIMULATION")
    print("=" * 60)
    print("This is what would happen in the admin panel:")
    print()
    print("1. Admin logs into admin panel with their password")
    print("2. Admin navigates to 'Users' section")
    print("3. Admin finds the user who needs password reset")
    print("4. Admin clicks 'Reset Password' button")
    print("5. Admin enters:")
    print("   - New password for the user")
    print("   - Admin's own password for verification")
    print("6. System performs admin password reset")
    print("7. User can now login with the new password")
    print()
    print("The process preserves:")
    print("✅ User's encrypted data (DEK remains the same)")
    print("✅ Admin access via A-DEK")
    print("✅ Other recovery methods (if configured)")

if __name__ == "__main__":
    print("🔐 ADMIN USER RECOVERY TEST")
    print("Testing admin's ability to recover user login access")
    print()
    
    # Test the admin password reset functionality
    success = test_admin_password_reset()
    
    if success:
        print("\n🎉 ADMIN USER RECOVERY SUCCESSFUL!")
        print("=" * 50)
        print("✅ Admin can reset user passwords")
        print("✅ User login is recoverable via admin")
        print("✅ User data remains accessible")
        print("✅ Admin access is preserved")
        
        # Show web interface info
        simulate_web_interface()
        
        print("\n💡 TO USE IN WEB INTERFACE:")
        print("1. Start the app: python main.py")
        print("2. Login as admin")
        print("3. Go to Admin → Users")
        print("4. Find the user and click 'Reset Password'")
        
    else:
        print("\n❌ ADMIN USER RECOVERY FAILED!")
        print("Check the error messages above for details")
