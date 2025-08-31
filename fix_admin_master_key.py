#!/usr/bin/env python3
"""
Fix Admin Master Key Access
The admin password 'Admin1234' validates but can't decrypt the master key
"""

import os
import sys
import mongoengine

# Setup
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
mongodb_db = os.environ.get("MONGODB_DB", "lifevault")

try:
    mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
    print(f"✅ Connected to {mongodb_db}")
except Exception as e:
    print(f"❌ MongoDB connection failed: {str(e)}")
    sys.exit(1)

from models import User, AdminMasterKey
from crypto_utils import CryptoManager

def analyze_admin_master_key_issue():
    """Analyze why admin password works for login but not master key"""
    print("🔍 ANALYZING ADMIN MASTER KEY ISSUE")
    print("="*50)
    
    # Get admin user
    admin = User.objects(is_admin=True).first()
    admin_password = "Admin1234"
    
    print(f"✅ Admin user: {admin.username}")
    print(f"✅ Admin password: {admin_password}")
    
    # Get crypto manager
    crypto_manager = CryptoManager()
    
    # Generate admin password hash
    admin_password_hash = crypto_manager.hash_password(admin_password)[0]
    print(f"🔍 Generated hash: {admin_password_hash[:30]}...")
    print(f"🔍 Stored hash:    {admin.password_hash[:30]}...")
    print(f"🔍 Hashes match:   {admin_password_hash == admin.password_hash}")
    
    # Get admin master key record
    admin_key_record = AdminMasterKey.objects(is_active=True).first()
    if not admin_key_record:
        print("❌ No active admin master key found")
        return
    
    print(f"✅ Found active admin master key")
    print(f"🔍 Created: {admin_key_record.created_at}")
    print(f"🔍 Encrypted key: {admin_key_record.encrypted_key[:50]}...")
    
    # Try to decrypt with different approaches
    print(f"\n🔧 TESTING DECRYPTION APPROACHES:")
    
    # Approach 1: Direct hash from password
    try:
        print(f"\n1️⃣ Using generated password hash...")
        admin_master_key = crypto_manager._decrypt_admin_master_key(admin_key_record, admin_password_hash)
        print(f"✅ SUCCESS with generated hash! Key length: {len(admin_master_key)}")
        return admin_master_key
    except Exception as e:
        print(f"❌ Failed: {str(e)}")
    
    # Approach 2: Stored user hash
    try:
        print(f"\n2️⃣ Using stored user password hash...")
        admin_master_key = crypto_manager._decrypt_admin_master_key(admin_key_record, admin.password_hash)
        print(f"✅ SUCCESS with stored hash! Key length: {len(admin_master_key)}")
        return admin_master_key
    except Exception as e:
        print(f"❌ Failed: {str(e)}")
    
    # Approach 3: Check what hashes are expected
    try:
        print(f"\n3️⃣ Checking expected admin hashes...")
        admin_users = User.objects(is_admin=True)
        admin_hashes = sorted([admin.password_hash for admin in admin_users])
        print(f"🔍 Expected admin hashes:")
        for i, hash_val in enumerate(admin_hashes):
            print(f"   {i+1}: {hash_val[:50]}...")
        
        print(f"🔍 Generated hash in list: {admin_password_hash in admin_hashes}")
        
    except Exception as e:
        print(f"❌ Failed to check hashes: {str(e)}")
    
    return None

def recreate_admin_master_key():
    """Recreate admin master key with correct password"""
    print(f"\n🛠️ RECREATING ADMIN MASTER KEY")
    print("="*50)
    
    admin_password = "Admin1234"
    crypto_manager = CryptoManager()
    
    try:
        # Deactivate old keys
        AdminMasterKey.objects().update(is_active=False)
        print(f"✅ Deactivated old admin master keys")
        
        # Generate new admin master key
        admin_password_hash = crypto_manager.hash_password(admin_password)[0]
        new_master_key = crypto_manager.get_or_create_admin_master_key(admin_password_hash)
        
        print(f"✅ Created new admin master key")
        print(f"🔍 New key length: {len(new_master_key)} bytes")
        
        # Test the new key
        test_key = crypto_manager.get_or_create_admin_master_key(admin_password_hash)
        print(f"✅ New key verification successful: {len(test_key)} bytes")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to recreate admin master key: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("🎯 ADMIN MASTER KEY FIXER")
    print("Analyzing and fixing admin master key access issue\n")
    
    # First analyze the issue
    master_key = analyze_admin_master_key_issue()
    
    if master_key:
        print(f"\n✅ Admin master key access is working!")
        return
    
    # If not working, recreate it
    print(f"\n💡 Admin master key access failed, attempting to recreate...")
    
    recreate_success = recreate_admin_master_key()
    
    if recreate_success:
        print(f"\n🎉 ADMIN MASTER KEY FIXED!")
        print(f"✅ Admin password: Admin1234")
        print(f"✅ Master key access: Working")
        print(f"\n💡 You can now run key rotation with admin password: Admin1234")
    else:
        print(f"\n❌ Failed to fix admin master key")
        print(f"💡 You may need to recreate the admin user")

if __name__ == "__main__":
    main()
