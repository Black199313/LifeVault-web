#!/usr/bin/env python3
"""
Key Rotation Diagnostic Suite
Identifies specific credential issues preventing key rotation
"""

import os
import sys
import json
import base64
import getpass
import mongoengine
from werkzeug.security import check_password_hash

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

from models import User, UserKeys, AdminMasterKey
from crypto_utils import CryptoManager

def diagnose_admin_credentials():
    """Find what admin password actually works"""
    print("\n" + "="*60)
    print("🔍 DIAGNOSING ADMIN CREDENTIALS")
    print("="*60)
    
    # Find admin user
    admin = User.objects(is_admin=True).first()
    if not admin:
        print("❌ No admin user found")
        return None
    
    print(f"✅ Found admin: {admin.username}")
    print(f"🔍 Password hash: {admin.password_hash[:50]}...")
    
    # Test common passwords
    test_passwords = [
        "admin123", "Admin123", "ADMIN123",
        "password", "Password", "PASSWORD", 
        "Test1234&", "Test1234*", "Test1234!",
        "lifevault", "LifeVault", "admin",
        "secret", "123456", "admin1234"
    ]
    
    print(f"\n🔧 Testing {len(test_passwords)} common passwords...")
    
    for password in test_passwords:
        if check_password_hash(admin.password_hash, password):
            print(f"✅ ADMIN PASSWORD FOUND: '{password}'")
            
            # Test if this password can decrypt admin master key
            try:
                crypto_manager = CryptoManager()
                admin_password_hash = crypto_manager.hash_password(password)[0]
                admin_master_key = crypto_manager.get_or_create_admin_master_key(admin_password_hash)
                print(f"✅ ADMIN MASTER KEY WORKS: Length {len(admin_master_key)} bytes")
                return password
            except Exception as e:
                print(f"❌ ADMIN MASTER KEY BROKEN: {str(e)}")
                return password
    
    print(f"❌ No common password worked")
    
    # Interactive testing
    while True:
        try:
            password = getpass.getpass("Enter admin password to test (or 'skip' to continue): ")
            if password.lower() == 'skip':
                break
                
            if check_password_hash(admin.password_hash, password):
                print(f"✅ PASSWORD HASH MATCH: '{password}'")
                
                try:
                    crypto_manager = CryptoManager()
                    admin_password_hash = crypto_manager.hash_password(password)[0]
                    admin_master_key = crypto_manager.get_or_create_admin_master_key(admin_password_hash)
                    print(f"✅ ADMIN MASTER KEY WORKS: Length {len(admin_master_key)} bytes")
                    return password
                except Exception as e:
                    print(f"❌ ADMIN MASTER KEY BROKEN: {str(e)}")
                    return password
            else:
                print(f"❌ Password hash does not match")
                
        except KeyboardInterrupt:
            break
    
    return None

def diagnose_user_edek(username):
    """Find what email password works for E-DEK"""
    print("\n" + "="*60)
    print(f"🔍 DIAGNOSING E-DEK FOR USER: {username}")
    print("="*60)
    
    # Find user
    user = User.objects(username=username).first()
    if not user:
        print(f"❌ User '{username}' not found")
        return None
    
    user_keys = UserKeys.objects(user=user).first()
    if not user_keys or not user_keys.email_encrypted_key:
        print(f"❌ No E-DEK found for user '{username}'")
        return None
    
    print(f"✅ Found E-DEK for {username}")
    
    # Parse E-DEK data
    try:
        edek_data = json.loads(user_keys.email_encrypted_key)
        print(f"✅ E-DEK format: {list(edek_data.keys())}")
        print(f"🔍 E-DEK encrypted: {edek_data['encrypted'][:50]}...")
        if 'salt' in edek_data:
            print(f"🔍 E-DEK salt: {edek_data['salt']}")
    except Exception as e:
        print(f"❌ Failed to parse E-DEK: {str(e)}")
        return None
    
    # Test common email passwords
    test_passwords = [
        "Xi9V7BxPSVChKUwx",  # From test output
        "password123", "email123", "recovery123",
        "Test1234&", "Test1234*", "admin123"
    ]
    
    print(f"\n🔧 Testing {len(test_passwords)} common email passwords...")
    
    crypto_manager = CryptoManager()
    
    for password in test_passwords:
        try:
            recovered_dek = crypto_manager.recover_dek_with_email_password(user_keys, password)
            print(f"✅ EMAIL PASSWORD FOUND: '{password}'")
            print(f"✅ E-DEK WORKS: DEK recovered, length {len(recovered_dek)} bytes")
            return password
        except Exception as e:
            print(f"❌ '{password}' failed: {str(e)[:50]}...")
    
    print(f"❌ No common email password worked")
    
    # Interactive testing
    while True:
        try:
            password = input("Enter email password to test (or 'skip' to continue): ")
            if password.lower() == 'skip':
                break
                
            try:
                recovered_dek = crypto_manager.recover_dek_with_email_password(user_keys, password)
                print(f"✅ EMAIL PASSWORD FOUND: '{password}'")
                print(f"✅ E-DEK WORKS: DEK recovered, length {len(recovered_dek)} bytes")
                return password
            except Exception as e:
                print(f"❌ '{password}' failed: {str(e)}")
                
        except KeyboardInterrupt:
            break
    
    return None

def diagnose_admin_master_key_storage():
    """Check admin master key storage format and integrity"""
    print("\n" + "="*60)
    print("🔍 DIAGNOSING ADMIN MASTER KEY STORAGE")
    print("="*60)
    
    # Check AdminMasterKey records
    admin_keys = AdminMasterKey.objects().order_by('-created_at')
    
    if not admin_keys:
        print("❌ No AdminMasterKey records found")
        return
    
    print(f"✅ Found {len(admin_keys)} AdminMasterKey records")
    
    for i, key_record in enumerate(admin_keys):
        print(f"\n🔍 AdminMasterKey #{i+1}:")
        print(f"   ID: {key_record.id}")
        print(f"   Active: {key_record.is_active}")
        print(f"   Created: {key_record.created_at}")
        print(f"   Encrypted key: {key_record.encrypted_key[:50]}...")
        if hasattr(key_record, 'version'):
            print(f"   Version: {key_record.version}")
        if hasattr(key_record, 'key_id'):
            print(f"   Key ID: {key_record.key_id}")
        
        if key_record.is_active:
            print(f"   👑 This is the ACTIVE admin master key")
            
            # Check admin users who should have access
            admin_users = User.objects(is_admin=True)
            print(f"   🔍 Admin users with access:")
            for admin in admin_users:
                print(f"      - {admin.username}: {admin.password_hash[:30]}...")

def diagnose_token_validation():
    """Check rotation token format and validation"""
    print("\n" + "="*60)
    print("🔍 DIAGNOSING TOKEN VALIDATION")
    print("="*60)
    
    from models import RotationToken
    
    # Find recent rotation tokens
    tokens = RotationToken.objects().order_by('-created_at').limit(5)
    
    if not tokens:
        print("❌ No rotation tokens found")
        return
    
    print(f"✅ Found {len(tokens)} recent rotation tokens")
    
    for i, token in enumerate(tokens):
        print(f"\n🔍 RotationToken #{i+1}:")
        print(f"   User ID: {token.user_id}")
        print(f"   Status: {token.status}")
        print(f"   Created: {token.created_at}")
        print(f"   Expires: {token.expires_at}")
        print(f"   Token hash: {token.token_hash[:20]}...")
        if hasattr(token, 'token_value') and token.token_value:
            print(f"   Token value: {token.token_value[:20]}...")
        print(f"   Temp password hash: {token.temporary_password_hash[:20]}...")

def main():
    print("🎯 KEY ROTATION DIAGNOSTIC SUITE")
    print("This will identify specific credential issues preventing key rotation\n")
    
    username = input("Enter username to diagnose: ").strip() or "sachin"
    
    # Run all diagnostics
    admin_password = diagnose_admin_credentials()
    email_password = diagnose_user_edek(username)
    diagnose_admin_master_key_storage()
    diagnose_token_validation()
    
    # Summary
    print("\n" + "="*60)
    print("📊 DIAGNOSTIC SUMMARY")
    print("="*60)
    
    print(f"✅ User: {username}")
    if admin_password:
        print(f"✅ Admin password: {admin_password}")
    else:
        print(f"❌ Admin password: NOT FOUND")
    
    if email_password:
        print(f"✅ Email password: {email_password}")
    else:
        print(f"❌ Email password: NOT FOUND")
    
    print(f"\n💡 RECOMMENDATIONS:")
    if not admin_password:
        print(f"   1. Fix admin password or recreate admin master key")
    if not email_password:
        print(f"   2. Fix email password or recreate E-DEK")
    if admin_password and email_password:
        print(f"   1. Run key rotation test with correct credentials")
        print(f"   2. Test web interface key rotation")

if __name__ == "__main__":
    main()
