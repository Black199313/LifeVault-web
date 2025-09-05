#!/usr/bin/env python3
"""
Debug A-DEK storage and recovery after key rotation
"""

import os
import sys
import base64
import mongoengine

# Add the parent directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

mongoengine.connect('lifevault', host='localhost', port=27017)

from models import User, UserKeys
from crypto_utils import CryptoManager

def debug_adek_recovery():
    """Debug A-DEK recovery issue"""
    
    username = 'sachin'
    admin_password = 'Admin1234'
    
    crypto_manager = CryptoManager()
    
    print("🔍 A-DEK Recovery Debug")
    print("=" * 30)
    
    # Get user
    user = User.objects(username=username).first()
    user_keys = UserKeys.objects(user=user).first()
    
    print(f"User: {user.username}")
    print(f"Key version: {user_keys.key_version}")
    
    # Check A-DEK format
    adek = user_keys.admin_master_encrypted_key
    print(f"\nA-DEK info:")
    print(f"  Type: {type(adek)}")
    print(f"  Length: {len(adek) if adek else 'None'}")
    print(f"  Content: {adek[:50] if adek else 'None'}...")
    
    # Get admin user and master key
    admin = User.objects(username='admin').first()
    print(f"\nAdmin user found: {admin.username if admin else 'None'}")
    
    try:
        admin_master_key = crypto_manager.get_or_create_admin_master_key(
            admin_password_hash=admin.password_hash
        )
        print(f"Admin master key length: {len(admin_master_key)} bytes")
        
        # Try to decrypt A-DEK manually
        print(f"\nTrying manual A-DEK decryption...")
        decrypted_dek_b64 = crypto_manager.decrypt_data(adek, admin_master_key)
        decrypted_dek = base64.urlsafe_b64decode(decrypted_dek_b64)
        print(f"✅ Manual decryption successful, DEK length: {len(decrypted_dek)} bytes")
        
        # Try using the recovery method
        print(f"\nTrying recovery method...")
        recovered_dek = crypto_manager.recover_dek_with_admin_key(user_keys)
        print(f"✅ Recovery method successful, DEK length: {len(recovered_dek)} bytes")
        print(f"DEKs match: {decrypted_dek == recovered_dek}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_adek_recovery()
