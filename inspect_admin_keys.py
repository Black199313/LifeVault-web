#!/usr/bin/env python3
"""
Admin Master Key Inspector
Shows how admin master keys are stored in the database
"""

import os
import sys
import mongoengine
from models import AdminMasterKey, User
from datetime import datetime
import base64
import hashlib

# Connect to MongoDB
mongoengine.connect('lifevault', host='mongodb://localhost:27017/lifevault', connect=False)

def inspect_admin_master_keys():
    """Inspect all admin master keys in the database"""
    print("🔑 ADMIN MASTER KEY DATABASE INSPECTION")
    print("=" * 60)
    
    # Get all admin master keys
    all_keys = AdminMasterKey.objects.all().order_by('-created_at')
    
    if not all_keys:
        print("❌ No admin master keys found in database!")
        return
        
    print(f"📊 Found {len(all_keys)} admin master key(s) in database:\n")
    
    for i, key in enumerate(all_keys, 1):
        print(f"🔑 Admin Master Key #{i}")
        print(f"   ID: {key.id}")
        print(f"   Key Hash: {key.key_hash}")
        print(f"   Encrypted Key: {key.encrypted_key}")
        print(f"   Created By: {key.created_by_admin.username if key.created_by_admin else 'Unknown'}")
        print(f"   Created At: {key.created_at}")
        print(f"   Is Active: {'✅ Yes' if key.is_active else '❌ No'}")
        print(f"   Approval Count: {key.approval_count}")
        print(f"   Required Approvals: {key.required_approvals}")
        
        if key.approved_by:
            print(f"   Approved By: {len(key.approved_by)} admin(s)")
            for approval in key.approved_by:
                print(f"     - Admin ID: {approval.admin_id} at {approval.approved_at}")
        
        # Decode the key to show its structure
        try:
            decoded_key = base64.urlsafe_b64decode(key.encrypted_key.encode())
            print(f"   Decoded Key Length: {len(decoded_key)} bytes")
            print(f"   Key Preview: {decoded_key[:16].hex()}... (showing first 16 bytes)")
        except Exception as e:
            print(f"   ❌ Failed to decode key: {str(e)}")
        
        print()

def show_key_generation_process():
    """Show how admin master keys are generated"""
    print("🔧 ADMIN MASTER KEY GENERATION PROCESS")
    print("=" * 60)
    
    # Get first admin user
    admin_user = User.objects(is_admin=True, is_active=True).first()
    
    if not admin_user:
        print("❌ No active admin users found!")
        return
        
    print(f"👤 Using admin user: {admin_user.username}")
    print(f"📧 Admin email: {admin_user.email}")
    print(f"🔐 Password hash: {admin_user.password_hash[:20]}...")
    
    # Show how the key would be generated
    timestamp = datetime.utcnow()
    combined_data = f"admin_master_{admin_user.password_hash}_{timestamp.isoformat()}"
    master_key = hashlib.sha256(combined_data.encode()).digest()
    key_hash = hashlib.sha256(master_key).hexdigest()
    encrypted_key = base64.urlsafe_b64encode(master_key).decode()
    
    print(f"\n🔧 Key Generation Details:")
    print(f"   Combined Data: admin_master_{admin_user.password_hash[:10]}..._{timestamp.isoformat()}")
    print(f"   Master Key (32 bytes): {master_key.hex()}")
    print(f"   Key Hash (SHA256): {key_hash}")
    print(f"   Encrypted Key (Base64): {encrypted_key}")
    
    print(f"\n💾 Database Storage Structure:")
    print(f"   - key_hash: SHA256 hash of the actual key")
    print(f"   - encrypted_key: Base64 encoded actual key")
    print(f"   - created_by_admin: Reference to admin user")
    print(f"   - is_active: Boolean flag for key status")
    print(f"   - created_at: Timestamp of key creation")

def show_current_active_key():
    """Show the currently active admin master key"""
    print("🎯 CURRENT ACTIVE ADMIN MASTER KEY")
    print("=" * 60)
    
    active_key = AdminMasterKey.objects(is_active=True).first()
    
    if not active_key:
        print("❌ No active admin master key found!")
        return
        
    print(f"✅ Active Key Found:")
    print(f"   ID: {active_key.id}")
    print(f"   Created By: {active_key.created_by_admin.username}")
    print(f"   Created At: {active_key.created_at}")
    print(f"   Key Hash: {active_key.key_hash}")
    print(f"   Age: {datetime.utcnow() - active_key.created_at}")
    
    # Try to reconstruct the key using the method
    try:
        from crypto_utils import CryptoManager
        crypto_manager = CryptoManager()
        current_key = crypto_manager.get_or_create_admin_master_key()
        print(f"   Reconstructed Key: {current_key.hex()}")
        print(f"   Key Length: {len(current_key)} bytes")
        
        # Verify the hash matches
        reconstructed_hash = hashlib.sha256(current_key).hexdigest()
        hash_matches = reconstructed_hash == active_key.key_hash
        print(f"   Hash Verification: {'✅ Match' if hash_matches else '❌ Mismatch'}")
        
    except Exception as e:
        print(f"   ❌ Failed to reconstruct key: {str(e)}")

if __name__ == "__main__":
    print("🔍 ADMIN MASTER KEY INSPECTION TOOL")
    print("=" * 60)
    
    while True:
        print("\nSelect an option:")
        print("1. Inspect all admin master keys")
        print("2. Show key generation process")
        print("3. Show current active key")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            inspect_admin_master_keys()
        elif choice == '2':
            show_key_generation_process()
        elif choice == '3':
            show_current_active_key()
        elif choice == '4':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please try again.")
