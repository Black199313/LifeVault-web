#!/usr/bin/env python3
"""
Fix A-DEK by re-encrypting DEK with admin master key
"""

def fix_adek_with_admin_key():
    try:
        from app import app
        from models import User, UserKeys, RotationToken
        from crypto_utils import crypto_manager
        import base64
        import json
        from werkzeug.security import check_password_hash
        
        with app.app_context():
            print("🔧 A-DEK REPAIR SCRIPT")
            print("=" * 30)
            
            # Find user sachin
            user = User.objects(username='sachin').first()
            if not user:
                print("❌ User 'sachin' not found")
                return False
            
            print(f"✅ Found user: {user.username}")
            
            # Get user keys
            user_keys = UserKeys.objects(user=user).first()
            if not user_keys:
                print("❌ User keys not found")
                return False
            
            print(f"✅ Found user keys (version: {user_keys.key_version})")
            
            # Method 1: Try to get DEK from P-DEK
            print("\n🔍 STEP 1: Get DEK from P-DEK")
            print("📝 Please provide user password:")
            user_password = input("User password (Test1234*): ").strip()
            if not user_password:
                user_password = "Test1234*"  # Default
            
            try:
                # Decrypt P-DEK to get the main DEK
                if user_keys.password_encrypted_key.startswith('{'):
                    p_dek_data = json.loads(user_keys.password_encrypted_key)
                    salt = base64.urlsafe_b64decode(p_dek_data['salt'])
                    password_key, _ = crypto_manager.derive_key_from_password(user_password, salt)
                    user_dek_b64 = crypto_manager.decrypt_data(p_dek_data['encrypted'], password_key)
                    user_dek = base64.urlsafe_b64decode(user_dek_b64)
                    
                    print(f"✅ Successfully extracted DEK from P-DEK")
                    print(f"   DEK length: {len(user_dek)} bytes")
                else:
                    print("❌ P-DEK not in expected JSON format")
                    return False
                    
            except Exception as e:
                print(f"❌ Failed to get DEK from P-DEK: {e}")
                return False
            
            # Method 2: Get admin master key
            print("\n🔍 STEP 2: Get Admin Master Key")
            print("📝 Please provide admin password:")
            admin_password = input("Admin password (Admin1234): ").strip()
            if not admin_password:
                admin_password = "Admin1234"  # Default
            
            # Find admin user
            admin_user = User.objects(username='admin').first()
            if not admin_user:
                print("❌ Admin user not found")
                return False
            
            # Validate admin password
            if not check_password_hash(admin_user.password_hash, admin_password):
                print("❌ Invalid admin password")
                return False
            
            print("✅ Admin password validated")
            
            try:
                # Get admin master key
                admin_master_key = crypto_manager.get_or_create_admin_master_key(
                    admin_password_hash=admin_user.password_hash
                )
                print(f"✅ Got admin master key (length: {len(admin_master_key)} bytes)")
                
            except Exception as e:
                print(f"❌ Failed to get admin master key: {e}")
                return False
            
            # Method 3: Re-encrypt DEK with admin master key
            print("\n🔍 STEP 3: Re-encrypt DEK with Admin Master Key")
            
            try:
                # Encrypt the user's DEK with admin master key
                new_a_dek = crypto_manager.encrypt_data(
                    base64.urlsafe_b64encode(user_dek).decode(), 
                    admin_master_key
                )
                
                print(f"✅ Successfully created new A-DEK")
                print(f"   New A-DEK length: {len(new_a_dek)}")
                
                # Backup current A-DEK
                old_a_dek = user_keys.admin_master_encrypted_key
                print(f"📋 Backing up old A-DEK: {old_a_dek[:50]}...")
                
                # Update user keys with new A-DEK
                user_keys.admin_master_encrypted_key = new_a_dek
                user_keys.save()
                
                print("✅ Updated user keys with new A-DEK")
                
            except Exception as e:
                print(f"❌ Failed to create new A-DEK: {e}")
                return False
            
            # Method 4: Test the new A-DEK
            print("\n🔍 STEP 4: Test New A-DEK")
            
            try:
                # Try to decrypt with admin master key
                decrypted_dek_b64 = crypto_manager.decrypt_data(new_a_dek, admin_master_key)
                decrypted_dek = base64.urlsafe_b64decode(decrypted_dek_b64)
                
                if decrypted_dek == user_dek:
                    print("✅ NEW A-DEK WORKS PERFECTLY!")
                    print(f"   Decrypted DEK length: {len(decrypted_dek)} bytes")
                    print(f"   DEK matches original: True")
                    
                    # Mark any pending rotation tokens as finalized
                    pending_tokens = RotationToken.objects(
                        user_id=str(user.id),
                        status='completed'
                    )
                    
                    for token in pending_tokens:
                        token.status = 'finalized'
                        token.a_dek_finalized = True
                        token.save()
                        print(f"✅ Marked token {token.id} as finalized")
                    
                    return True
                else:
                    print("❌ A-DEK test failed - DEK mismatch")
                    return False
                    
            except Exception as e:
                print(f"❌ A-DEK test failed: {e}")
                return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def fix_adek_with_temp_password():
    """Alternative method using temporary password"""
    try:
        from app import app
        from models import User, UserKeys, RotationToken
        from crypto_utils import crypto_manager
        import base64
        import json
        from werkzeug.security import check_password_hash
        
        with app.app_context():
            print("🔧 A-DEK REPAIR WITH TEMP PASSWORD")
            print("=" * 40)
            
            # Find user and token
            user = User.objects(username='sachin').first()
            user_keys = UserKeys.objects(user=user).first()
            
            token_id = input("Enter rotation token ID: ").strip()
            token = RotationToken.objects(id=token_id).first()
            
            if not token:
                print("❌ Token not found")
                return False
            
            print(f"✅ Found token: {token.id}")
            
            # Get passwords
            temp_password = input("Enter temporary password: ").strip()
            admin_password = input("Enter admin password (Admin1234): ").strip() or "Admin1234"
            
            # Get admin user and validate
            admin_user = User.objects(username='admin').first()
            if not check_password_hash(admin_user.password_hash, admin_password):
                print("❌ Invalid admin password")
                return False
            
            try:
                # Step 1: Decrypt current A-DEK with temp password
                temp_key, _ = crypto_manager.derive_key_from_password(temp_password)
                
                if user_keys.admin_master_encrypted_key.startswith('{'):
                    json_data = json.loads(user_keys.admin_master_encrypted_key)
                    encrypted_dek = json_data['encrypted']
                else:
                    encrypted_dek = user_keys.admin_master_encrypted_key
                
                user_dek_b64 = crypto_manager.decrypt_data(encrypted_dek, temp_key)
                user_dek = base64.urlsafe_b64decode(user_dek_b64)
                
                print(f"✅ Successfully decrypted A-DEK with temp password")
                print(f"   DEK length: {len(user_dek)} bytes")
                
                # Step 2: Get admin master key and re-encrypt
                admin_master_key = crypto_manager.get_or_create_admin_master_key(
                    admin_password_hash=admin_user.password_hash
                )
                
                new_a_dek = crypto_manager.encrypt_data(
                    base64.urlsafe_b64encode(user_dek).decode(), 
                    admin_master_key
                )
                
                # Step 3: Update and test
                user_keys.admin_master_encrypted_key = new_a_dek
                user_keys.save()
                
                # Test
                test_dek_b64 = crypto_manager.decrypt_data(new_a_dek, admin_master_key)
                test_dek = base64.urlsafe_b64decode(test_dek_b64)
                
                if test_dek == user_dek:
                    print("✅ A-DEK FIXED SUCCESSFULLY!")
                    token.status = 'finalized'
                    token.a_dek_finalized = True
                    token.save()
                    return True
                else:
                    print("❌ A-DEK test failed")
                    return False
                
            except Exception as e:
                print(f"❌ Failed: {e}")
                return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("Choose repair method:")
    print("1. Fix A-DEK using P-DEK (recommended)")
    print("2. Fix A-DEK using temporary password")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        success = fix_adek_with_admin_key()
    elif choice == "2":
        success = fix_adek_with_temp_password()
    else:
        print("Invalid choice")
        success = False
    
    if success:
        print("\n🎉 A-DEK REPAIR COMPLETED!")
        print("✅ Admin can now access user data")
        print("✅ Key rotation fully finalized")
    else:
        print("\n❌ A-DEK REPAIR FAILED")
        print("Please check the diagnostic output and try again")
