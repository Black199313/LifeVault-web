#!/usr/bin/env python3
"""
Diagnostic script for A-DEK finalization issues
"""

def diagnose_adek_finalization():
    try:
        from app import app
        from models import User, UserKeys, RotationToken
        from crypto_utils import crypto_manager
        import base64
        import json
        
        with app.app_context():
            print("🔍 A-DEK FINALIZATION DIAGNOSTIC")
            print("=" * 50)
            
            # Find user sachin
            user = User.objects(username='sachin').first()
            if not user:
                print("❌ User 'sachin' not found")
                return
            
            print(f"✅ Found user: {user.username} (ID: {user.id})")
            
            # Get user keys
            user_keys = UserKeys.objects(user=user).first()
            if not user_keys:
                print("❌ User keys not found")
                return
            
            print(f"✅ Found user keys (version: {user_keys.key_version})")
            
            # Find latest completed rotation token
            completed_tokens = RotationToken.objects(
                user_id=str(user.id),
                status='completed'
            ).order_by('-created_at')
            
            if not completed_tokens:
                print("❌ No completed rotation tokens found")
                return
            
            token = completed_tokens.first()
            print(f"✅ Found completed token: {token.id}")
            print(f"   Status: {token.status}")
            print(f"   Stage: {token.rotation_stage}")
            print(f"   A-DEK finalized: {token.a_dek_finalized}")
            
            # Check current A-DEK format
            if user_keys.admin_master_encrypted_key:
                print(f"✅ A-DEK exists, length: {len(user_keys.admin_master_encrypted_key)}")
                print(f"   A-DEK preview: {user_keys.admin_master_encrypted_key[:50]}...")
                
                # Check if it's JSON format or direct encryption
                try:
                    json_data = json.loads(user_keys.admin_master_encrypted_key)
                    print("✅ A-DEK is in JSON format")
                    print(f"   Keys in JSON: {list(json_data.keys())}")
                except:
                    print("✅ A-DEK is in direct encryption format")
            else:
                print("❌ No A-DEK found")
                return
            
            # Test different decryption methods
            print("\n🧪 TESTING A-DEK DECRYPTION")
            print("-" * 30)
            
            # Method 1: Try with temp password from token
            if hasattr(token, 'temporary_password_hash'):
                print("🔍 Testing with various temporary passwords...")
                
                # Common temp passwords to try
                temp_passwords = []
                
                # Ask user for temp password
                print("\n📝 Please provide the temporary password for this rotation:")
                temp_password = input("Temporary password: ").strip()
                if temp_password:
                    temp_passwords.append(temp_password)
                
                for i, temp_pass in enumerate(temp_passwords, 1):
                    try:
                        print(f"\n🧪 Test {i}: Temp password '{temp_pass[:8]}...'")
                        temp_key, _ = crypto_manager.derive_key_from_password(temp_pass)
                        
                        if user_keys.admin_master_encrypted_key.startswith('{'):
                            # JSON format
                            json_data = json.loads(user_keys.admin_master_encrypted_key)
                            encrypted_dek = json_data['encrypted']
                        else:
                            # Direct format
                            encrypted_dek = user_keys.admin_master_encrypted_key
                        
                        user_dek_b64 = crypto_manager.decrypt_data(encrypted_dek, temp_key)
                        user_dek = base64.urlsafe_b64decode(user_dek_b64)
                        
                        print(f"✅ SUCCESS! Decrypted DEK with temp password")
                        print(f"   DEK length: {len(user_dek)} bytes")
                        
                        return {
                            'success': True,
                            'temp_password': temp_pass,
                            'dek_length': len(user_dek),
                            'token_id': str(token.id),
                            'user_id': str(user.id)
                        }
                        
                    except Exception as e:
                        print(f"❌ Failed: {str(e)}")
                        continue
            
            # Method 2: Try with P-DEK approach
            print("\n🔍 Testing P-DEK approach...")
            print("📝 Please provide user password:")
            user_password = input("User password: ").strip()
            
            if user_password:
                try:
                    # Get P-DEK
                    if user_keys.password_encrypted_key.startswith('{'):
                        p_dek_data = json.loads(user_keys.password_encrypted_key)
                        salt = base64.urlsafe_b64decode(p_dek_data['salt'])
                        password_key, _ = crypto_manager.derive_key_from_password(user_password, salt)
                        user_dek_b64 = crypto_manager.decrypt_data(p_dek_data['encrypted'], password_key)
                        user_dek = base64.urlsafe_b64decode(user_dek_b64)
                        
                        print(f"✅ Successfully got DEK from P-DEK")
                        print(f"   DEK length: {len(user_dek)} bytes")
                        
                        return {
                            'success': True,
                            'method': 'p_dek',
                            'dek_length': len(user_dek),
                            'user_password': user_password,
                            'user_id': str(user.id)
                        }
                        
                except Exception as e:
                    print(f"❌ P-DEK approach failed: {str(e)}")
            
            print("\n❌ ALL METHODS FAILED")
            return {'success': False, 'error': 'Could not decrypt A-DEK'}
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': str(e)}

if __name__ == "__main__":
    result = diagnose_adek_finalization()
    
    if result.get('success'):
        print("\n🎉 DIAGNOSTIC SUCCESSFUL!")
        print("✅ A-DEK can be decrypted and fixed")
    else:
        print("\n❌ DIAGNOSTIC FAILED")
        print("Need more information to fix A-DEK")
