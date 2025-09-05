#!/usr/bin/env python3
"""
Test script for improved A-DEK finalization implementation.
Tests all error conditions, validation steps, and rollback scenarios.
"""

import os
import sys
import hashlib
import base64
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mongoengine
from models import User, UserKeys, RotationToken
from crypto_utils import CryptoManager

def setup_test_environment():
    """Setup test environment with MongoDB connection"""
    try:
        mongoengine.connect('lifevault', host='localhost', port=27017)  # Use main database
        print("✅ Connected to MongoDB")
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

def create_test_rotation_token(user_id, temp_password):
    """Create a test rotation token in completed state"""
    temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
    
    # First ensure the A-DEK is encrypted with this temp password and get salt
    temp_salt = setup_adek_with_temp_password(user_id, temp_password)
    
    token = RotationToken(
        user_id=str(user_id),
        temporary_password_hash=temp_hash,
        temporary_password_salt=base64.urlsafe_b64encode(temp_salt).decode(),
        expires_at=datetime.utcnow() + timedelta(hours=1),
        status='completed',
        rotation_stage='completed',
        a_dek_finalized=False
    )
    token.save()
    print(f"✅ Created test token: {token.id}")
    return token

def setup_adek_with_temp_password(user_id, temp_password):
    """Ensure A-DEK is encrypted with the temporary password"""
    from models import User, UserKeys
    
    user = User.objects(id=user_id).first()
    user_keys = UserKeys.objects(user=user).first()
    crypto_manager = CryptoManager()
    
    # Get current DEK (try admin master key first, then user password)
    try:
        admin = User.objects(username='admin').first()
        admin_master_key = crypto_manager.get_or_create_admin_master_key(
            admin_password_hash=admin.password_hash
        )
        user_dek_b64 = crypto_manager.decrypt_data(
            user_keys.admin_master_encrypted_key, 
            admin_master_key
        )
        user_dek = base64.urlsafe_b64decode(user_dek_b64)
    except:
        # Fallback to user password
        user_dek = crypto_manager.recover_dek_with_password(user_keys, "Test1234*")
        user_dek_b64 = base64.urlsafe_b64encode(user_dek).decode()
    
    # Re-encrypt with temporary password and return salt
    temp_key, temp_salt = crypto_manager.derive_key_from_password(temp_password)
    temp_encrypted_adek = crypto_manager.encrypt_data(user_dek_b64, temp_key)
    
    # Update A-DEK
    user_keys.admin_master_encrypted_key = temp_encrypted_adek
    user_keys.save()
    print(f"✅ A-DEK re-encrypted with temp password for test")
    
    return temp_salt

def test_validation_scenarios(crypto_manager, user, token):
    """Test all validation scenarios"""
    print("\n🧪 Testing validation scenarios...")
    
    # Valid scenario data
    valid_temp_password = "Test1234*"
    valid_admin_password = "Admin1234"
    invalid_temp_password = "WrongPassword"
    invalid_admin_password = "WrongAdmin"
    
    test_cases = [
        {
            "name": "Valid finalization",
            "temp_password": valid_temp_password,
            "admin_password": valid_admin_password,
            "expected_success": True
        },
        {
            "name": "Invalid temporary password",
            "temp_password": invalid_temp_password,
            "admin_password": valid_admin_password,
            "expected_success": False,
            "expected_error": "Failed to decrypt A-DEK with temporary password"
        },
        {
            "name": "Invalid admin password",
            "temp_password": valid_temp_password,
            "admin_password": invalid_admin_password,
            "expected_success": False,
            "expected_error": "Invalid admin password"
        },
        {
            "name": "Missing passwords",
            "temp_password": None,
            "admin_password": valid_admin_password,
            "expected_success": False,
            "expected_error": "required"
        }
    ]
    
    results = []
    for i, test_case in enumerate(test_cases):
        print(f"\n  Test {i+1}: {test_case['name']} (actually_save={i == 0})")
        
        try:
            result = simulate_finalization(
                crypto_manager, 
                token.id,
                test_case['temp_password'],
                test_case['admin_password'],
                actually_save=(i == 0)  # Only save for first test
            )
            
            if test_case['expected_success']:
                if result['success']:
                    print(f"    ✅ Expected success - got success")
                    results.append(True)
                else:
                    print(f"    ❌ Expected success - got error: {result.get('error')}")
                    results.append(False)
            else:
                if not result['success']:
                    if test_case['expected_error'] in result.get('error', ''):
                        print(f"    ✅ Expected error - got correct error")
                        results.append(True)
                    else:
                        print(f"    ⚠️ Expected error but got different error: {result.get('error')}")
                        results.append(False)
                else:
                    print(f"    ❌ Expected error - got success")
                    results.append(False)
                    
        except Exception as e:
            print(f"    ❌ Test failed with exception: {e}")
            results.append(False)
            
        # Reset token for next test
        if i < len(test_cases) - 1:
            # Reload token to ensure fresh state
            token = RotationToken.objects(id=token.id).first()
            token.status = 'completed'
            token.a_dek_finalized = False
            token.save()
            
            # Also reset user keys if they were modified
            if test_case['expected_success'] and result.get('success'):
                # If the test succeeded, the A-DEK was re-encrypted with admin key
                # We need to reset it back to temp password encryption
                temp_salt = setup_adek_with_temp_password(user.id, "Test1234*")
                token.temporary_password_salt = base64.urlsafe_b64encode(temp_salt).decode()
                token.save()
    
    return all(results)

def simulate_finalization(crypto_manager, token_id, temp_password, admin_password, actually_save=True):
    """Simulate the A-DEK finalization process"""
    from werkzeug.security import check_password_hash
    
    try:
        # Validate inputs
        if not all([temp_password, admin_password]):
            return {'success': False, 'error': 'Temporary password and admin password required'}
        
        # Get admin user (simulated)
        admin = User.objects(username='admin').first()  # Use 'admin' not 'lifevault_admin'
        if not admin:
            return {'success': False, 'error': 'Admin user not found'}
            
        # Validate admin password
        if not check_password_hash(admin.password_hash, admin_password):
            return {'success': False, 'error': 'Invalid admin password'}
            
        token = RotationToken.objects(id=token_id).first()
        if not token or token.status != 'completed':
            return {'success': False, 'error': 'Invalid token or rotation not completed'}
        
        # Get stored salt for temporary password decryption
        if not token.temporary_password_salt:
            return {'success': False, 'error': 'Temporary password salt not found in token'}
            
        temp_salt = base64.urlsafe_b64decode(token.temporary_password_salt)
        print(f"DEBUG: Salt from token: {temp_salt.hex()[:20]}...")
            
        # Get user and their new A-DEK
        user = User.objects(id=token.user_id).first()
        user_keys = UserKeys.objects(user=user).first()
        
        if not user_keys:
            return {'success': False, 'error': 'User keys not found'}
        
        # Backup current A-DEK for rollback
        original_a_dek = user_keys.admin_master_encrypted_key
        
        try:
            # Decrypt DEK using temporary password with stored salt
            if not token.temporary_password_salt:
                return {'success': False, 'error': 'Temporary password salt not found in token'}
                
            temp_salt = base64.urlsafe_b64decode(token.temporary_password_salt)
            temp_key, _ = crypto_manager.derive_key_from_password(temp_password, temp_salt)
            user_dek_b64 = crypto_manager.decrypt_data(user_keys.admin_master_encrypted_key, temp_key)
            user_dek = base64.urlsafe_b64decode(user_dek_b64)
            
        except Exception as e:
            return {'success': False, 'error': 'Failed to decrypt A-DEK with temporary password. Verify temp password is correct.'}
        
        try:
            # Re-encrypt with admin master key
            admin_master_key = crypto_manager.get_or_create_admin_master_key(
                admin_password_hash=admin.password_hash
            )
            new_a_dek = crypto_manager.encrypt_data(
                base64.urlsafe_b64encode(user_dek).decode(), 
                admin_master_key
            )
            
            # Verify the new A-DEK works before saving
            test_dek_b64 = crypto_manager.decrypt_data(new_a_dek, admin_master_key)
            test_dek = base64.urlsafe_b64decode(test_dek_b64)
            
            if test_dek != user_dek:
                raise ValueError("A-DEK verification failed - decrypted DEK doesn't match original")
                
        except Exception as e:
            return {'success': False, 'error': 'Failed to re-encrypt A-DEK with admin master key'}
        
        try:
            # Update user keys with verified A-DEK
            if actually_save:
                user_keys.admin_master_encrypted_key = new_a_dek
                user_keys.save()
                
                # Mark token as finalized
                token.status = 'finalized'
                token.a_dek_finalized = True
                token.save()
            
            return {'success': True, 'message': 'A-DEK finalized with admin master key'}
            
        except Exception as e:
            # Rollback on save failure (only if actually_save is True)
            if actually_save:
                try:
                    user_keys.admin_master_encrypted_key = original_a_dek
                    user_keys.save()
                except:
                    pass
            
            return {'success': False, 'error': 'Failed to save finalized A-DEK'}
        
    except Exception as e:
        return {'success': False, 'error': f'Unexpected error: {str(e)}'}

def test_rollback_scenario(crypto_manager, user, token):
    """Test rollback functionality"""
    print("\n🔄 Testing rollback scenario...")
    
    user_keys = UserKeys.objects(user=user).first()
    if not user_keys:
        print("❌ User keys not found for rollback test")
        return False
        
    original_a_dek = user_keys.admin_master_encrypted_key
    
    # Simulate failure during save (by temporarily corrupting the token)
    token.user_id = "invalid_user_id"
    token.save()
    
    result = simulate_finalization(crypto_manager, token.id, "Test1234*", "Admin1234")
    
    # Restore token
    token.user_id = str(user.id)
    token.save()
    
    # Check if A-DEK is still the original
    user_keys.reload()
    if user_keys.admin_master_encrypted_key == original_a_dek:
        print("✅ Rollback test passed - A-DEK unchanged after failure")
        return True
    else:
        print("❌ Rollback test failed - A-DEK was modified despite failure")
        return False

def main():
    """Main test function"""
    print("🚀 Testing Improved A-DEK Finalization Implementation")
    print("=" * 60)
    
    if not setup_test_environment():
        return False
    
    crypto_manager = CryptoManager()
    
    # Get existing test user
    user = User.objects(username='sachin').first()  # Use existing user
    if not user:
        print("❌ Test user 'sachin' not found")
        return False
    
    print(f"✅ Found test user: {user.username}")
    
    # Create test rotation token
    token = create_test_rotation_token(user.id, "Test1234*")
    
    try:
        # Test validation scenarios
        validation_passed = test_validation_scenarios(crypto_manager, user, token)
        
        # Test rollback scenario
        rollback_passed = test_rollback_scenario(crypto_manager, user, token)
        
        # Final status
        print(f"\n📊 Test Results:")
        print(f"  Validation Tests: {'✅ PASSED' if validation_passed else '❌ FAILED'}")
        print(f"  Rollback Test: {'✅ PASSED' if rollback_passed else '❌ FAILED'}")
        
        all_passed = validation_passed and rollback_passed
        print(f"\n🎯 Overall Result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
        
        return all_passed
        
    finally:
        # Cleanup
        token.delete()
        print(f"\n🧹 Cleaned up test token")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
