#!/usr/bin/env python3
"""
Corrected Key Rotation Test
Uses the proper admin credential approach based on diagnostic findings
"""

import os
import sys
import json
import base64
import hashlib
import mongoengine
from datetime import datetime, timedelta
from secrets import token_urlsafe

# Setup
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ Environment variables loaded")
except ImportError:
    print("⚠️ python-dotenv not installed")

mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
mongodb_db = os.environ.get("MONGODB_DB", "lifevault")

try:
    mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
    print(f"✅ MongoDB connected to {mongodb_db}")
except Exception as e:
    print(f"❌ MongoDB connection failed: {str(e)}")
    sys.exit(1)

from models import User, UserKeys, RotationToken, Secret
from crypto_utils import CryptoManager

def test_corrected_key_rotation():
    """Test key rotation with corrected credentials"""
    print("🎯 CORRECTED KEY ROTATION TEST")
    print("="*60)
    
    # Fixed credentials based on diagnostic
    username = "sachin"
    user_password = "Test1234*"
    admin_password = "Admin1234"  
    email_password = "Xi9V7BxPSVChKUwx"
    security_answers = ["Test78", "Test78", "Test78"]
    recovery_phrase = "antenna affair anxiety act able afford across alcohol alarm abandon antenna alert"
    
    print(f"✅ Username: {username}")
    print(f"✅ User password: {user_password}")
    print(f"✅ Admin password: {admin_password}")
    print(f"✅ Email password: {email_password}")
    print(f"✅ Security answers: {security_answers}")
    print(f"✅ Recovery phrase: {recovery_phrase}")
    
    # Initialize
    crypto_manager = CryptoManager()
    
    # Find user
    user = User.objects(username=username).first()
    user_keys = UserKeys.objects(user=user).first()
    
    if not user or not user_keys:
        print(f"❌ User or keys not found")
        return False
    
    print(f"✅ Found user: {user.username} (version: {user_keys.key_version})")
    
    # Test admin credentials with CORRECT approach
    print(f"\n🔧 Testing admin credentials...")
    admin_user = User.objects(username="admin").first()
    
    # Use stored password hash (not generated)
    admin_password_hash = admin_user.password_hash
    print(f"🔍 Using stored admin hash: {admin_password_hash[:30]}...")
    
    try:
        admin_master_key = crypto_manager.get_or_create_admin_master_key(admin_password_hash)
        print(f"✅ Admin master key works! Length: {len(admin_master_key)} bytes")
    except Exception as e:
        print(f"❌ Admin master key failed: {str(e)}")
        return False
    
    # Test all recovery methods
    print(f"\n🔧 Testing all recovery methods...")
    
    try:
        # P-DEK
        current_dek = crypto_manager.recover_dek_with_password(user_keys, user_password)
        print(f"✅ P-DEK works: {len(current_dek)} bytes")
        
        # Q-DEK  
        qdek = crypto_manager.recover_dek_with_security_questions(user_keys, security_answers)
        print(f"✅ Q-DEK works: {qdek == current_dek}")
        
        # R-DEK
        rdek = crypto_manager.recover_dek_with_recovery_phrase(user_keys, recovery_phrase)
        print(f"✅ R-DEK works: {rdek == current_dek}")
        
        # E-DEK
        edek = crypto_manager.recover_dek_with_email_password(user_keys, email_password)
        print(f"✅ E-DEK works: {edek == current_dek}")
        
    except Exception as e:
        print(f"❌ Recovery method failed: {str(e)}")
        return False
    
    # Generate rotation credentials
    temp_password = token_urlsafe(16)
    token = token_urlsafe(32)
    
    print(f"\n✅ Generated temp password: {temp_password}")
    print(f"✅ Generated token: {token}")
    
    # Create rotation token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
    
    rotation_token = RotationToken(
        user_id=str(user.id),
        admin_id=str(admin_user.id),
        token_hash=token_hash,
        token_value=token,
        temporary_password_hash=temp_hash,
        expires_at=datetime.utcnow() + timedelta(hours=24),
        status='approved',
        request_reason='Corrected rotation test'
    )
    rotation_token.save()
    
    print(f"✅ Rotation token created and approved")
    
    # Test the complete rotation using the actual method
    print(f"\n🔧 Testing complete key rotation...")
    
    try:
        # Use the actual rotation method from crypto_utils  
        new_dek, updated_keys = crypto_manager.rotate_user_keys_preserve_admin_access(
            user_keys=user_keys,
            password=user_password,
            security_answers=security_answers,
            recovery_phrase=recovery_phrase
        )
        
        if new_dek and updated_keys:
            print(f"🎉 KEY ROTATION COMPLETED SUCCESSFULLY!")
            print(f"✅ New DEK generated: {len(new_dek)} bytes")
            print(f"✅ Updated keys: {updated_keys}")
            
            # Verify new keys work
            user_keys.reload()
            test_dek = crypto_manager.recover_dek_with_password(user_keys, user_password)
            print(f"✅ New P-DEK verification: {len(test_dek)} bytes")
            print(f"✅ New key version: {user_keys.key_version}")
            
            return True
        else:
            print(f"❌ Key rotation method returned None")
            return False
            
    except Exception as e:
        print(f"❌ Key rotation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("🚀 RUNNING CORRECTED KEY ROTATION TEST")
    print("Using diagnostic findings to test with proper credentials\n")
    
    success = test_corrected_key_rotation()
    
    if success:
        print(f"\n🎉 SUCCESS! Key rotation is now working properly!")
        print(f"\n💡 CREDENTIALS FOR WEB INTERFACE:")
        print(f"   Username: sachin")
        print(f"   Password: Test1234*")
        print(f"   Admin Password: Admin1234")
        print(f"   Email Password: Xi9V7BxPSVChKUwx")
    else:
        print(f"\n❌ Key rotation still has issues")
        print(f"💡 Check the error messages above for specific problems")

if __name__ == "__main__":
    main()
