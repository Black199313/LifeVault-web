#!/usr/bin/env python3
"""
Simple A-DEK diagnostic without Flask app context conflicts
"""

import os
import sys
sys.path.append('.')

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import required modules
import mongoengine
from models import User, UserKeys, RotationToken
from crypto_utils import crypto_manager
import base64
import json
from datetime import datetime

def setup_mongodb():
    """Setup MongoDB connection"""
    mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
    mongodb_db = os.environ.get("MONGODB_DB", "lifevault")
    
    try:
        mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
        print(f"✅ MongoDB connected to database: {mongodb_db}")
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

def main():
    print("🔍 A-DEK FINALIZATION DIAGNOSTIC")
    print("=" * 50)
    
    try:
        # Connect to MongoDB directly
        if not setup_mongodb():
            return
        
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
        print(f"   Created: {token.created_at}")
        if hasattr(token, 'temporary_password_hash'):
            print(f"   Has temp password hash: Yes ({token.temporary_password_hash[:20]}...)")
        
        # Check current A-DEK format
        if user_keys.admin_master_encrypted_key:
            print(f"✅ A-DEK exists, length: {len(user_keys.admin_master_encrypted_key)}")
            print(f"   A-DEK preview: {user_keys.admin_master_encrypted_key[:100]}...")
            
            # Check if it's JSON format or direct encryption
            try:
                json_data = json.loads(user_keys.admin_master_encrypted_key)
                print("✅ A-DEK is in JSON format")
                print(f"   Keys in JSON: {list(json_data.keys())}")
                is_json = True
            except:
                print("✅ A-DEK is in direct encryption format")
                is_json = False
        else:
            print("❌ No A-DEK found")
            return
        
        # Check P-DEK to ensure we can get the main DEK
        print("\n🔍 Testing P-DEK access...")
        user_password = "Test1234*"  # Known password
        
        try:
            if user_keys.password_encrypted_key.startswith('{'):
                p_dek_data = json.loads(user_keys.password_encrypted_key)
                salt = base64.urlsafe_b64decode(p_dek_data['salt'])
                password_key, _ = crypto_manager.derive_key_from_password(user_password, salt)
                user_dek_b64 = crypto_manager.decrypt_data(p_dek_data['encrypted'], password_key)
                user_dek = base64.urlsafe_b64decode(user_dek_b64)
                
                print(f"✅ Successfully got DEK from P-DEK")
                print(f"   DEK length: {len(user_dek)} bytes")
                main_dek = user_dek
                
            else:
                print("❌ P-DEK not in expected JSON format")
                return
                
        except Exception as e:
            print(f"❌ P-DEK access failed: {e}")
            return
        
        # Now the critical part - what's wrong with A-DEK finalization?
        print("\n🧪 TESTING A-DEK FINALIZATION ISSUE")
        print("-" * 40)
        
        print("Token ID that failed: 68b44101da610afc7551285c")
        print("Checking if this matches our found token...")
        
        if str(token.id) == "68b44101da610afc7551285c":
            print("✅ Token IDs match - this is the problematic token")
        else:
            print(f"❌ Token ID mismatch: found {token.id}, expected 68b44101da610afc7551285c")
        
        # Get the exact temp password hash from the token
        if hasattr(token, 'temporary_password_hash') and token.temporary_password_hash:
            print(f"✅ Token has temp password hash: {token.temporary_password_hash}")
            
            # The problem: what temp password was used?
            print("\n🔍 The issue is likely:")
            print("1. Wrong temporary password being provided")
            print("2. A-DEK encrypted with wrong key during rotation")
            print("3. Admin master key not working properly")
            
            # Let's see what the A-DEK was encrypted with
            print(f"\n📋 A-DEK Analysis:")
            if is_json:
                try:
                    a_dek_data = json.loads(user_keys.admin_master_encrypted_key)
                    print(f"   A-DEK JSON keys: {list(a_dek_data.keys())}")
                    encrypted_part = a_dek_data.get('encrypted', user_keys.admin_master_encrypted_key)
                except:
                    encrypted_part = user_keys.admin_master_encrypted_key
            else:
                encrypted_part = user_keys.admin_master_encrypted_key
            
            print(f"   Encrypted data length: {len(encrypted_part)}")
            print(f"   Encrypted data preview: {encrypted_part[:50]}...")
            
        else:
            print("❌ Token missing temporary_password_hash")
        
        print(f"\n📝 SOLUTION NEEDED:")
        print(f"1. Get the correct temporary password that was generated")
        print(f"2. OR use P-DEK to extract main DEK and re-encrypt with admin master key")
        print(f"3. Token ID to fix: {token.id}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
