#!/usr/bin/env python3

"""
Fix corrupted P-DEK data caused by double base64 encoding bug
"""

from mongoengine import connect
from models import User, UserKeys
import base64
import json

def main():
    connect('lifevault')
    
    # Find users with potentially corrupted P-DEKs
    users_with_keys = UserKeys.objects()
    
    for user_keys in users_with_keys:
        user = User.objects(id=user_keys.user.id).first()
        if not user:
            continue
            
        print(f"\nChecking user: {user.username}")
        
        p_dek = user_keys.password_encrypted_key
        print(f"P-DEK format: {p_dek[:100]}...")
        
        # Check if it's JSON format
        try:
            data = json.loads(p_dek)
            print(f"✅ User {user.username} has valid JSON format P-DEK")
            continue
        except json.JSONDecodeError:
            pass
        
        # Check if it's colon format
        if ':' in p_dek:
            parts = p_dek.split(':', 1)
            if len(parts) == 2:
                salt_part, encrypted_part = parts
                print(f"Salt part: {salt_part}")
                print(f"Encrypted part: {encrypted_part[:50]}...")
                
                # Try to decode salt
                try:
                    salt = base64.urlsafe_b64decode(salt_part.encode())
                    print(f"✅ Salt decodes OK, length: {len(salt)}")
                except Exception as e:
                    print(f"❌ Salt decode failed: {e}")
                    continue
                
                # Check if encrypted part looks like double-encoded base64
                try:
                    # Try to decode once
                    first_decode = base64.urlsafe_b64decode(encrypted_part.encode())
                    print(f"First decode length: {len(first_decode)}")
                    
                    # Try to decode again (this would indicate double encoding)
                    try:
                        second_decode = base64.urlsafe_b64decode(first_decode)
                        print(f"❌ User {user.username} has DOUBLE-ENCODED P-DEK (corrupted)")
                        
                        # Fix it by storing the first decode result
                        fixed_p_dek = f"{salt_part}:{first_decode.decode()}"
                        print(f"Fixed P-DEK: {fixed_p_dek[:50]}...")
                        
                        # Uncomment to actually fix:
                        # user_keys.password_encrypted_key = fixed_p_dek
                        # user_keys.save()
                        # print(f"✅ Fixed P-DEK for user {user.username}")
                        
                    except:
                        print(f"✅ User {user.username} has normal single-encoded P-DEK")
                        
                except Exception as e:
                    print(f"❌ Encrypted part decode failed: {e}")
            else:
                print(f"❌ Invalid colon format for user {user.username}")
        else:
            print(f"❌ Unknown P-DEK format for user {user.username}")

if __name__ == "__main__":
    main()
