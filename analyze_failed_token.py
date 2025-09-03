#!/usr/bin/env python3
"""
Get detailed info about failed rotation token
"""

import os
import sys
from dotenv import load_dotenv
load_dotenv()

import mongoengine
mongoengine.connect(host=os.getenv('MONGO_URI', 'mongodb://localhost:27017/lifevault'))

from models import RotationToken, User

def analyze_failed_token():
    token_id = '68b8824594d2346fd98b56b3'
    
    token = RotationToken.objects(id=token_id).first()
    if not token:
        print(f"Token {token_id} not found!")
        return
    
    user = User.objects(id=token.user_id).first()
    
    print(f'Failed Rotation Token Analysis:')
    print(f'  ID: {token.id}')
    print(f'  User: {user.username if user else "Unknown"} ({token.user_id})')
    print(f'  Status: {token.status}')
    print(f'  Stage: {getattr(token, "rotation_stage", "unknown")}')
    print(f'  Created: {token.created_at}')
    print(f'  Expires: {token.expires_at}')
    print(f'  Used at: {getattr(token, "used_at", "Not used")}')
    print(f'  Request reason: {getattr(token, "request_reason", "No reason")}')
    
    # Check if there's an error message
    if hasattr(token, 'error_message') and token.error_message:
        print(f'  Error message: {token.error_message}')
    else:
        print(f'  Error message: No error message stored')
    
    # Check backup keys
    backup_keys = getattr(token, 'backup_keys', None)
    if backup_keys:
        print(f'  Backup keys: Available ({len(backup_keys)} entries)')
        for key, value in backup_keys.items():
            if isinstance(value, list):
                print(f'    {key}: {len(value)} items')
            elif isinstance(value, str):
                print(f'    {key}: {len(value)} chars')
            else:
                print(f'    {key}: {type(value)}')
    else:
        print(f'  Backup keys: None')
    
    # Check new DEK
    if hasattr(token, 'new_dek') and token.new_dek:
        print(f'  New DEK: Available ({len(token.new_dek)} chars)')
    else:
        print(f'  New DEK: Not available')
    
    # Check temp password info
    if hasattr(token, 'temporary_password_hash') and token.temporary_password_hash:
        print(f'  Temp password hash: Available ({len(token.temporary_password_hash)} chars)')
    else:
        print(f'  Temp password hash: Not available')
    
    if hasattr(token, 'temporary_password_salt') and token.temporary_password_salt:
        print(f'  Temp password salt: Available ({len(token.temporary_password_salt)} chars)')
    else:
        print(f'  Temp password salt: Not available')

if __name__ == "__main__":
    analyze_failed_token()
