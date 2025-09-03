#!/usr/bin/env python3
"""
Check recent failed rotation tokens
"""

import os
import sys
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure environment
import json
from dotenv import load_dotenv
load_dotenv()

# Configure MongoDB
import mongoengine
mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/lifevault')
mongoengine.connect(host=mongo_uri)

from models import RotationToken, User

def check_failed_rotations():
    """Check recent failed rotation tokens"""
    
    # Get recent failed rotation tokens  
    recent_time = datetime.utcnow() - timedelta(hours=24)
    failed_tokens = RotationToken.objects(status='failed', created_at__gte=recent_time).order_by('-created_at')
    
    print(f'Recent failed rotation tokens ({len(failed_tokens)}):')
    
    if not failed_tokens:
        print("No recent failed rotations found.")
        
        # Check for any pending or other tokens
        all_recent_tokens = RotationToken.objects(created_at__gte=recent_time).order_by('-created_at')
        print(f'\nAll recent rotation tokens ({len(all_recent_tokens)}):')
        
        for token in all_recent_tokens:
            user = User.objects(id=token.user_id).first()
            username = user.username if user else "Unknown"
            
            print(f'  Token ID: {token.id}')
            print(f'  User: {username} ({token.user_id})')
            print(f'  Status: {token.status}')
            print(f'  Stage: {getattr(token, "rotation_stage", "unknown")}')
            print(f'  Created: {token.created_at}')
            print(f'  Expires: {token.expires_at}')
            if hasattr(token, 'error_message') and token.error_message:
                print(f'  Error: {token.error_message}')
            print('---')
        
        return
    
    for token in failed_tokens:
        user = User.objects(id=token.user_id).first()
        username = user.username if user else "Unknown"
        
        print(f'  Token ID: {token.id}')
        print(f'  User: {username} ({token.user_id})')
        print(f'  Status: {token.status}')
        print(f'  Stage: {getattr(token, "rotation_stage", "unknown")}')
        print(f'  Created: {token.created_at}')
        if hasattr(token, 'error_message') and token.error_message:
            print(f'  Error: {token.error_message}')
        print('---')

if __name__ == "__main__":
    check_failed_rotations()
