#!/usr/bin/env python3
"""
Test the fixed key rotation with MongoDB _id token approach
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_token_logic():
    """Test the simplified token logic"""
    try:
        from models import RotationToken, User
        from datetime import datetime, timedelta
        import logging
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        
        print("🧪 Testing Fixed Token Logic")
        print("=" * 50)
        
        # Step 1: Find a user
        user = User.objects(username='sachin').first()
        if not user:
            print("❌ User 'sachin' not found")
            return False
            
        print(f"✅ Found user: {user.username} (ID: {user.id})")
        
        # Step 2: Create a rotation token (simulating the request)
        print("\n🔄 Creating rotation token...")
        rotation_token = RotationToken(
            user_id=str(user.id),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            status='approved',  # Simulate admin approval
            request_reason='Testing fixed token logic'
        )
        rotation_token.save()
        
        # The token is now the MongoDB _id
        token_id = str(rotation_token.id)
        print(f"✅ Token created with ID: {token_id}")
        
        # Step 3: Test token validation (simulating the validation)
        print(f"\n🔍 Testing token validation with ID: {token_id}")
        
        # Direct lookup by ID
        found_token = RotationToken.objects(
            id=token_id,
            status='approved',
            expires_at__gt=datetime.utcnow()
        ).first()
        
        if found_token:
            print(f"✅ Token validation successful!")
            print(f"   - Token ID: {found_token.id}")
            print(f"   - User ID: {found_token.user_id}")
            print(f"   - Status: {found_token.status}")
            print(f"   - Expires: {found_token.expires_at}")
            
            # Cleanup
            found_token.delete()
            print(f"🧹 Cleaned up test token")
            return True
        else:
            print(f"❌ Token validation failed!")
            return False
            
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("🚀 Testing Fixed Key Rotation Logic")
    print("=" * 60)
    
    # Initialize MongoDB connection
    try:
        from app import app
        with app.app_context():
            success = test_token_logic()
            
        if success:
            print("\n🎉 ALL TESTS PASSED!")
            print("✅ Token logic is now working correctly")
            print("✅ Ready to test in web interface")
        else:
            print("\n❌ TESTS FAILED!")
            print("❌ There are still issues to fix")
            
    except Exception as e:
        print(f"❌ Setup error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
