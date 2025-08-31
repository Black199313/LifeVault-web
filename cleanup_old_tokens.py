#!/usr/bin/env python3
"""
Clean up old rotation tokens and test the new system
"""

def cleanup_and_test():
    try:
        from app import app
        from models import RotationToken
        from datetime import datetime, timedelta
        
        with app.app_context():
            print("🧹 CLEANING UP OLD TOKENS")
            print("=" * 40)
            
            # Delete all existing rotation tokens (fresh start)
            deleted_count = RotationToken.objects.delete()
            print(f"🗑️  Deleted {deleted_count} old tokens")
            
            print("\n🧪 TESTING NEW TOKEN SYSTEM")
            print("=" * 40)
            
            # Create a fresh token using the new format
            print("📝 Creating new format token...")
            new_token = RotationToken(
                user_id='68b409e048ffa721a23832a9',  # sachin's user ID
                expires_at=datetime.utcnow() + timedelta(hours=24),
                status='approved',  # Directly approve for testing
                request_reason='Testing new token format',
                temporary_password_hash='bb853b11b65659cb85b9e5a50ca5e07c09c01b6b4f7e0da49acbe527b59dae0a'  # Hash of temp password
            )
            new_token.save()
            token_id = str(new_token.id)
            print(f"✅ New token created with ID: {token_id}")
            print(f"   User ID: {new_token.user_id}")
            print(f"   Status: {new_token.status}")
            print(f"   Expires: {new_token.expires_at}")
            
            # Test validation
            print(f"\n🔍 Testing validation for token: {token_id}")
            found = RotationToken.objects(
                id=token_id,
                status='approved',
                expires_at__gt=datetime.utcnow()
            ).first()
            
            if found:
                print("✅ Token validation works!")
                print(f"   Found token ID: {found.id}")
                print(f"   User: {found.user_id}")
                return token_id
            else:
                print("❌ Token validation failed")
                return None
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    token_id = cleanup_and_test()
    if token_id:
        print(f"\n🎉 SUCCESS!")
        print(f"✅ Fresh token ready for testing: {token_id}")
        print("\n📋 TO TEST KEY ROTATION:")
        print(f"1. Use token: {token_id}")
        print("2. Temporary password: EpRt6gFB (this should work)")
        print("3. Current password: Test1234*")
        print("4. Admin password: Admin1234")
        print("5. Email password: Xi9V7BxPSVChKUwx")
        print("6. Security answers: Test78, Test78, Test78")
    else:
        print("\n❌ FAILED - Still issues to fix")
