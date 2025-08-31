#!/usr/bin/env python3
"""
Quick test to verify the new token logic works
"""

def test_new_token_logic():
    try:
        from app import app
        from models import RotationToken
        from datetime import datetime, timedelta
        
        with app.app_context():
            print("🧪 Testing New Token Logic")
            print("=" * 40)
            
            # Create test token
            print("📝 Creating test token...")
            token = RotationToken(
                user_id='test_user_id',
                expires_at=datetime.utcnow() + timedelta(hours=1),
                status='approved',
                request_reason='Test new token logic'
            )
            token.save()
            token_id = str(token.id)
            print(f"✅ Token created with ID: {token_id}")
            
            # Test the new validation logic
            print(f"🔍 Testing validation for ID: {token_id}")
            found = RotationToken.objects(
                id=token_id,
                status='approved',
                expires_at__gt=datetime.utcnow()
            ).first()
            
            if found:
                print("✅ Token lookup by MongoDB _id works!")
                print(f"   Token ID: {found.id}")
                print(f"   User ID: {found.user_id}")
                print(f"   Status: {found.status}")
                
                # Cleanup
                found.delete()
                print("🧹 Test token cleaned up")
                return True
            else:
                print("❌ Token lookup failed")
                return False
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_new_token_logic()
    if success:
        print("\n🎉 NEW TOKEN LOGIC WORKS!")
        print("✅ Ready to test in web interface")
    else:
        print("\n❌ STILL ISSUES TO FIX")
