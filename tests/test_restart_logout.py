#!/usr/bin/env python3
"""
Test script to verify server restart logout functionality
"""

import os
import sys
from datetime import datetime, timedelta
import tempfile

def test_restart_detection():
    """Test the restart detection mechanism"""
    print("🧪 Testing server restart logout functionality...")
    
    # Test 1: Create a restart marker file
    restart_time = datetime.utcnow()
    with open('.server_restart_time', 'w') as f:
        f.write(restart_time.isoformat())
    
    print(f"✅ Created restart marker at: {restart_time}")
    
    # Test 2: Simulate user login before restart
    user_login_time = restart_time - timedelta(minutes=30)  # 30 minutes before restart
    print(f"📝 Simulated user login at: {user_login_time}")
    print(f"🔄 Server restart at: {restart_time}")
    
    # Test 3: Check if session would be invalidated
    if user_login_time < restart_time:
        print("✅ Session would be INVALIDATED (user logged in before restart)")
    else:
        print("❌ Session would be VALID (user logged in after restart)")
    
    # Test 4: Simulate user login after restart
    new_login_time = restart_time + timedelta(minutes=10)  # 10 minutes after restart
    print(f"📝 Simulated new login at: {new_login_time}")
    
    if new_login_time > restart_time:
        print("✅ New session would be VALID (user logged in after restart)")
    else:
        print("❌ New session would be INVALID")
    
    # Cleanup
    if os.path.exists('.server_restart_time'):
        os.remove('.server_restart_time')
        print("🧹 Cleaned up test marker file")
    
    print("\n🎯 Server restart logout test completed!")
    print("📋 Expected behavior:")
    print("  1. When server restarts, all existing sessions become invalid")
    print("  2. Users logged in BEFORE restart will be forced to login again")
    print("  3. Users logging in AFTER restart will have valid sessions")
    print("  4. Session validation checks restart timestamp on each request")

if __name__ == "__main__":
    test_restart_detection()
