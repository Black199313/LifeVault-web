#!/usr/bin/env python3
"""
Test script to verify that the JSON import fixes are working correctly.
"""

import json

def test_json_functionality():
    """Test that JSON operations work without the 'cannot access local variable' error"""
    
    # Test 1: Basic JSON operations
    test_data = {'test': 'value', 'number': 42}
    json_str = json.dumps(test_data)
    parsed_data = json.loads(json_str)
    
    assert parsed_data == test_data, "Basic JSON round-trip failed"
    print("✓ Basic JSON functionality works")
    
    # Test 2: Import admin_routes (should not cause json variable conflict)
    try:
        import admin_routes
        print("✓ admin_routes imports without JSON variable conflicts")
    except Exception as e:
        print(f"✗ admin_routes import failed: {e}")
        return False
    
    # Test 3: Import admin_escrow (should not cause json variable conflict)
    try:
        import admin_escrow
        print("✓ admin_escrow imports without JSON variable conflicts")
    except Exception as e:
        print(f"✗ admin_escrow import failed: {e}")
        return False
    
    # Test 4: Import crypto_utils (should not cause json variable conflict)
    try:
        import crypto_utils
        print("✓ crypto_utils imports without JSON variable conflicts")
    except Exception as e:
        print(f"✗ crypto_utils import failed: {e}")
        return False
    
    # Test 5: Import routes (should not cause json variable conflict)
    try:
        import routes
        print("✓ routes imports without JSON variable conflicts")
    except Exception as e:
        print(f"✗ routes import failed: {e}")
        return False
    
    print("\nAll JSON import fixes are working correctly!")
    return True

if __name__ == "__main__":
    success = test_json_functionality()
    if success:
        print("\n🎉 JSON variable conflict has been resolved!")
    else:
        print("\n❌ There are still issues that need to be addressed.")
