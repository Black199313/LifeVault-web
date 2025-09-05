#!/usr/bin/env python3
"""
Test script to verify user-friendly password generation
"""

def test_password_generation():
    """Test all password generation functions for user-friendliness"""
    print("🧪 Testing User-Friendly Password Generation")
    print("=" * 50)
    
    try:
        from utils import generate_user_friendly_password
        
        # Test 1: Generate multiple passwords
        print("📝 Test 1: Generate sample passwords")
        for i in range(5):
            pwd = generate_user_friendly_password(16)
            print(f"  Password {i+1}: {pwd}")
        
        # Test 2: Check for confusing characters
        print("\n🔍 Test 2: Check for confusing characters")
        confusing_chars = '0OIl1i'  # Characters that are easily confused
        print(f"  Confusing characters to avoid: {confusing_chars}")
        
        # Generate a long password to test character set
        test_pwd = generate_user_friendly_password(200)
        has_confusing = any(char in test_pwd for char in confusing_chars)
        
        if has_confusing:
            print("  ❌ FAIL: Found confusing characters in generated password!")
            found_chars = [char for char in confusing_chars if char in test_pwd]
            print(f"     Found: {found_chars}")
        else:
            print("  ✅ PASS: No confusing characters found")
        
        # Test 3: Character set analysis
        print("\n📊 Test 3: Character set analysis")
        unique_chars = set(test_pwd)
        print(f"  Unique characters used: {len(unique_chars)}")
        print(f"  Expected alphabet: ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*+-=?")
        print(f"  Expected length: 68 characters (48 letters + 8 numbers + 12 special chars)")
        
        # Check for special characters
        special_chars = '!@#$%^&*+-=?'
        has_special = any(char in test_pwd for char in special_chars)
        print(f"  Contains special characters: {has_special}")
        
        if has_special:
            found_special = [char for char in special_chars if char in test_pwd]
            print(f"  Special characters found: {found_special}")
        
        # Test 4: Simulate temporary password generation
        print("\n🔑 Test 4: Temporary password simulation")
        temp_passwords = [generate_user_friendly_password(16) for _ in range(3)]
        for i, pwd in enumerate(temp_passwords, 1):
            print(f"  Temp password {i}: {pwd}")
        
        # Test 5: Simulate email password generation  
        print("\n📧 Test 5: Email password simulation")
        email_passwords = [generate_user_friendly_password(16) for _ in range(3)]
        for i, pwd in enumerate(email_passwords, 1):
            print(f"  Email password {i}: {pwd}")
        
        print("\n✅ All password generation tests completed!")
        print("🎯 Expected improvements:")
        print("  - No more confusion between 0 and O")
        print("  - No more confusion between I, l, and 1") 
        print("  - No more confusion between i and l")
        print("  - Includes special characters for stronger passwords")
        print("  - Easy-to-type special characters: !@#$%^&*+-=?")
        print("  - Easier to read and type manually")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_password_generation()
