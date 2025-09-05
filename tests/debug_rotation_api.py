#!/usr/bin/env python3
"""
Debug script to test the key rotation API endpoint
"""

import requests
import json
import sys

def test_rotation_api():
    """Test the rotation API endpoint"""
    base_url = "http://127.0.0.1:5000"
    
    # Create a session for cookie handling
    session = requests.Session()
    
    print("🔍 Testing Key Rotation API")
    print("=" * 40)
    
    try:
        # First, check if server is running
        print("1. Checking if server is running...")
        response = session.get(f"{base_url}/")
        if response.status_code != 200:
            print(f"❌ Server not responding: {response.status_code}")
            return False
        print("✅ Server is running")
        
        # Try to access login page
        print("2. Accessing login page...")
        response = session.get(f"{base_url}/login")
        if response.status_code != 200:
            print(f"❌ Login page not accessible: {response.status_code}")
            return False
        print("✅ Login page accessible")
        
        # Try to login
        print("3. Attempting login...")
        login_data = {
            'username': 'sachin',  # Use actual username
            'password': 'Sachin@123'  # Use actual password
        }
        
        response = session.post(f"{base_url}/login", data=login_data)
        if response.status_code != 200:
            print(f"❌ Login failed with status: {response.status_code}")
            return False
            
        # Check if login was successful by looking for redirect or success indicators
        if 'dashboard' in response.url or 'secrets' in response.url or response.status_code == 200:
            print("✅ Login successful")
        else:
            print("❌ Login failed - no redirect to dashboard")
            print(f"Response URL: {response.url}")
            return False
        
        # Test the rotation API endpoint
        print("4. Testing rotation API endpoint...")
        
        rotation_data = {
            'reason': 'routine_maintenance',
            'description': 'Testing rotation API'
        }
        
        try:
            response = session.post(
                f"{base_url}/api/request_key_rotation", 
                json=rotation_data,
                timeout=10  # 10 second timeout
            )
            
            print(f"Response status: {response.status_code}")
            print(f"Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ API call successful")
                print(f"Response: {json.dumps(result, indent=2)}")
                return True
            else:
                print(f"❌ API call failed: {response.status_code}")
                print(f"Response text: {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            print("❌ API call timed out after 10 seconds")
            return False
        except requests.exceptions.ConnectionError:
            print("❌ Connection error during API call")
            return False
        except Exception as e:
            print(f"❌ API call error: {str(e)}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("Debug Key Rotation API")
    print("Make sure the Flask app is running on http://127.0.0.1:5000")
    print()
    
    if test_rotation_api():
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)
