#!/usr/bin/env python3
"""
Find admin password
"""

import os
import sys
import getpass
import mongoengine
from werkzeug.security import check_password_hash

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Initialize MongoDB connection
mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
mongodb_db = os.environ.get("MONGODB_DB", "lifevault")

try:
    mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
    print(f"✅ MongoDB connected")
except Exception as e:
    print(f"❌ MongoDB connection failed: {str(e)}")
    sys.exit(1)

from models import User

def main():
    # Find admin user
    admin = User.objects(is_admin=True).first()
    if not admin:
        print("❌ No admin user found")
        return
    
    print(f"✅ Found admin: {admin.username}")
    print(f"🔍 Password hash: {admin.password_hash[:50]}...")
    
    # Extended test passwords
    test_passwords = [
        "admin123", "Admin123", "ADMIN123",
        "admin", "Admin", "ADMIN",
        "password", "Password", "PASSWORD",
        "Test1234&", "Test1234*", "Test1234!",
        "test123", "Test123", "TEST123",
        "lifevault", "LifeVault", "LIFEVAULT",
        "secret", "Secret", "SECRET",
        "123456", "admin1234", "password123"
    ]
    
    print(f"\n🔍 Testing extended password list...")
    
    for password in test_passwords:
        if check_password_hash(admin.password_hash, password):
            print(f"✅ ADMIN PASSWORD FOUND: '{password}'")
            return password
    
    print(f"❌ No matching password found in extended list")
    
    # Interactive testing
    print(f"\n🔧 Manual admin password testing:")
    while True:
        try:
            test_password = getpass.getpass("Enter admin password to test (or 'quit' to exit): ")
            if test_password.lower() == 'quit':
                break
                
            if check_password_hash(admin.password_hash, test_password):
                print(f"✅ ADMIN PASSWORD FOUND: '{test_password}'")
                return test_password
            else:
                print(f"❌ Password does not match")
                
        except KeyboardInterrupt:
            print(f"\n👋 Goodbye!")
            break
    
    return None

if __name__ == "__main__":
    main()
