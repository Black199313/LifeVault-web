#!/usr/bin/env python3
"""
Admin User Creation Script for LifeVault
Creates admin users separately from the main application.
"""

import os
import sys
import getpass
import mongoengine
from datetime import datetime
from werkzeug.security import generate_password_hash

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_to_database():
    """Connect to MongoDB database"""
    try:
        mongodb_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/lifevault")
        mongodb_db = os.environ.get("MONGODB_DB", "lifevault")
        
        mongoengine.connect(mongodb_db, host=mongodb_uri, connect=False)
        logger.info(f"Connected to MongoDB database: {mongodb_db}")
        return True
    except Exception as e:
        logger.error(f"Failed to connect to database: {str(e)}")
        return False

def create_admin_user_interactive():
    """Create admin user with interactive prompts"""
    print("=" * 60)
    print("   LifeVault Admin User Creation Script")
    print("=" * 60)
    print()
    
    try:
        # Connect to database
        if not connect_to_database():
            print("❌ Failed to connect to database")
            return False
        
        # Import models after database connection
        from models import User, UserKeys, generate_recovery_phrase
        from crypto_utils import crypto_manager
        
        print("✅ Connected to database")
        
        # Get admin details
        print("\n📝 Enter admin account details:")
        username = input("Username: ").strip()
        
        if not username:
            print("❌ Username cannot be empty!")
            return False
        
        # Check if username exists
        if User.objects(username=username).first():
            print(f"❌ Username '{username}' already exists!")
            return False
        
        email = input("Email: ").strip()
        if not email:
            print("❌ Email cannot be empty!")
            return False
        
        # Check if email exists
        if User.objects(email=email).first():
            print(f"❌ Email '{email}' already registered!")
            return False
        
        # Get password securely
        while True:
            password = getpass.getpass("Password: ")
            if len(password) < 8:
                print("❌ Password must be at least 8 characters long!")
                continue
            
            confirm_password = getpass.getpass("Confirm Password: ")
            if password != confirm_password:
                print("❌ Passwords do not match!")
                continue
            
            break
        
        # Confirmation
        print(f"\n📋 Creating admin user:")
        print(f"   Username: {username}")
        print(f"   Email: {email}")
        print(f"   Admin privileges: YES")
        
        confirm = input("\nProceed? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ Operation cancelled.")
            return False
        
        # Create admin user
        print("\n🔄 Creating admin user...")
        admin_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=True,
            is_active=True,
            email_verified=True,  # Admin accounts are pre-verified
            created_at=datetime.utcnow()
        )
        admin_user.save()
        print(f"✅ Admin user '{username}' created successfully!")
        
        # Create admin encryption keys (minimal setup for admin management only)
        print("\n🔐 Setting up admin encryption keys...")
        try:
            # Generate a minimal DEK for admin (only for admin functions, not user data)
            admin_dek = crypto_manager.generate_key()
            recovery_phrase = generate_recovery_phrase()
            
            # Create 5-key system for admin
            five_keys = crypto_manager.create_five_key_system(
                admin_dek,
                password,
                ['admin', 'system', 'management'],  # Default security answers
                recovery_phrase
            )
            
            admin_keys = UserKeys(
                user=admin_user,
                **five_keys
            )
            admin_keys.save()
            
            print("✅ Admin encryption keys created successfully!")
            print(f"\n📝 IMPORTANT - Save this recovery phrase:")
            print(f"   Recovery Phrase: {recovery_phrase}")
            print(f"   (This is for admin account recovery only)")
            
        except Exception as e:
            logger.error(f"Failed to create admin keys: {str(e)}")
            print(f"⚠️  Admin user created but encryption setup failed: {str(e)}")
            print("   The admin can still log in and manage users.")
        
        print(f"\n🎉 Admin account setup complete!")
        print(f"   Username: {username}")
        print(f"   Password: [hidden]")
        print(f"   Role: Administrator")
        print(f"\n⚠️  Please change the default password after first login!")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to create admin user: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return False

def create_admin_user_from_env():
    """Create admin user from environment variables"""
    try:
        if not connect_to_database():
            print("❌ Failed to connect to database")
            return False
        
        # Import models after database connection
        from models import User, UserKeys, generate_recovery_phrase
        from crypto_utils import crypto_manager
        
        username = os.environ.get('ADMIN_USERNAME')
        email = os.environ.get('ADMIN_EMAIL') 
        password = os.environ.get('ADMIN_PASSWORD')
        
        if not all([username, email, password]):
            print("❌ Missing environment variables: ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD")
            return False
        
        # Check if admin already exists
        if User.objects(username=username).first():
            print(f"ℹ️  Admin user '{username}' already exists")
            return True
        
        # Create admin user
        admin_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=True,
            is_active=True,
            email_verified=True,
            created_at=datetime.utcnow()
        )
        admin_user.save()
        
        # Create minimal admin keys
        admin_dek = crypto_manager.generate_key()
        recovery_phrase = generate_recovery_phrase()
        
        five_keys = crypto_manager.create_five_key_system(
            admin_dek,
            password,
            ['admin', 'system', 'management'],
            recovery_phrase
        )
        
        admin_keys = UserKeys(
            user=admin_user,
            **five_keys
        )
        admin_keys.save()
        
        print(f"✅ Admin user '{username}' created successfully from environment variables")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create admin from env: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return False

def list_admin_users():
    """List all existing admin users"""
    try:
        if not connect_to_database():
            print("❌ Failed to connect to database")
            return
        
        # Import models after database connection
        from models import User
        
        admins = User.objects(is_admin=True)
        
        if not admins:
            print("ℹ️  No admin users found")
            return
        
        print(f"\n👑 Admin Users ({len(admins)} found):")
        print("-" * 60)
        for admin in admins:
            status = "Active" if admin.is_active else "Inactive"
            created = admin.created_at.strftime('%Y-%m-%d') if admin.created_at else 'Unknown'
            last_login = admin.last_login.strftime('%Y-%m-%d %H:%M') if admin.last_login else 'Never'
            
            print(f"Username: {admin.username}")
            print(f"Email: {admin.email}")
            print(f"Status: {status}")
            print(f"Created: {created}")
            print(f"Last Login: {last_login}")
            print("-" * 60)
            
    except Exception as e:
        logger.error(f"Failed to list admins: {str(e)}")
        print(f"❌ Error: {str(e)}")

def main():
    """Main script function"""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'list':
            list_admin_users()
        elif command == 'env':
            create_admin_user_from_env()
        elif command == 'help':
            print("Usage:")
            print("  python create_admin.py            - Interactive admin creation")
            print("  python create_admin.py env        - Create from environment variables")
            print("  python create_admin.py list       - List existing admin users")
            print("  python create_admin.py help       - Show this help")
        else:
            print(f"Unknown command: {command}")
            print("Use 'python create_admin.py help' for usage information")
    else:
        # Interactive mode
        create_admin_user_interactive()

if __name__ == "__main__":
    main()
