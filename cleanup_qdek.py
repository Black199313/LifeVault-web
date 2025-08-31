#!/usr/bin/env python3
"""
Script to clean up security questions and Q-DEK for a user to allow fresh setup
"""

import os
import sys
import mongoengine
from models import User, UserKeys
import json

# Connect to MongoDB
mongoengine.connect('lifevault', host='mongodb://localhost:27017/lifevault', connect=False)

def clean_user_qdek(username):
    """Clean up Q-DEK and security questions for a user"""
    print(f"🧹 CLEANING Q-DEK DATA FOR USER: {username}")
    print("=" * 50)
    
    # Find user
    user = User.objects(username=username).first()
    if not user:
        print(f"❌ User '{username}' not found!")
        return
    
    print(f"✅ User found: {user.username}")
    print(f"📧 Email: {user.email}")
    
    # Get user keys
    user_keys = UserKeys.objects(user=user).first()
    if not user_keys:
        print(f"❌ No UserKeys found for user!")
        return
    
    print(f"\n📋 BEFORE CLEANUP:")
    print(f"Security questions count: {len(user.security_questions) if user.security_questions else 0}")
    print(f"Q-DEK exists: {'Yes' if user_keys.security_questions_encrypted_key else 'No'}")
    if user_keys.security_questions_encrypted_key:
        print(f"Q-DEK format: {'OLD (colon)' if ':' in user_keys.security_questions_encrypted_key else 'NEW (JSON)'}")
    
    # Ask for confirmation
    confirm = input(f"\n⚠️  Are you sure you want to delete Q-DEK data for user '{username}'? (yes/no): ")
    if confirm.lower() != 'yes':
        print("❌ Operation cancelled.")
        return
    
    try:
        # Clear security questions from User model
        user.security_questions = []
        user.save()
        print("✅ Cleared security questions from User model")
        
        # Generate a placeholder Q-DEK (this will be replaced when user sets up new questions)
        # We'll use a dummy value that will be overwritten during setup
        user_keys.security_questions_encrypted_key = ""
        user_keys.save()
        print("✅ Cleared Q-DEK from UserKeys")
        
        print(f"\n🎉 CLEANUP COMPLETE!")
        print(f"📋 AFTER CLEANUP:")
        print(f"Security questions count: {len(user.security_questions)}")
        print(f"Q-DEK exists: {'Yes' if user_keys.security_questions_encrypted_key else 'No'}")
        
        print(f"\n💡 NEXT STEPS:")
        print(f"1. Start the Flask app: python main.py")
        print(f"2. Login as user '{username}'")
        print(f"3. Go to Profile → Update Recovery Options")
        print(f"4. Set up new security questions")
        print(f"5. Test the Q-DEK recovery system")
        
    except Exception as e:
        print(f"❌ Error during cleanup: {str(e)}")
        return

def show_user_status(username):
    """Show current status of user's Q-DEK setup"""
    print(f"📊 CURRENT STATUS FOR USER: {username}")
    print("=" * 40)
    
    user = User.objects(username=username).first()
    if not user:
        print(f"❌ User '{username}' not found!")
        return
    
    user_keys = UserKeys.objects(user=user).first()
    if not user_keys:
        print(f"❌ No UserKeys found for user!")
        return
    
    print(f"👤 User: {user.username}")
    print(f"📧 Email: {user.email}")
    print(f"🔐 Security questions: {len(user.security_questions) if user.security_questions else 0}")
    print(f"🗝️  Q-DEK exists: {'Yes' if user_keys.security_questions_encrypted_key else 'No'}")
    
    if user.security_questions:
        print(f"\n📋 Current Security Questions:")
        for i, sq in enumerate(user.security_questions, 1):
            print(f"  {i}. {sq.question}")
    
    if user_keys.security_questions_encrypted_key:
        print(f"\n🔍 Q-DEK Details:")
        print(f"Format: {'OLD (colon)' if ':' in user_keys.security_questions_encrypted_key else 'NEW (JSON)'}")
        print(f"Data: {user_keys.security_questions_encrypted_key[:50]}...")

if __name__ == "__main__":
    username = "sachin"  # Change this if needed
    
    print("🔧 Q-DEK CLEANUP UTILITY")
    print("=" * 30)
    
    # Show current status
    show_user_status(username)
    
    print(f"\n" + "=" * 50)
    
    # Offer cleanup
    clean_user_qdek(username)
