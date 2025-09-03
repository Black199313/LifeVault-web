#!/usr/bin/env python3
"""
Script to verify security question answers for a specific user
"""

import os
import sys
import mongoengine
from models import User, UserKeys
from werkzeug.security import check_password_hash
import json

# Connect to MongoDB
mongoengine.connect('lifevault', host='mongodb://localhost:27017/lifevault', connect=False)

def verify_security_answers(username, test_answers):
    """Verify security question answers for a user"""
    print(f"🔍 VERIFYING SECURITY ANSWERS FOR USER: {username}")
    print("=" * 60)
    
    # Find user
    user = User.objects(username=username).first()
    if not user:
        print(f"❌ User '{username}' not found!")
        return
    
    print(f"✅ User found: {user.username}")
    print(f"📧 Email: {user.email}")
    print(f"🔐 Security questions count: {len(user.security_questions) if user.security_questions else 0}")
    
    if not user.security_questions or len(user.security_questions) != 3:
        print(f"❌ User doesn't have exactly 3 security questions set up!")
        return
    
    print(f"\n📋 SECURITY QUESTIONS AND VERIFICATION:")
    print("-" * 60)
    
    all_correct = True
    
    for i, (sq, test_answer) in enumerate(zip(user.security_questions, test_answers), 1):
        print(f"\n{i}. Question: {sq.question}")
        print(f"   Test Answer: '{test_answer}'")
        print(f"   Stored Hash: {sq.answer_hash[:50]}...")
        
        # Test the answer as-is
        is_correct_original = check_password_hash(sq.answer_hash, test_answer)
        print(f"   ✓ Original case: {is_correct_original}")
        
        # Test the answer in lowercase (as stored during setup)
        is_correct_lower = check_password_hash(sq.answer_hash, test_answer.lower())
        print(f"   ✓ Lowercase: {is_correct_lower}")
        
        # Test with strip
        is_correct_stripped = check_password_hash(sq.answer_hash, test_answer.strip())
        print(f"   ✓ Stripped: {is_correct_stripped}")
        
        # Test with lower and strip (setup format)
        is_correct_processed = check_password_hash(sq.answer_hash, test_answer.lower().strip())
        print(f"   ✓ Lower + Strip: {is_correct_processed}")
        
        if not (is_correct_original or is_correct_lower or is_correct_stripped or is_correct_processed):
            print(f"   ❌ NONE of the variations match!")
            all_correct = False
        else:
            print(f"   ✅ At least one variation matches!")
    
    print(f"\n" + "=" * 60)
    
    if all_correct:
        print(f"✅ ALL SECURITY ANSWERS ARE CORRECT!")
        print(f"The Q-DEK recovery should work with these answers.")
    else:
        print(f"❌ SOME SECURITY ANSWERS ARE INCORRECT!")
        print(f"The Q-DEK recovery will fail with these answers.")
    
    # Also test what the combined answer string would be
    print(f"\n🔗 COMBINED ANSWER TESTING:")
    print("-" * 30)
    
    # Test different combinations for Q-DEK
    processed_answers = [answer.lower().strip() for answer in test_answers]
    combined_original = ''.join(test_answers)
    combined_processed = ''.join(processed_answers)
    
    print(f"Original answers: {test_answers}")
    print(f"Processed answers: {processed_answers}")
    print(f"Combined original: '{combined_original}'")
    print(f"Combined processed: '{combined_processed}'")
    
    # Now let's also check what's in the UserKeys
    user_keys = UserKeys.objects(user=user).first()
    if user_keys and user_keys.security_questions_encrypted_key:
        print(f"\n🗝️  Q-DEK INFO:")
        print(f"Format: {'OLD (colon)' if ':' in user_keys.security_questions_encrypted_key else 'NEW (JSON)'}")
        print(f"Data: {user_keys.security_questions_encrypted_key[:80]}...")
        
        # Try to see what was actually used to encrypt the Q-DEK
        if ':' in user_keys.security_questions_encrypted_key:
            parts = user_keys.security_questions_encrypted_key.split(':', 1)
            salt_b64 = parts[0]
            print(f"Salt: {salt_b64}")
    
    return all_correct

if __name__ == "__main__":
    username = "sachin"
    test_answers = ["Test12", "Test34", "Test56"]
    
    print("🔐 SECURITY QUESTION VERIFICATION TOOL")
    print("=" * 50)
    
    result = verify_security_answers(username, test_answers)
