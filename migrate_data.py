#!/usr/bin/env python3
"""
Data Migration Script: Old vs New Encryption Keys

This script handles the migration of existing data that was encrypted with the old
broken user_id-based key system to the new proper DEK-based system.

The issue: Existing secrets were encrypted with derive_key_from_user_id() but now
we're trying to decrypt them with the real DEK from P-DEK, causing decryption failures.
"""

import sys
import os
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import CryptoManager
from models import User, UserKeys, SecretData
from app import app

def migrate_user_data():
    """Migrate existing encrypted data from old key system to new DEK system"""
    
    print("🔄 STARTING DATA MIGRATION")
    print("=" * 50)
    print("Migrating from: user_id-based keys (broken)")
    print("Migrating to: Real DEK from 5-way encryption (secure)")
    print()
    
    crypto_manager = CryptoManager()
    migration_stats = {
        'users_processed': 0,
        'secrets_migrated': 0,
        'secrets_failed': 0,
        'users_skipped': 0
    }
    
    with app.app_context():
        try:
            # Get all users who have secrets
            users_with_secrets = User.objects()
            
            for user in users_with_secrets:
                print(f"\n👤 Processing user: {user.username} (ID: {user.id})")
                migration_stats['users_processed'] += 1
                
                # Get user's keys
                user_keys = UserKeys.objects(user=str(user.id)).first()
                if not user_keys:
                    print(f"   ⚠️ No UserKeys found - user hasn't completed setup")
                    migration_stats['users_skipped'] += 1
                    continue
                
                # Get user's secrets
                user_secrets = SecretData.objects(user=user)
                if not user_secrets:
                    print(f"   ℹ️ No secrets to migrate")
                    continue
                
                print(f"   📁 Found {len(user_secrets)} secrets to migrate")
                
                # We need the user's password to get the real DEK
                # Since we don't have it, we'll offer two approaches:
                print(f"   🔑 Need user password to decrypt real DEK")
                print(f"   📝 For now, marking secrets for manual migration")
                
                for secret in user_secrets:
                    try:
                        # Try to decrypt with old method to verify it's old data
                        old_key = crypto_manager.derive_key_from_user_id(str(user.id))
                        try:
                            decrypted_content = crypto_manager.decrypt_data(secret.encrypted_content, old_key)
                            print(f"      ✅ Secret '{secret.title}' uses old encryption")
                            
                            # Mark for migration (add a migration flag)
                            secret.needs_migration = True
                            secret.save()
                            migration_stats['secrets_migrated'] += 1
                            
                        except Exception as e:
                            print(f"      ❓ Secret '{secret.title}' may already use new encryption")
                            migration_stats['secrets_failed'] += 1
                            
                    except Exception as e:
                        print(f"      ❌ Failed to process secret '{secret.title}': {str(e)}")
                        migration_stats['secrets_failed'] += 1
            
            print(f"\n📊 MIGRATION SUMMARY")
            print("=" * 50)
            print(f"Users processed: {migration_stats['users_processed']}")
            print(f"Users skipped (no keys): {migration_stats['users_skipped']}")
            print(f"Secrets marked for migration: {migration_stats['secrets_migrated']}")
            print(f"Secrets failed/already migrated: {migration_stats['secrets_failed']}")
            
            print(f"\n💡 NEXT STEPS:")
            print("1. Secrets are marked with 'needs_migration=True'")
            print("2. When users log in, we can migrate their data using their password")
            print("3. Or provide a manual migration tool that asks for passwords")
            
        except Exception as e:
            print(f"❌ Migration failed: {str(e)}")
            import traceback
            traceback.print_exc()

def create_migration_route():
    """Create a route to handle data migration during login"""
    
    migration_code = '''
# Add this to your login route after successful login:

# Check if user has data that needs migration
user_secrets = SecretData.objects(user=current_user, needs_migration=True)
if user_secrets:
    try:
        # User just logged in, so we have their password
        # Get the real DEK from session (already stored during login)
        if 'user_dek' in session:
            session_dek = bytes.fromhex(session['user_dek'])
            old_key = crypto_manager.derive_key_from_user_id(str(current_user.id))
            
            migrated_count = 0
            for secret in user_secrets:
                try:
                    # Decrypt with old key
                    old_content = crypto_manager.decrypt_data(secret.encrypted_content, old_key)
                    
                    # Re-encrypt with new DEK
                    new_content = crypto_manager.encrypt_data(old_content, session_dek)
                    
                    # Update the secret
                    secret.encrypted_content = new_content
                    secret.needs_migration = False
                    secret.save()
                    
                    migrated_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to migrate secret {secret.id}: {str(e)}")
            
            if migrated_count > 0:
                flash(f'Successfully migrated {migrated_count} secrets to new encryption!', 'success')
                
    except Exception as e:
        logger.error(f"Migration error: {str(e)}")
'''
    
    print("🔧 MIGRATION ROUTE CODE")
    print("=" * 50)
    print(migration_code)
    
    # Save to file
    with open('migration_route_code.txt', 'w') as f:
        f.write(migration_code)
    
    print("\n💾 Migration code saved to: migration_route_code.txt")

if __name__ == "__main__":
    print(f"🚀 Data Migration Tool - {datetime.now()}")
    print("Handling transition from old broken encryption to new secure encryption")
    
    print("\n🔍 Step 1: Analyze existing data")
    migrate_user_data()
    
    print(f"\n🛠️ Step 2: Generate migration route code")
    create_migration_route()
    
    print(f"\n✅ Migration analysis complete!")
    print("Review the output above and implement the migration route code.")
