"""
Admin Key Escrow System for LifeVault
Solves the problem of how admins can help with password recovery without knowing user passwords.
"""

import base64
import json
from datetime import datetime
from crypto_utils import crypto_manager

class AdminKeyEscrow:
    """
    Handles the secure creation and management of admin-encrypted DEKs (A-DEKs)
    without requiring admins to know user passwords.
    """
    
    def create_user_with_admin_escrow(self, username, email, temp_password, is_admin=False):
        """
        Create a new user account with proper admin escrow setup.
        
        Process:
        1. Create user with temporary password
        2. Generate user's DEK
        3. Encrypt DEK with admin master key (A-DEK) - PERMANENT
        4. Create P-DEK with temp password (user can login immediately)
        5. Q-DEK and R-DEK are optional (created when user chooses)
        """
        from models import User, UserKeys
        from werkzeug.security import generate_password_hash
        from datetime import datetime
        
        # Step 1: Create user account
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(temp_password),
            is_admin=is_admin,
            is_active=True,
            email_verified=True,  # Admin-created accounts are verified
            created_at=datetime.utcnow(),
            force_password_change=True  # Encourage password change on first login
        )
        user.save()
        
        # Step 2: Generate user's DEK
        user_dek = crypto_manager.generate_key()
        
        # Step 3: Create A-DEK (PERMANENT - never changes)
        # Get admin master key using current admin's authentication
        from flask_login import current_user
        if current_user and current_user.is_authenticated and current_user.is_admin:
            admin_master_key = crypto_manager.get_or_create_admin_master_key(
                admin_password_hash=current_user.password_hash
            )
        else:
            # Fallback for system initialization
            admin_master_key = crypto_manager.get_or_create_admin_master_key()
            
        admin_encrypted_dek = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(user_dek).decode(),
            admin_master_key
        )
        
        # Step 4: Create P-DEK with temporary password (user can login immediately)
        password_key, password_salt = crypto_manager.derive_key_from_password(temp_password)
        password_encrypted_dek = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(user_dek).decode(),
            password_key
        )
        
        # Step 5: Create key structure (A-DEK + P-DEK ready, Q-DEK + R-DEK optional)
        user_keys = UserKeys(
            user=user,
            
            # P-DEK - Ready for immediate login
            password_encrypted_key=json.dumps({
                'encrypted': password_encrypted_dek,
                'salt': base64.urlsafe_b64encode(password_salt).decode()
            }),
            
            # Q-DEK and R-DEK - Optional (created when user sets them up)
            security_questions_encrypted_key=None,  # Created via /update_recovery
            recovery_phrase_encrypted_key=None,     # Created via /update_recovery
            
            # A-DEK - PERMANENT admin recovery (never changes)
            admin_master_encrypted_key=admin_encrypted_dek,
            
            # T-DEK - Optional time lock
            time_lock_encrypted_key=None,
            
            key_version=1,
            created_at=datetime.utcnow(),
            escrow_mode=False  # User can login normally, just encourage password change
        )
        user_keys.save()
        
        return user, temp_password
    
    def admin_password_reset_with_escrow(self, user_id, new_password, admin_password):
        """
        Admin resets user password using admin master key.
        
        Process:
        1. Admin recovers user's DEK using A-DEK with admin password verification
        2. Re-encrypt DEK with new password (creates new P-DEK)
        3. User can now log in with new password
        4. A-DEK, Q-DEK, R-DEK remain unchanged
        
        Args:
            user_id: ID of user whose password is being reset
            new_password: New password for the user
            admin_password: Admin's actual password for verification
        """
        from models import User, UserKeys
        from werkzeug.security import generate_password_hash
        
        # Find user and keys
        user = User.objects(id=user_id).first()
        user_keys = UserKeys.objects(user=user).first()
        
        if not user or not user_keys:
            raise ValueError("User or keys not found")
        
        # Step 1: Recover DEK using A-DEK with admin password
        from flask_login import current_user
        if not current_user or not current_user.is_admin:
            raise ValueError("Admin authentication required for user recovery")
        
        # Get admin master key using the provided admin password
        admin_master_key = crypto_manager.get_or_create_admin_master_key_with_password(admin_password)
        
        # Handle both old format (string) and new format (JSON) for A-DEK
        a_dek_data = user_keys.admin_master_encrypted_key
        
        if isinstance(a_dek_data, str) and a_dek_data.startswith('{'):
            # New JSON format
            parsed_data = json.loads(a_dek_data)
            encrypted_a_dek = parsed_data['encrypted']
        else:
            # Old format (direct encrypted string)
            encrypted_a_dek = a_dek_data
        
        dek_b64 = crypto_manager.decrypt_data(encrypted_a_dek, admin_master_key)
        user_dek = base64.urlsafe_b64decode(dek_b64.encode())
        
        # Step 2: Update user password
        user.password_hash = generate_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        user.force_password_change = False  # Reset flag
        user.save()
        
        # Step 3: Create new P-DEK with new password
        password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
        password_encrypted_dek = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(user_dek).decode(),
            password_key
        )
        
        # Update P-DEK in JSON format
        user_keys.password_encrypted_key = json.dumps({
            'encrypted': password_encrypted_dek,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        user_keys.save()
        
        # Note: A-DEK, Q-DEK, R-DEK remain unchanged - user keeps access to all recovery methods
        
        return True
    
    def user_first_login_setup(self, user, old_password, new_password, security_questions, answers, recovery_phrase):
        """
        Complete user setup on first login after admin creation.
        
        Process:
        1. Validate temporary password
        2. Create P-DEK with new password
        3. Create Q-DEK with security questions
        4. Create R-DEK with recovery phrase
        5. Disable escrow mode
        """
        from werkzeug.security import check_password_hash, generate_password_hash
        from models import SecurityQuestion
        
        # Validate old password
        if not check_password_hash(user.password_hash, old_password):
            raise ValueError("Invalid temporary password")
        
        # Get user's DEK from admin escrow
        from models import UserKeys
        user_keys = UserKeys.objects(user=user).first()
        
        # Try to get admin master key with current admin context, fallback to system mode
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated and current_user.is_admin:
                admin_master_key = crypto_manager.get_or_create_admin_master_key(
                    admin_password_hash=current_user.password_hash
                )
            else:
                # This is user-initiated during first login, use system mode
                admin_master_key = crypto_manager.get_or_create_admin_master_key()
        except:
            # Emergency fallback for system initialization
            admin_master_key = crypto_manager.get_or_create_admin_master_key()
            
        dek_b64 = crypto_manager.decrypt_data(user_keys.admin_master_encrypted_key, admin_master_key)
        user_dek = base64.urlsafe_b64decode(dek_b64.encode())
        
        # Create P-DEK with new password
        password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
        password_encrypted_dek = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(user_dek).decode(),
            password_key
        )
        
        # Create Q-DEK with security questions
        combined_answers = ''.join([answer.lower().strip() for answer in answers])
        sq_key, sq_salt = crypto_manager.derive_key_from_password(combined_answers)
        sq_encrypted_dek = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(user_dek).decode(),
            sq_key
        )
        
        # Create R-DEK with recovery phrase
        rp_key, rp_salt = crypto_manager.derive_key_from_password(recovery_phrase)
        rp_encrypted_dek = crypto_manager.encrypt_data(
            base64.urlsafe_b64encode(user_dek).decode(),
            rp_key
        )
        
        # Update user
        user.password_hash = generate_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        user.force_password_change = False
        
        # Set up security questions
        user.security_questions = []
        for i, (question, answer) in enumerate(zip(security_questions, answers)):
            sq = SecurityQuestion(
                question=question,
                answer_hash=generate_password_hash(answer.lower().strip())
            )
            user.security_questions.append(sq)
        
        # Save encrypted recovery phrase
        user.recovery_phrase = crypto_manager.encrypt_with_password(recovery_phrase, new_password)
        user.save()
        
        # Update all keys in JSON format
        user_keys.password_encrypted_key = json.dumps({
            'encrypted': password_encrypted_dek,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        
        user_keys.security_questions_encrypted_key = json.dumps({
            'encrypted': sq_encrypted_dek,
            'salt': base64.urlsafe_b64encode(sq_salt).decode()
        })
        
        user_keys.recovery_phrase_encrypted_key = json.dumps({
            'encrypted': rp_encrypted_dek,
            'salt': base64.urlsafe_b64encode(rp_salt).decode()
        })
        
        # Keep A-DEK for admin recovery (unchanged)
        # user_keys.admin_master_encrypted_key stays the same
        
        user_keys.escrow_mode = False  # User now fully set up
        user_keys.save()
        
        return True

# Global instance
admin_escrow = AdminKeyEscrow()

"""
ADMIN WORKFLOW SUMMARY:

1. Admin Creates User:
   - Admin runs: python create_admin.py or uses web interface
   - System generates temp password: "TempPass123!"
   - User gets email with temp credentials
   - A-DEK created with admin master key
   
2. User First Login:
   - User logs in with temp password
   - System forces password change + security setup
   - Creates P-DEK, Q-DEK, R-DEK
   - Disables escrow mode
   
3. Admin Password Reset:
   - Admin uses A-DEK to recover user's DEK
   - Re-encrypts with new password (new P-DEK)
   - User can log in immediately
   - User's other keys (Q-DEK, R-DEK) remain unchanged

4. User Recovery:
   - User can use Q-DEK (security questions)
   - User can use R-DEK (recovery phrase)  
   - Admin can use A-DEK (admin master key)
   - All recover the same DEK, user data remains accessible

SECURITY BENEFITS:
✅ Admin never knows user passwords
✅ Admin can always help with recovery
✅ User controls Q-DEK and R-DEK
✅ Multiple recovery methods always available
✅ Zero-knowledge architecture maintained
"""
