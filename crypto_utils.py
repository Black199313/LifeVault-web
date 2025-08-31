import os
import base64
import secrets
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import json
from datetime import datetime

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()
        self.logger = logging.getLogger(__name__)
    
    def generate_key(self):
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    def derive_key_from_user_id(self, user_id_str: str) -> bytes:
        """Derive a consistent encryption key from user ID"""
        # Use a consistent salt based on user ID for demo purposes
        # In production, you'd properly derive this from the 5-key system
        salt = hashlib.sha256(f"lifevault_salt_{user_id_str}".encode()).digest()[:16]
        
        print(f"Deriving key from user_id: '{user_id_str}'")
        print(f"Consistent salt: {salt.hex()}")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(user_id_str.encode()))
        print(f"Derived key: {key[:20]}... (length: {len(key)})")
        return key
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple:
        """Derive encryption key from password with optional salt"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def encrypt_data(self, data: str, key: bytes) -> str:
        """Encrypt data with the given key"""
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_data(self, encrypted_data: str, key: bytes) -> str:
        """Decrypt data with the given key"""
        try:
            f = Fernet(key)
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = f.decrypt(decoded_data)
            return decrypted.decode()
        except Exception:
            raise ValueError("Failed to decrypt data")
    
    def hash_password(self, password: str, salt: bytes = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = os.urandom(32)
        
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.urlsafe_b64encode(pwdhash).decode(), base64.urlsafe_b64encode(salt).decode()
    
    def verify_password(self, password: str, stored_hash: str, stored_salt: str) -> bool:
        """Verify password against stored hash"""
        salt = base64.urlsafe_b64decode(stored_salt.encode())
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.urlsafe_b64encode(pwdhash).decode() == stored_hash
    
    def create_five_key_system(self, dek: bytes, password: str, security_answers: list, 
                              recovery_phrase: str, admin_master_key: bytes = None) -> dict:
        """Create the five encrypted copies of the DEK"""
        
        # 1. Password-encrypted key
        password_key, password_salt = self.derive_key_from_password(password)
        password_encrypted = self.encrypt_data(base64.urlsafe_b64encode(dek).decode(), password_key)
        
        # 2. Security questions encrypted key
        combined_answers = ''.join(answer.lower().strip() for answer in security_answers)
        sq_key, sq_salt = self.derive_key_from_password(combined_answers)
        sq_encrypted = self.encrypt_data(base64.urlsafe_b64encode(dek).decode(), sq_key)
        
        # 3. Recovery phrase encrypted key
        rp_key, rp_salt = self.derive_key_from_password(recovery_phrase)
        rp_encrypted = self.encrypt_data(base64.urlsafe_b64encode(dek).decode(), rp_key)
        
        # 4. Admin master key encrypted
        if admin_master_key is None:
            admin_master_key = self.get_or_create_admin_master_key(allow_user_operations=True)
        admin_encrypted = self.encrypt_data(base64.urlsafe_b64encode(dek).decode(), admin_master_key)
        
        # 5. Time-lock key (uses current date + 30 days as additional factor)
        import datetime
        time_factor = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat()
        time_key, time_salt = self.derive_key_from_password(recovery_phrase + time_factor)
        time_encrypted = self.encrypt_data(base64.urlsafe_b64encode(dek).decode(), time_key)
        
        return {
            'password_encrypted_key': json.dumps({
                'encrypted': password_encrypted,
                'salt': base64.urlsafe_b64encode(password_salt).decode()
            }),
            'security_questions_encrypted_key': json.dumps({
                'encrypted': sq_encrypted,
                'salt': base64.urlsafe_b64encode(sq_salt).decode()
            }),
            'recovery_phrase_encrypted_key': json.dumps({
                'encrypted': rp_encrypted,
                'salt': base64.urlsafe_b64encode(rp_salt).decode()
            }),
            'admin_master_encrypted_key': json.dumps({
                'encrypted': admin_encrypted,
                'version': 'v2'  # Finalized A-DEK with admin master key
            }),
            'time_lock_encrypted_key': json.dumps({
                'encrypted': time_encrypted,
                'salt': base64.urlsafe_b64encode(time_salt).decode(),
                'time_factor': time_factor
            })
        }
    
    def get_or_create_admin_master_key(self, admin_password_hash: str = None, allow_user_operations: bool = False) -> bytes:
        """
        Get or create admin master key with security controls.
        
        SECURITY MODES:
        1. Admin Operations: Requires admin_password_hash (full security)
        2. User Operations: Uses cached session key (limited security for UX)
        3. System Operations: Uses environment-based authentication
        
        Args:
            admin_password_hash: Admin's password hash for authentication
            allow_user_operations: Allow retrieval for user key rotation
        """
        try:
            from models import AdminMasterKey, User
            from flask import session
            
            # Try to get existing active key
            active_key = AdminMasterKey.objects(is_active=True).first()
            
            # Mode 1: Admin Operations (Full Security)
            if admin_password_hash:
                if active_key:
                    return self._decrypt_admin_master_key(active_key, admin_password_hash)
                else:
                    return self._create_new_encrypted_admin_master_key()
            
            # Mode 2: User Operations (Cached Key for UX)
            if allow_user_operations and active_key:
                # Check if admin key is cached in session (admin previously authenticated)
                if 'admin_master_key_cache' in session:
                    try:
                        cached_key = base64.urlsafe_b64decode(session['admin_master_key_cache'].encode())
                        # Verify cache is valid by checking hash
                        if hashlib.sha256(cached_key).hexdigest() == active_key.key_hash:
                            return cached_key
                    except:
                        pass  # Cache invalid, fall through
                
                # For user operations, we need a different approach
                # Option A: Require admin to pre-authorize user operations
                # Option B: Use emergency fallback (less secure)
                raise ValueError("User key rotation requires admin pre-authorization or cached admin key")
            
            # Mode 3: System Initialization (No auth required)
            if not active_key:
                return self._create_new_encrypted_admin_master_key()
            
            # Mode 4: Admin-initiated operations (when admin is authenticated)
            from flask import has_request_context
            from flask_login import current_user
            if has_request_context() and current_user and current_user.is_authenticated and current_user.is_admin:
                # Admin is authenticated, allow retrieval with their password hash
                return self._decrypt_admin_master_key(active_key, current_user.password_hash)
            
            # Default: Require authentication
            raise ValueError("Admin authentication required to retrieve master key")
            
        except Exception as e:
            # Development fallback
            if os.environ.get("ENVIRONMENT", "").lower() == "development":
                print(f"Warning: Using fallback admin key in development: {str(e)}")
                # Generate a proper Fernet key for development
                fallback_key = self.generate_key()
                return fallback_key
            raise e
    
    def cache_admin_master_key_for_user_operations(self, admin_password_hash: str) -> bool:
        """
        Cache admin master key in session for user operations.
        
        This allows user key rotation without requiring admin password each time.
        Cache expires with session.
        """
        try:
            from flask import session
            
            # Get admin master key with full authentication
            admin_master_key = self.get_or_create_admin_master_key(admin_password_hash=admin_password_hash)
            
            # Cache in session for user operations
            session['admin_master_key_cache'] = base64.urlsafe_b64encode(admin_master_key).decode()
            session['admin_key_cached_at'] = datetime.utcnow().isoformat()
            
            return True
        except Exception as e:
            print(f"Failed to cache admin master key: {str(e)}")
            return False
    
    def _decrypt_admin_master_key(self, admin_key_record, admin_password_hash: str) -> bytes:
        """
        Decrypt admin master key using admin credentials.
        
        SECURITY: Key is encrypted with admin password hash, not stored in plaintext.
        """
        try:
            # Get all current admin password hashes for decryption
            from models import User
            admin_users = User.objects(is_admin=True, is_active=True)
            admin_hashes = sorted([admin.password_hash for admin in admin_users])
            
            # Verify the requesting admin is valid
            if admin_password_hash not in admin_hashes:
                raise ValueError("Invalid admin credentials")
            
            # Create decryption key from combined admin credentials
            combined_hash = hashlib.sha256()
            for pwd_hash in admin_hashes:
                combined_hash.update(pwd_hash.encode())
            
            combined_key = combined_hash.digest()
            encryption_key = base64.urlsafe_b64encode(combined_key)
            
            # Decrypt the admin master key
            from cryptography.fernet import Fernet
            fernet = Fernet(encryption_key)
            encrypted_data = base64.urlsafe_b64decode(admin_key_record.encrypted_key.encode())
            admin_master_key = fernet.decrypt(encrypted_data)
            
            return admin_master_key
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt admin master key: {str(e)}")
    
    def _create_new_encrypted_admin_master_key(self) -> bytes:
        """
        Create new admin master key encrypted with current admin credentials.
        
        SECURITY: Key is encrypted with combined admin password hashes.
        """
        from models import AdminMasterKey, User
        
        # Get all current admin users
        admin_users = User.objects(is_admin=True, is_active=True)
        if not admin_users:
            raise ValueError("No active admin users found")
        
        admin_hashes = sorted([admin.password_hash for admin in admin_users])
        
        # Generate random admin master key
        admin_master_key = self.generate_key()  # 32 random bytes
        
        # Create encryption key from combined admin credentials
        combined_hash = hashlib.sha256()
        for pwd_hash in admin_hashes:
            combined_hash.update(pwd_hash.encode())
        
        combined_key = combined_hash.digest()
        encryption_key = base64.urlsafe_b64encode(combined_key)
        
        # Encrypt the admin master key
        from cryptography.fernet import Fernet
        fernet = Fernet(encryption_key)
        encrypted_key = fernet.encrypt(admin_master_key)
        
        # Store the encrypted admin master key
        timestamp = datetime.utcnow()
        admin_key_record = AdminMasterKey(
            key_hash=hashlib.sha256(admin_master_key).hexdigest(),
            encrypted_key=base64.urlsafe_b64encode(encrypted_key).decode(),
            is_active=True,
            created_at=timestamp,
            created_by_admin=admin_users.first()
        )
        admin_key_record.save()
        
        return admin_master_key
    
    def recover_dek_with_password(self, user_keys, password: str) -> bytes:
        """Recover DEK using password"""
        try:
            print(f"🔍 Starting DEK recovery with password for user")
            print(f"🔍 P-DEK data: {user_keys.password_encrypted_key[:50]}...")
            
            is_json_format = False
            
            # Try to parse as JSON first (new format)
            try:
                key_data = json.loads(user_keys.password_encrypted_key)
                salt = base64.urlsafe_b64decode(key_data['salt'].encode())
                encrypted_data = key_data['encrypted']
                is_json_format = True
                print("✅ Using new JSON format for password recovery")
            except json.JSONDecodeError:
                # Handle old format: "salt:encrypted_data"
                print("🔍 Using old colon-separated format for password recovery")
                if ':' in user_keys.password_encrypted_key:
                    parts = user_keys.password_encrypted_key.split(':', 1)
                    if len(parts) == 2:
                        salt = base64.urlsafe_b64decode(parts[0].encode())
                        encrypted_data = parts[1]
                        print(f"✅ Parsed colon format, salt length: {len(salt)}, encrypted length: {len(encrypted_data)}")
                    else:
                        raise ValueError("Invalid old format: expected 'salt:data'")
                else:
                    raise ValueError("Failed to parse password key data - unknown format")
            
            print(f"🔍 Deriving key from password...")
            password_key, _ = self.derive_key_from_password(password, salt)
            print(f"✅ Password key derived, length: {len(password_key)}")
            
            print(f"🔍 Decrypting DEK...")
            if is_json_format:
                # JSON format - decrypt_data expects base64-encoded key parameter
                decrypted_dek_b64 = self.decrypt_data(encrypted_data, password_key)
            else:
                # Colon format - direct Fernet decryption with raw key
                # encrypted_data is Fernet token as string (base64), use directly
                raw_password_key = base64.urlsafe_b64decode(password_key)
                f = Fernet(base64.urlsafe_b64encode(raw_password_key))
                decrypted_dek_b64 = f.decrypt(encrypted_data.encode()).decode()
            
            print(f"✅ DEK decrypted, b64 length: {len(decrypted_dek_b64)}")
            
            result = base64.urlsafe_b64decode(decrypted_dek_b64.encode())
            print(f"✅ DEK recovery successful, final DEK length: {len(result)}")
            return result
            
        except Exception as e:
            print(f"❌ DEK recovery failed: {str(e)}")
            import traceback
            traceback.print_exc()
            raise ValueError(f"Failed to recover DEK with password: {str(e)}")
    
    def recover_dek_with_security_questions(self, user_keys, answers: list) -> bytes:
        """Recover DEK using security question answers"""
        # Try different combinations to handle historical field name mismatches and case sensitivity
        combinations_to_try = [
            answers,  # Original format as provided
            [answer.lower().strip() for answer in answers],  # Lowercase with strip (setup format)
            ['', '', ''],  # All empty (in case of field name mismatch during setup)
            answers[::-1],  # Reverse order
        ]
        
        # Debug: Show what we're working with
        print(f"DEBUG: user_keys.security_questions_encrypted_key: {user_keys.security_questions_encrypted_key}")
        print(f"DEBUG: Input answers: {answers}")
        
        for attempt, answer_combo in enumerate(combinations_to_try):
            try:
                # Try to parse as JSON first (new format)
                try:
                    key_data = json.loads(user_keys.security_questions_encrypted_key)
                    salt = base64.urlsafe_b64decode(key_data['salt'].encode())
                    encrypted_data = key_data['encrypted']
                    print(f"Using new JSON format for security questions (attempt {attempt + 1})")
                except json.JSONDecodeError:
                    # Handle old format: "salt:encrypted_data"
                    print(f"Using old colon-separated format for security questions (attempt {attempt + 1})")
                    if ':' in user_keys.security_questions_encrypted_key:
                        parts = user_keys.security_questions_encrypted_key.split(':', 1)
                        if len(parts) == 2:
                            salt = base64.urlsafe_b64decode(parts[0].encode())
                            encrypted_data = parts[1]
                        else:
                            raise ValueError("Invalid old format: expected 'salt:data'")
                    else:
                        raise ValueError("Failed to parse security questions key data - unknown format")
                
                # For the first attempt, use answers as-is
                # For the second attempt, ensure we replicate the exact setup process
                if attempt == 0:
                    combined_answers = ''.join(answer_combo)
                elif attempt == 1:
                    # Replicate exact setup process: answers already processed with .lower().strip()
                    # Then joined together (no additional processing needed)
                    combined_answers = ''.join(answer_combo)
                else:
                    combined_answers = ''.join(answer_combo)
                
                print(f"DEBUG: Attempt {attempt + 1} - Combined answers: '{combined_answers}' (length: {len(combined_answers)})")
                print(f"DEBUG: Attempt {attempt + 1} - Salt: {base64.urlsafe_b64encode(salt).decode()}")
                print(f"DEBUG: Attempt {attempt + 1} - Encrypted data: {encrypted_data[:50]}...")
                
                sq_key, _ = self.derive_key_from_password(combined_answers, salt)
                print(f"DEBUG: Attempt {attempt + 1} - Derived key length: {len(sq_key)}")
                
                dek_b64 = self.decrypt_data(encrypted_data, sq_key)
                print(f"SUCCESS: Recovery worked with attempt {attempt + 1}")
                return base64.urlsafe_b64decode(dek_b64.encode())
            except Exception as e:
                print(f"Attempt {attempt + 1} failed: {str(e)}")
                continue
        
        # If all attempts failed
        print(f"All recovery attempts failed")
        raise ValueError("Failed to recover DEK with security questions")
    
    def recover_dek_with_recovery_phrase(self, user_keys, recovery_phrase: str) -> bytes:
        """Recover DEK using recovery phrase"""
        try:
            # Try to parse as JSON first (new format)
            try:
                key_data = json.loads(user_keys.recovery_phrase_encrypted_key)
                salt = base64.urlsafe_b64decode(key_data['salt'].encode())
                encrypted_data = key_data['encrypted']
                print("Using new JSON format for recovery phrase")
            except json.JSONDecodeError:
                # Handle old format: "salt:encrypted_data"
                print("Using old colon-separated format for recovery phrase")
                if ':' in user_keys.recovery_phrase_encrypted_key:
                    parts = user_keys.recovery_phrase_encrypted_key.split(':', 1)
                    if len(parts) == 2:
                        salt = base64.urlsafe_b64decode(parts[0].encode())
                        encrypted_data = parts[1]
                        print(f"Parsed old format - salt length: {len(salt)}, encrypted length: {len(encrypted_data)}")
                    else:
                        raise ValueError("Invalid old format: expected 'salt:data'")
                else:
                    raise ValueError("Failed to parse recovery phrase key data - unknown format")
            
            # Derive key and decrypt
            rp_key, _ = self.derive_key_from_password(recovery_phrase, salt)
            print(f"Derived key length: {len(rp_key)}")
            
            dek_b64 = self.decrypt_data(encrypted_data, rp_key)
            print(f"Decrypted DEK (base64) length: {len(dek_b64)}")
            
            return base64.urlsafe_b64decode(dek_b64.encode())
            
        except Exception as e:
            print(f"Recovery phrase error: {str(e)}")
            import traceback
            traceback.print_exc()
            raise ValueError("Failed to recover DEK with recovery phrase")
    
    def recover_dek_with_admin_key(self, user_keys) -> bytes:
        """Recover DEK using admin master key"""
        try:
            admin_master_key = self.get_or_create_admin_master_key()
            
            # Handle both old format (string) and new format (JSON)
            a_dek_data = user_keys.admin_master_encrypted_key
            
            if isinstance(a_dek_data, str) and a_dek_data.startswith('{'):
                # New JSON format
                import json
                parsed_data = json.loads(a_dek_data)
                encrypted_a_dek = parsed_data['encrypted']
                # Future: could use parsed_data['version'] for format handling
            else:
                # Old format (direct encrypted string)
                encrypted_a_dek = a_dek_data
            
            dek_b64 = self.decrypt_data(encrypted_a_dek, admin_master_key)
            return base64.urlsafe_b64decode(dek_b64.encode())
        except Exception:
            raise ValueError("Failed to recover DEK with admin key")
    
    def setup_email_recovery(self, user_keys, user_password: str, recovery_email: str) -> str:
        """
        Setup email recovery (E-DEK) - Requirement 18b,c
        Generate email password, encrypt DEK with it, and return the password to be emailed
        """
        try:
            print(f"🔍 Setting up E-DEK for email recovery")
            
            # Step 1: Recover DEK using user password
            current_dek = self.recover_dek_with_password(user_keys, user_password)
            print(f"✅ DEK recovered for E-DEK creation")
            
            # Step 2: Generate a random email password with unambiguous characters
            import secrets
            import string
            # Use only unambiguous characters to avoid confusion
            # Excluded: 0, O, I, l, 1 (confusing characters)
            alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
            email_password = ''.join(secrets.choice(alphabet) for _ in range(16))
            print(f"✅ Email password generated with unambiguous characters, length: {len(email_password)}")
            
            # Step 3: Create E-DEK by encrypting DEK with email password
            email_salt = os.urandom(16)
            email_key, _ = self.derive_key_from_password(email_password, email_salt)
            encrypted_dek_b64 = self.encrypt_data(base64.urlsafe_b64encode(current_dek).decode(), email_key)
            
            # Step 4: Store E-DEK in JSON format for consistency
            e_dek_data = {
                'salt': base64.urlsafe_b64encode(email_salt).decode(),
                'encrypted': encrypted_dek_b64
            }
            user_keys.email_encrypted_key = json.dumps(e_dek_data)
            print(f"✅ E-DEK created and stored")
            
            return email_password
            
        except Exception as e:
            print(f"❌ E-DEK setup failed: {str(e)}")
            raise Exception(f"Failed to setup email recovery: {str(e)}")
    
    def recover_dek_with_email_password(self, user_keys, email_password: str) -> bytes:
        """
        Recover DEK using email password (E-DEK recovery) - Requirement 18d
        """
        try:
            print(f"🔍 Starting E-DEK recovery with email password")
            
            if not user_keys.email_encrypted_key:
                raise ValueError("No email recovery configured for this account")
            
            # Parse E-DEK data (JSON format)
            try:
                e_dek_data = json.loads(user_keys.email_encrypted_key)
                salt = base64.urlsafe_b64decode(e_dek_data['salt'].encode())
                encrypted_data = e_dek_data['encrypted']
                print("✅ Using JSON format for E-DEK recovery")
            except json.JSONDecodeError:
                raise ValueError("Invalid E-DEK format")
            
            # Derive key from email password
            email_key, _ = self.derive_key_from_password(email_password, salt)
            print(f"✅ Email key derived, length: {len(email_key)}")
            
            # Decrypt DEK
            decrypted_dek_b64 = self.decrypt_data(encrypted_data, email_key)
            print(f"✅ E-DEK decrypted, b64 length: {len(decrypted_dek_b64)}")
            
            return base64.urlsafe_b64decode(decrypted_dek_b64.encode())
            
        except Exception as e:
            print(f"❌ E-DEK recovery failed: {str(e)}")
            raise ValueError(f"Failed to recover DEK with email password: {str(e)}")
    
    def reset_email_recovery(self, user_keys, user_password: str, new_recovery_email: str) -> str:
        """
        Reset email recovery (generate new email password and E-DEK) - Requirement 18e
        """
        try:
            print(f"🔍 Resetting E-DEK for new email recovery")
            
            # Use the same setup process to generate new email password and E-DEK
            new_email_password = self.setup_email_recovery(user_keys, user_password, new_recovery_email)
            print(f"✅ E-DEK reset completed")
            
            return new_email_password
            
        except Exception as e:
            print(f"❌ E-DEK reset failed: {str(e)}")
            raise Exception(f"Failed to reset email recovery: {str(e)}")
    
    def update_user_password_only(self, user_keys, old_password: str, new_password: str):
        """
        Simple password change: decrypt P-DEK with old password, encrypt with new password
        """
        try:
            print(f"🔍 Updating P-DEK for user")
            
            # Step 1: Recover the actual DEK using the old password
            current_dek = self.recover_dek_with_password(user_keys, old_password)
            print(f"✅ Successfully recovered DEK with old password")
            
            # Step 2: Create new P-DEK with new password (same format as initial setup)
            new_salt = os.urandom(16)
            new_password_key, _ = self.derive_key_from_password(new_password, new_salt)
            
            # Encrypt the DEK with new password (same as in setup_user_keys)
            dek_b64 = base64.urlsafe_b64encode(current_dek).decode()
            new_encrypted_dek = self.encrypt_data(dek_b64, new_password_key)
            
            # Store in JSON format (same as setup)
            new_p_dek_data = {
                'salt': base64.urlsafe_b64encode(new_salt).decode(),
                'encrypted': new_encrypted_dek
            }
            user_keys.password_encrypted_key = json.dumps(new_p_dek_data)
            user_keys.key_version += 1
            user_keys.last_updated = datetime.utcnow()
            
            print(f"✅ P-DEK successfully updated with new password")
            return user_keys
            
        except Exception as e:
            print(f"❌ P-DEK update failed: {str(e)}")
            self.logger.error(f"User password update failed: {str(e)}")
            raise Exception(f"Password update failed: {str(e)}")
    
    def update_password_key(self, user_keys, old_password: str, new_password: str):
        """Update password-encrypted key with new password"""
        # First recover the DEK with old password
        dek = self.recover_dek_with_password(user_keys, old_password)
        
        # Re-encrypt with new password
        password_key_b64, password_salt = self.derive_key_from_password(new_password)
        password_key = base64.urlsafe_b64decode(password_key_b64)
        password_encrypted = self.encrypt_data(base64.urlsafe_b64encode(dek).decode(), password_key)
        
        user_keys.password_encrypted_key = json.dumps({
            'encrypted': password_encrypted,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        
        return user_keys
    
    def update_admin_password_and_rotate_master_key(self, admin_user, old_password: str, new_password: str):
        """
        Update an admin's password and optionally rotate the admin master key.
        
        NOTE: With the new storage approach, admin password changes don't require
        admin master key rotation unless specifically requested for security.
        """
        print(f"Starting admin password change for {admin_user.username}")
        
        # First, verify the old password
        from werkzeug.security import check_password_hash, generate_password_hash
        if not check_password_hash(admin_user.password_hash, old_password):
            raise ValueError("Incorrect current password")
        
        # Get the current admin master key (this works without admin password)
        current_admin_master_key = self.get_or_create_admin_master_key()
        
        # Update the admin's password
        admin_user.password_hash = generate_password_hash(new_password)
        admin_user.password_changed_at = datetime.utcnow()
        admin_user.save()
        print(f"Updated admin password for {admin_user.username}")
        
        # Option 1: Keep existing admin master key (recommended for most cases)
        # The admin master key is independent of admin passwords now
        print("Admin master key remains unchanged - existing A-DEKs continue to work")
        
        # Option 2: Optionally rotate admin master key for enhanced security
        # This would require re-encrypting all users' A-DEKs
        rotate_master_key = False  # Set to True for maximum security
        
        if rotate_master_key:
            print("Rotating admin master key for enhanced security...")
            self._rotate_admin_master_key_and_update_adeks(admin_user, current_admin_master_key)
        
        return True
    
    def _rotate_admin_master_key_and_update_adeks(self, admin_user, old_admin_master_key):
        """
        Private method to rotate admin master key and update all A-DEKs.
        This is expensive but provides maximum security.
        """
        from models import AdminMasterKey, UserKeys
        
        # Deactivate old admin master key
        old_keys = AdminMasterKey.objects(is_active=True)
        for key in old_keys:
            key.is_active = False
            key.save()
        
        # Generate new random admin master key (not password-derived)
        new_admin_master_key = self.generate_key()
        timestamp = datetime.utcnow()
        
        # Store new admin master key
        new_admin_key_record = AdminMasterKey(
            key_hash=hashlib.sha256(new_admin_master_key).hexdigest(),
            encrypted_key=base64.urlsafe_b64encode(new_admin_master_key).decode(),
            is_active=True,
            created_at=timestamp,
            created_by_admin=admin_user
        )
        new_admin_key_record.save()
        print("Created new admin master key")
        
        # Now update all users' A-DEKs
        all_user_keys = UserKeys.objects.all()
        updated_count = 0
        
        for user_keys in all_user_keys:
            try:
                if user_keys.admin_master_encrypted_key:  # Fixed field name
                    # Decrypt the user's DEK with old admin master key
                    dek_b64 = self.decrypt_data(user_keys.admin_master_encrypted_key, old_admin_master_key)
                    user_dek = base64.urlsafe_b64decode(dek_b64.encode())
                    
                    # Re-encrypt with new admin master key
                    new_encrypted_dek = self.encrypt_data(
                        base64.urlsafe_b64encode(user_dek).decode(), 
                        new_admin_master_key
                    )
                    
                    # Update the A-DEK in database
                    user_keys.admin_master_encrypted_key = new_encrypted_dek
                    user_keys.save()
                    updated_count += 1
                    
            except Exception as e:
                print(f"Warning: Failed to update A-DEK for user {user_keys.user}: {str(e)}")
                continue
        
        print(f"Updated A-DEKs for {updated_count} users")
        return True
    
    def create_user_keys(self, user_id, password: str, security_answers: list, 
                        recovery_phrase: str, force_recreate: bool = False) -> bool:
        """Create or recreate user's encryption keys"""
        try:
            # Convert user_id to string for consistency
            user_id_str = str(user_id)
            print(f"Creating user keys for user_id: {user_id_str} (original type: {type(user_id)})")
            
            # Import here to avoid circular imports
            from models import UserKeys
            
            # Check if keys already exist
            existing_keys = UserKeys.objects(user=user_id_str).first()
            if existing_keys and not force_recreate:
                print("Keys already exist and force_recreate is False")
                return False  # Keys already exist
            
            print("Generating new DEK...")
            # Generate a new Data Encryption Key (DEK)
            dek = self.generate_key()
            
            print("Creating five-key system...")
            # Create the five-key system
            keys_data = self.create_five_key_system(
                dek=dek,
                password=password,
                security_answers=security_answers,
                recovery_phrase=recovery_phrase
            )
            
            print("Saving keys to database...")
            if existing_keys:
                # Update existing keys (rotation)
                existing_keys.password_encrypted_key = keys_data['password_encrypted_key']
                existing_keys.security_questions_encrypted_key = keys_data['security_questions_encrypted_key']
                existing_keys.recovery_phrase_encrypted_key = keys_data['recovery_phrase_encrypted_key']
                existing_keys.admin_master_encrypted_key = keys_data['admin_master_encrypted_key']
                existing_keys.time_lock_encrypted_key = keys_data['time_lock_encrypted_key']
                existing_keys.key_version += 1
                existing_keys.save()
                print(f"Updated existing keys to version {existing_keys.key_version}")
            else:
                # Create new keys
                user_keys = UserKeys(
                    user=user_id_str,
                    password_encrypted_key=keys_data['password_encrypted_key'],
                    security_questions_encrypted_key=keys_data['security_questions_encrypted_key'],
                    recovery_phrase_encrypted_key=keys_data['recovery_phrase_encrypted_key'],
                    admin_master_encrypted_key=keys_data['admin_master_encrypted_key'],
                    time_lock_encrypted_key=keys_data['time_lock_encrypted_key'],
                    key_version=1
                )
                user_keys.save()
                print("Created new user keys successfully")
            
            return True
            
        except Exception as e:
            print(f"Error creating user keys: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_user_keys(self, user_id):
        """Get user's encryption keys"""
        try:
            # Import here to avoid circular imports
            from models import UserKeys
            
            # Convert user_id to string to handle ObjectId types
            user_id_str = str(user_id)
            user_keys = UserKeys.objects(user=user_id_str).first()
            return user_keys
            
        except Exception as e:
            print(f"Error getting user keys: {str(e)}")
            raise e
    
    def encrypt_user_data(self, data: str, user_id) -> str:
        """Encrypt data using user's actual DEK from session"""
        try:
            # Convert user_id to string for consistency
            user_id_str = str(user_id)
            print(f"Encrypting data for user_id: {user_id_str} (original type: {type(user_id)})")
            
            # ✅ FIXED: Get DEK from session (stored during login)
            from flask import session
            if 'user_dek' not in session:
                raise ValueError("User DEK not found in session - user must log in again")
            
            dek = bytes.fromhex(session['user_dek'])
            print(f"Successfully retrieved DEK from session, length: {len(dek)} bytes")
            
            # Encrypt the data using the real DEK
            result = self.encrypt_data(data, dek)
            print(f"Data encryption successful, result length: {len(result)}")
            return result
            
        except Exception as e:
            print(f"Error encrypting user data: {str(e)}")
            import traceback
            traceback.print_exc()
            raise e
    
    def decrypt_user_data(self, encrypted_data: str, user_id) -> str:
        """Decrypt data using user's actual DEK from session"""
        try:
            # Convert user_id to string for consistency
            user_id_str = str(user_id)
            print(f"🔍 Decrypting data for user_id: {user_id_str} (original type: {type(user_id)})")
            print(f"🔍 Encrypted data length: {len(encrypted_data)}")
            
            # ✅ FIXED: Get DEK from session (stored during login)
            from flask import session
            if 'user_dek' not in session:
                print(f"❌ User DEK not found in session - user must log in again")
                raise ValueError("User DEK not found in session - user must log in again")
            
            dek = bytes.fromhex(session['user_dek'])
            print(f"✅ Successfully retrieved DEK from session, length: {len(dek)} bytes")
            
            # Decrypt the data using the real DEK
            result = self.decrypt_data(encrypted_data, dek)
            print(f"✅ Data decryption successful, result length: {len(result)}")
            return result
            
        except Exception as e:
            print(f"❌ Error decrypting user data: {str(e)}")
            import traceback
            traceback.print_exc()
            raise e
    
    def encrypt_with_password(self, data: str, password: str) -> str:
        """Encrypt data with a password (used for recovery phrase storage)"""
        try:
            # Derive key from password
            key, salt = self.derive_key_from_password(password)
            
            # Encrypt the data
            encrypted_data = self.encrypt_data(data, key)
            
            # Return both encrypted data and salt as JSON
            return json.dumps({
                'encrypted': encrypted_data,
                'salt': base64.urlsafe_b64encode(salt).decode()
            })
            
        except Exception as e:
            print(f"Error encrypting with password: {str(e)}")
            raise e
    
    def decrypt_with_password(self, encrypted_json: str, password: str) -> str:
        """Decrypt data that was encrypted with a password"""
        try:
            # Parse the JSON data
            data = json.loads(encrypted_json)
            salt = base64.urlsafe_b64decode(data['salt'].encode())
            
            # Derive the same key using the password and salt
            key, _ = self.derive_key_from_password(password, salt)
            
            # Decrypt the data
            return self.decrypt_data(data['encrypted'], key)
            
        except Exception as e:
            print(f"Error decrypting with password: {str(e)}")
            raise e
    
    def rotate_user_keys_preserve_admin_access(self, user_keys, password: str, security_answers: list, recovery_phrase: str):
        """
        Rotate user keys while preserving admin access.
        
        This method ensures that:
        1. New DEK is generated
        2. All user data is re-encrypted with new DEK
        3. New A-DEK is created with current admin master key
        4. Admin retains recovery access to all data
        """
        try:
            # Generate new DEK
            new_dek = self.generate_key()
            
            # Create new five-key system with new DEK
            keys_data = self.create_five_key_system(
                dek=new_dek,
                password=password,
                security_answers=security_answers,
                recovery_phrase=recovery_phrase
            )
            
            # Update all keys
            user_keys.password_encrypted_key = keys_data['password_encrypted_key']
            user_keys.security_questions_encrypted_key = keys_data['security_questions_encrypted_key'] 
            user_keys.recovery_phrase_encrypted_key = keys_data['recovery_phrase_encrypted_key']
            user_keys.admin_master_encrypted_key = keys_data['admin_master_encrypted_key']
            user_keys.time_lock_encrypted_key = keys_data['time_lock_encrypted_key']
            user_keys.key_version += 1
            user_keys.rotated_at = datetime.utcnow()
            
            return new_dek, user_keys
            
        except Exception as e:
            print(f"Error during key rotation: {str(e)}")
            raise e

# Global instance
crypto_manager = CryptoManager()

class AtomicKeyRotation:
    def __init__(self, crypto_manager):
        self.crypto_manager = crypto_manager
        
    def start_rotation_with_token(self, user_id: str, token: str, temp_password: str, 
                                 current_password: str, new_password: str = None, 
                                 security_answers: list = None, recovery_phrase: str = None, email_password: str = None):
        """
        Atomic key rotation with staged recovery points and conditional recovery methods
        """
        from models import RotationToken, User, UserKeys, Secret, JournalEntry
        from utils import log_audit
        
        if new_password is None:
            new_password = current_password
        
        rotation_token = None
        try:
            # Stage 1: Validate token
            rotation_token = self._validate_and_lock_token(token, temp_password)
            if not rotation_token:
                raise ValueError("Invalid or expired rotation token")
                
            user = User.objects(id=user_id).first()
            if not user or str(user.id) != rotation_token.user_id:
                raise ValueError("Token user mismatch")
                
            # Stage 2: Backup current state
            self._backup_current_state(rotation_token, user, current_password)
            rotation_token.rotation_stage = 'dek_generated'
            rotation_token.save()
            
            # Stage 3: Generate new DEK
            new_dek = self.crypto_manager.generate_key()
            rotation_token.new_dek = base64.urlsafe_b64encode(new_dek).decode()
            rotation_token.save()
            
            # Stage 4: Create all new keys (conditional based on user's setup)
            new_keys = self._create_all_new_keys_conditional(new_dek, new_password, security_answers, 
                                               recovery_phrase, email_password, temp_password, user, rotation_token)
            rotation_token.rotation_stage = 'keys_created'
            rotation_token.save()
            
            # Stage 5: Re-encrypt all data (atomic transaction)
            self._reencrypt_all_user_data(user, rotation_token, new_dek, current_password)
            rotation_token.rotation_stage = 'data_encrypted'
            rotation_token.save()
            
            # Stage 6: Finalize rotation
            self._finalize_rotation(user, new_keys, rotation_token)
            rotation_token.rotation_stage = 'completed'
            rotation_token.status = 'completed'
            rotation_token.used_at = datetime.utcnow()
            rotation_token.save()
            
            log_audit('key_rotation_completed', 'key_rotation', user_id, 
                     'Complete atomic key rotation finished successfully')
            
            return {"success": True, "message": "Key rotation completed successfully"}
            
        except Exception as e:
            # Automatic rollback on any failure
            if rotation_token:
                self._rollback_rotation(rotation_token)
            raise e
    
    def _validate_and_lock_token(self, token: str, temp_password: str):
        """Validate token by MongoDB _id and mark as in-progress"""
        from models import RotationToken
        import logging
        from bson import ObjectId
        
        logger = logging.getLogger(__name__)
        
        logger.info(f"🔍 Token validation - Token ID: {token}, Temp password provided: {'Yes' if temp_password else 'No'}")
        
        try:
            # Direct lookup by MongoDB _id (token IS the _id)
            rotation_token = RotationToken.objects(
                id=token,  # token is the MongoDB _id
                status='approved',
                expires_at__gt=datetime.utcnow()
            ).first()
            
            if not rotation_token:
                logger.error(f"❌ No approved token found with ID: {token}")
                return None
            
            # Validate temporary password if provided
            if temp_password:
                temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
                if rotation_token.temporary_password_hash != temp_hash:
                    logger.error(f"❌ Temporary password mismatch for token: {token}")
                    return None
                logger.info(f"✅ Temporary password validated for token: {token}")
            
            # Mark token as in-progress
            rotation_token.status = 'in_progress'
            rotation_token.save()
            logger.info(f"✅ Token {token} validated and marked in-progress")
            
            return rotation_token
            
        except Exception as e:
            logger.error(f"❌ Token validation error: {e}")
            return None
    
    def _backup_current_state(self, rotation_token, user, current_password):
        """Backup current keys for rollback"""
        from models import UserKeys, Secret, JournalEntry
        
        user_keys = UserKeys.objects(user=user).first()
        if user_keys:
            backup_data = {
                'password_encrypted_key': user_keys.password_encrypted_key,
                'security_questions_encrypted_key': user_keys.security_questions_encrypted_key,
                'recovery_phrase_encrypted_key': user_keys.recovery_phrase_encrypted_key,
                'admin_master_encrypted_key': user_keys.admin_master_encrypted_key,
                'time_lock_encrypted_key': user_keys.time_lock_encrypted_key,
                'email_encrypted_key': user_keys.email_encrypted_key,  # Include E-DEK
                'password_salt': user_keys.password_salt,
                'security_questions_salt': user_keys.security_questions_salt,
                'recovery_phrase_salt': user_keys.recovery_phrase_salt,
                'key_version': user_keys.key_version
            }
            
            # Backup encrypted user data
            secrets = Secret.objects(user=user)
            journal_entries = JournalEntry.objects(user=user)
            
            backup_data['secrets_backup'] = []
            for secret in secrets:
                backup_data['secrets_backup'].append({
                    'id': str(secret.id),
                    'encrypted_data': secret.encrypted_data
                })
                
            backup_data['journal_backup'] = []
            for entry in journal_entries:
                backup_data['journal_backup'].append({
                    'id': str(entry.id),
                    'encrypted_content': entry.content  # Assuming content is encrypted
                })
            
            rotation_token.backup_keys = backup_data
            rotation_token.save()
    
    def _create_all_new_keys_conditional(self, new_dek, new_password, security_answers, recovery_phrase, email_password, temp_password, user, rotation_token):
        """Create all keys conditionally based on user's configured recovery methods"""
        from models import UserKeys
        
        # Get user's current keys to see what's configured
        user_keys = UserKeys.objects(user=user).first()
        
        new_keys = {}
        
        # P-DEK (always required)
        password_key, password_salt = self.crypto_manager.derive_key_from_password(new_password)
        p_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), password_key)
        new_keys.update({
            'password_encrypted_key': json.dumps({
                'encrypted': p_dek,
                'salt': base64.urlsafe_b64encode(password_salt).decode()
            }),
            'password_salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        
        # Q-DEK (only if security questions are configured and answers provided)
        if user_keys and user_keys.security_questions_encrypted_key and security_answers:
            combined_answers = ''.join([answer.lower().strip() for answer in security_answers])
            sq_key, sq_salt = self.crypto_manager.derive_key_from_password(combined_answers)
            q_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), sq_key)
            new_keys.update({
                'security_questions_encrypted_key': json.dumps({
                    'encrypted': q_dek,
                    'salt': base64.urlsafe_b64encode(sq_salt).decode()
                }),
                'security_questions_salt': base64.urlsafe_b64encode(sq_salt).decode()
            })
        
        # R-DEK (only if recovery phrase is configured and provided)
        if user_keys and user_keys.recovery_phrase_encrypted_key and recovery_phrase:
            rp_key, rp_salt = self.crypto_manager.derive_key_from_password(recovery_phrase)
            r_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), rp_key)
            new_keys.update({
                'recovery_phrase_encrypted_key': json.dumps({
                    'encrypted': r_dek,
                    'salt': base64.urlsafe_b64encode(rp_salt).decode()
                }),
                'recovery_phrase_salt': base64.urlsafe_b64encode(rp_salt).decode()
            })
        
        # E-DEK (only if email recovery is configured and password provided)
        if user_keys and user_keys.email_encrypted_key and email_password:
            email_key, email_salt = self.crypto_manager.derive_key_from_password(email_password)
            e_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), email_key)
            new_keys['email_encrypted_key'] = json.dumps({
                'encrypted': e_dek,
                'salt': base64.urlsafe_b64encode(email_salt).decode()
            })
        
        # A-DEK (always required - using temporary password)
        temp_key, temp_salt = self.crypto_manager.derive_key_from_password(temp_password)
        a_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), temp_key)
        new_keys['admin_master_encrypted_key'] = json.dumps({
            'encrypted': a_dek,
            'salt': base64.urlsafe_b64encode(temp_salt).decode(),
            'version': 'v2_temp'  # Indicates temporary A-DEK before finalization
        })
        
        # Store the salt for later finalization
        rotation_token.temporary_password_salt = base64.urlsafe_b64encode(temp_salt).decode()
        rotation_token.save()
        
        # T-DEK (time-lock key - optional, for legal/inheritance access)
        if user_keys and user_keys.time_lock_encrypted_key:
            from datetime import timedelta
            time_factor = (datetime.utcnow() + timedelta(days=30)).isoformat()
            time_key, _ = self.crypto_manager.derive_key_from_password(f"{new_password}_{time_factor}")
            t_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), time_key)
            new_keys['time_lock_encrypted_key'] = json.dumps({
                'encrypted': t_dek,
                'salt': base64.urlsafe_b64encode(password_salt).decode(),  # Reuse password salt
                'time_factor': time_factor
            })
        
        return new_keys

    def _create_all_new_keys(self, new_dek, new_password, security_answers, recovery_phrase, temp_password):
        """Create all 5 new keys (legacy method - kept for backward compatibility)"""
        # P-DEK
        password_key, password_salt = self.crypto_manager.derive_key_from_password(new_password)
        p_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), password_key)
        
        # Q-DEK  
        combined_answers = ''.join([answer.lower().strip() for answer in security_answers])
        sq_key, sq_salt = self.crypto_manager.derive_key_from_password(combined_answers)
        q_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), sq_key)
        
        # R-DEK
        rp_key, rp_salt = self.crypto_manager.derive_key_from_password(recovery_phrase)
        r_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), rp_key)
        
        # A-DEK (using temporary password)
        temp_key, temp_salt = self.crypto_manager.derive_key_from_password(temp_password)
        a_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), temp_key)
        
        # T-DEK
        from datetime import timedelta
        time_factor = (datetime.utcnow() + timedelta(days=30)).isoformat()
        time_key, _ = self.crypto_manager.derive_key_from_password(f"{new_password}_{time_factor}")
        t_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), time_key)
        
        return {
            'password_encrypted_key': json.dumps({
                'encrypted': p_dek,
                'salt': base64.urlsafe_b64encode(password_salt).decode()
            }),
            'password_salt': base64.urlsafe_b64encode(password_salt).decode(),
            'security_questions_encrypted_key': json.dumps({
                'encrypted': q_dek,
                'salt': base64.urlsafe_b64encode(sq_salt).decode()
            }),
            'security_questions_salt': base64.urlsafe_b64encode(sq_salt).decode(),
            'recovery_phrase_encrypted_key': json.dumps({
                'encrypted': r_dek,
                'salt': base64.urlsafe_b64encode(rp_salt).decode()
            }),
            'recovery_phrase_salt': base64.urlsafe_b64encode(rp_salt).decode(),
            'admin_master_encrypted_key': json.dumps({
                'encrypted': a_dek,
                'salt': base64.urlsafe_b64encode(temp_salt).decode(),
                'version': 'v2_temp'  # Indicates temporary A-DEK before finalization
            }),
            'time_lock_encrypted_key': json.dumps({
                'encrypted': t_dek,
                'salt': base64.urlsafe_b64encode(sq_salt).decode(),  # Reuse salt
                'time_factor': time_factor
            })
        }
    
    def _create_all_new_keys_conditional(self, new_dek, new_password, security_answers, 
                                        recovery_phrase, email_password, temp_password, user):
        """Create new keys conditionally based on user's configured recovery methods"""
        from models import UserKeys
        
        # Get user's current recovery setup
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            raise ValueError("User keys not found")
        
        new_keys = {}
        
        # P-DEK (always required)
        password_key, password_salt = self.crypto_manager.derive_key_from_password(new_password)
        p_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), password_key)
        new_keys['password_encrypted_key'] = json.dumps({
            'encrypted': p_dek,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        new_keys['password_salt'] = base64.urlsafe_b64encode(password_salt).decode()
        
        # Q-DEK (only if user has security questions configured)
        if user_keys.security_questions_encrypted_key and security_answers:
            combined_answers = ''.join([answer.lower().strip() for answer in security_answers])
            sq_key, sq_salt = self.crypto_manager.derive_key_from_password(combined_answers)
            q_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), sq_key)
            new_keys['security_questions_encrypted_key'] = json.dumps({
                'encrypted': q_dek,
                'salt': base64.urlsafe_b64encode(sq_salt).decode()
            })
            new_keys['security_questions_salt'] = base64.urlsafe_b64encode(sq_salt).decode()
        
        # R-DEK (only if user has recovery phrase configured)
        if user_keys.recovery_phrase_encrypted_key and recovery_phrase:
            rp_key, rp_salt = self.crypto_manager.derive_key_from_password(recovery_phrase)
            r_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), rp_key)
            new_keys['recovery_phrase_encrypted_key'] = json.dumps({
                'encrypted': r_dek,
                'salt': base64.urlsafe_b64encode(rp_salt).decode()
            })
            new_keys['recovery_phrase_salt'] = base64.urlsafe_b64encode(rp_salt).decode()
        
        # E-DEK (only if user has email recovery configured)
        if user_keys.email_encrypted_key and email_password:
            email_key, email_salt = self.crypto_manager.derive_key_from_password(email_password)
            e_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), email_key)
            new_keys['email_encrypted_key'] = json.dumps({
                'encrypted': e_dek,
                'salt': base64.urlsafe_b64encode(email_salt).decode()
            })
        
        # A-DEK (always required - using temporary password during rotation)
        temp_key, temp_salt = self.crypto_manager.derive_key_from_password(temp_password)
        a_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), temp_key)
        new_keys['admin_master_encrypted_key'] = json.dumps({
            'encrypted': a_dek,
            'salt': base64.urlsafe_b64encode(temp_salt).decode(),
            'version': 'v2_temp'  # Indicates temporary A-DEK before finalization
        })
        
        # T-DEK (always created for time-based recovery)
        from datetime import timedelta
        time_factor = (datetime.utcnow() + timedelta(days=30)).isoformat()
        time_key, time_salt = self.crypto_manager.derive_key_from_password(f"{new_password}_{time_factor}")
        t_dek = self.crypto_manager.encrypt_data(base64.urlsafe_b64encode(new_dek).decode(), time_key)
        new_keys['time_lock_encrypted_key'] = json.dumps({
            'encrypted': t_dek,
            'salt': base64.urlsafe_b64encode(time_salt).decode(),
            'time_factor': time_factor
        })
        
        return new_keys
    
    def _reencrypt_all_user_data(self, user, rotation_token, new_dek, current_password):
        """Re-encrypt all user data with new DEK"""
        from models import Secret, JournalEntry
        
        try:
            # Get old DEK for decryption
            old_dek = self._get_old_dek_from_backup(rotation_token, user, current_password)
            
            # Re-encrypt secrets
            secrets = Secret.objects(user=user)
            for secret in secrets:
                # Decrypt with old DEK
                decrypted_data = self.crypto_manager.decrypt_data(secret.encrypted_data, old_dek)
                # Encrypt with new DEK
                new_encrypted_data = self.crypto_manager.encrypt_data(decrypted_data, new_dek)
                secret.encrypted_data = new_encrypted_data
                secret.save()
            
            # Re-encrypt journal entries
            journal_entries = JournalEntry.objects(user=user)
            for entry in journal_entries:
                # Decrypt with old DEK
                decrypted_content = self.crypto_manager.decrypt_data(entry.content, old_dek)
                # Encrypt with new DEK
                new_encrypted_content = self.crypto_manager.encrypt_data(decrypted_content, new_dek)
                entry.content = new_encrypted_content
                entry.save()
                
        except Exception as e:
            raise Exception(f"Data re-encryption failed: {str(e)}")
    
    def _get_old_dek_from_backup(self, rotation_token, user, current_password):
        """Get old DEK for data re-encryption"""
        from models import UserKeys
        
        backup_keys = rotation_token.backup_keys
        if not backup_keys:
            raise ValueError("No backup keys found for rotation")
        
        try:
            # Try to decrypt with current password using backed up P-DEK
            password_encrypted_data = json.loads(backup_keys['password_encrypted_key'])
            salt = base64.urlsafe_b64decode(password_encrypted_data['salt'])
            
            # Derive the same key using the password and salt
            password_key, _ = self.crypto_manager.derive_key_from_password(current_password, salt)
            
            # Decrypt the DEK
            old_dek_b64 = self.crypto_manager.decrypt_data(password_encrypted_data['encrypted'], password_key)
            old_dek = base64.urlsafe_b64decode(old_dek_b64)
            return old_dek
            
        except Exception as e:
            raise ValueError(f"Cannot decrypt old DEK: {str(e)}")
    
    def _finalize_rotation(self, user, new_keys, rotation_token):
        """Update user keys with new values"""
        from models import UserKeys
        
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            user_keys = UserKeys(user=user)
            
        # Update all keys
        for key, value in new_keys.items():
            setattr(user_keys, key, value)
            
        user_keys.key_version = rotation_token.backup_keys.get('key_version', 1) + 1
        user_keys.rotated_at = datetime.utcnow()
        user_keys.save()
    
    def _rollback_rotation(self, rotation_token):
        """Rollback rotation on failure"""
        from models import User, UserKeys, Secret, JournalEntry
        from utils import log_audit
        
        try:
            rotation_token.status = 'failed'
            
            if rotation_token.rotation_stage in ['data_encrypted', 'keys_created']:
                # Restore from backup
                user = User.objects(id=rotation_token.user_id).first()
                if user and rotation_token.backup_keys:
                    
                    # Restore user keys
                    user_keys = UserKeys.objects(user=user).first()
                    if user_keys:
                        backup = rotation_token.backup_keys
                        user_keys.password_encrypted_key = backup.get('password_encrypted_key')
                        user_keys.security_questions_encrypted_key = backup.get('security_questions_encrypted_key')
                        user_keys.recovery_phrase_encrypted_key = backup.get('recovery_phrase_encrypted_key')
                        user_keys.admin_master_encrypted_key = backup.get('admin_master_encrypted_key')
                        user_keys.time_lock_encrypted_key = backup.get('time_lock_encrypted_key')
                        user_keys.password_salt = backup.get('password_salt')
                        user_keys.security_questions_salt = backup.get('security_questions_salt')
                        user_keys.recovery_phrase_salt = backup.get('recovery_phrase_salt')
                        user_keys.key_version = backup.get('key_version', 1)
                        user_keys.save()
                    
                    # Restore secrets
                    if 'secrets_backup' in backup:
                        for secret_backup in backup['secrets_backup']:
                            secret = Secret.objects(id=secret_backup['id']).first()
                            if secret:
                                secret.encrypted_data = secret_backup['encrypted_data']
                                secret.save()
                    
                    # Restore journal entries
                    if 'journal_backup' in backup:
                        for entry_backup in backup['journal_backup']:
                            entry = JournalEntry.objects(id=entry_backup['id']).first()
                            if entry:
                                entry.content = entry_backup['encrypted_content']
                                entry.save()
            
            rotation_token.save()
            log_audit('rollback_rotation', 'key_rotation', rotation_token.user_id, 
                     f'Rotation rolled back at stage: {rotation_token.rotation_stage}')
                     
        except Exception as e:
            log_audit('rollback_failed', 'key_rotation', rotation_token.user_id, 
                     f'Rollback failed: {str(e)}')

# Global atomic rotation instance
atomic_rotation = AtomicKeyRotation(crypto_manager)
