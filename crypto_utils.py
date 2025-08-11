import os
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import json

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key(self):
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple:
        """Derive encryption key from password"""
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
            admin_master_key = self.get_or_create_admin_master_key()
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
            'admin_master_encrypted_key': admin_encrypted,
            'time_lock_encrypted_key': json.dumps({
                'encrypted': time_encrypted,
                'salt': base64.urlsafe_b64encode(time_salt).decode(),
                'time_factor': time_factor
            })
        }
    
    def get_or_create_admin_master_key(self) -> bytes:
        """Get or create admin master key"""
        from app import db
        from models import AdminMasterKey
        
        active_key = AdminMasterKey.query.filter_by(is_active=True).first()
        if active_key:
            # For simplicity, we'll use a hardcoded key for admin master
            # In production, this should be derived from multiple admin passwords
            return base64.urlsafe_b64encode(b'admin_master_key_placeholder_32b')
        
        # Create new admin master key
        master_key = self.generate_key()
        
        # In production, this would require multiple admin approvals
        admin_key_record = AdminMasterKey(
            key_hash=hashlib.sha256(master_key).hexdigest(),
            encrypted_key=base64.urlsafe_b64encode(master_key).decode(),
            created_by_admin_id=1,  # Should be actual admin ID
            is_active=True
        )
        
        db.session.add(admin_key_record)
        db.session.commit()
        
        return master_key
    
    def recover_dek_with_password(self, user_keys, password: str) -> bytes:
        """Recover DEK using password"""
        try:
            key_data = json.loads(user_keys.password_encrypted_key)
            salt = base64.urlsafe_b64decode(key_data['salt'].encode())
            
            password_key, _ = self.derive_key_from_password(password, salt)
            dek_b64 = self.decrypt_data(key_data['encrypted'], password_key)
            return base64.urlsafe_b64decode(dek_b64.encode())
        except Exception:
            raise ValueError("Failed to recover DEK with password")
    
    def recover_dek_with_security_questions(self, user_keys, answers: list) -> bytes:
        """Recover DEK using security question answers"""
        try:
            key_data = json.loads(user_keys.security_questions_encrypted_key)
            salt = base64.urlsafe_b64decode(key_data['salt'].encode())
            
            combined_answers = ''.join(answer.lower().strip() for answer in answers)
            sq_key, _ = self.derive_key_from_password(combined_answers, salt)
            dek_b64 = self.decrypt_data(key_data['encrypted'], sq_key)
            return base64.urlsafe_b64decode(dek_b64.encode())
        except Exception:
            raise ValueError("Failed to recover DEK with security questions")
    
    def recover_dek_with_recovery_phrase(self, user_keys, recovery_phrase: str) -> bytes:
        """Recover DEK using recovery phrase"""
        try:
            key_data = json.loads(user_keys.recovery_phrase_encrypted_key)
            salt = base64.urlsafe_b64decode(key_data['salt'].encode())
            
            rp_key, _ = self.derive_key_from_password(recovery_phrase, salt)
            dek_b64 = self.decrypt_data(key_data['encrypted'], rp_key)
            return base64.urlsafe_b64decode(dek_b64.encode())
        except Exception:
            raise ValueError("Failed to recover DEK with recovery phrase")
    
    def recover_dek_with_admin_key(self, user_keys) -> bytes:
        """Recover DEK using admin master key"""
        try:
            admin_master_key = self.get_or_create_admin_master_key()
            dek_b64 = self.decrypt_data(user_keys.admin_master_encrypted_key, admin_master_key)
            return base64.urlsafe_b64decode(dek_b64.encode())
        except Exception:
            raise ValueError("Failed to recover DEK with admin key")
    
    def update_password_key(self, user_keys, old_password: str, new_password: str):
        """Update password-encrypted key with new password"""
        # First recover the DEK with old password
        dek = self.recover_dek_with_password(user_keys, old_password)
        
        # Re-encrypt with new password
        password_key, password_salt = self.derive_key_from_password(new_password)
        password_encrypted = self.encrypt_data(base64.urlsafe_b64encode(dek).decode(), password_key)
        
        user_keys.password_encrypted_key = json.dumps({
            'encrypted': password_encrypted,
            'salt': base64.urlsafe_b64encode(password_salt).decode()
        })
        
        return user_keys

# Global instance
crypto_manager = CryptoManager()
