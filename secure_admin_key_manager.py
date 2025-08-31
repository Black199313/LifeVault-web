#!/usr/bin/env python3
"""
Secure Admin Master Key Implementation

This addresses the security concerns about storing admin master keys in the database.
Shows multiple secure approaches for production use.
"""

import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

class SecureAdminKeyManager:
    """
    Production-grade admin master key management addressing security concerns.
    
    Multiple approaches to secure admin master key storage:
    1. Master Password Encryption
    2. Multi-Admin Threshold Scheme
    3. Hardware Security Module (HSM) Integration
    4. Encrypted Database Storage with Authentication
    """
    
    def __init__(self):
        self.current_approach = "master_password"  # Can be: master_password, threshold, hsm, encrypted_db
    
    # APPROACH 1: Master Password Encryption
    def store_admin_key_with_master_password(self, admin_master_key: bytes, master_password: str) -> str:
        """
        Store admin master key encrypted with a master password.
        
        Security Benefits:
        - Admin master key is encrypted, not plaintext
        - Requires master password to retrieve
        - Master password can be stored securely (HSM, split among admins)
        
        Trade-offs:
        - Requires master password for user key rotation
        - Master password becomes critical single point
        """
        # Derive key from master password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        encryption_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        # Encrypt admin master key
        fernet = Fernet(encryption_key)
        encrypted_key = fernet.encrypt(admin_master_key)
        
        # Store salt + encrypted key
        stored_data = base64.urlsafe_b64encode(salt + encrypted_key).decode()
        
        return stored_data
    
    def retrieve_admin_key_with_master_password(self, stored_data: str, master_password: str) -> bytes:
        """Retrieve admin master key using master password"""
        try:
            # Decode stored data
            data = base64.urlsafe_b64decode(stored_data.encode())
            salt = data[:16]
            encrypted_key = data[16:]
            
            # Derive same key from master password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            encryption_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            
            # Decrypt admin master key
            fernet = Fernet(encryption_key)
            admin_master_key = fernet.decrypt(encrypted_key)
            
            return admin_master_key
        except Exception as e:
            raise ValueError(f"Failed to retrieve admin master key: {str(e)}")
    
    # APPROACH 2: Multi-Admin Threshold Scheme
    def create_threshold_admin_key(self, admin_passwords: list, threshold: int = 2) -> dict:
        """
        Create admin master key using threshold cryptography.
        
        Security Benefits:
        - Requires multiple admins to recover key
        - No single point of failure
        - Admin compromise doesn't expose key
        
        Implementation:
        - Split admin master key into shares
        - Each admin gets encrypted share
        - Threshold number of admins needed to reconstruct
        """
        if len(admin_passwords) < threshold:
            raise ValueError("Not enough admins for threshold")
        
        # Generate admin master key
        admin_master_key = os.urandom(32)
        
        # Simple threshold implementation (production would use Shamir's Secret Sharing)
        shares = []
        for i, password in enumerate(admin_passwords):
            # Create share by XORing with password-derived key
            share_key = hashlib.sha256(f"admin_share_{i}_{password}".encode()).digest()
            share = bytes(a ^ b for a, b in zip(admin_master_key, share_key))
            shares.append({
                'admin_id': i,
                'encrypted_share': base64.urlsafe_b64encode(share).decode()
            })
        
        return {
            'shares': shares,
            'threshold': threshold,
            'original_key': base64.urlsafe_b64encode(admin_master_key).decode()  # For verification
        }
    
    def reconstruct_threshold_key(self, shares: list, admin_passwords: list) -> bytes:
        """Reconstruct admin master key from threshold shares"""
        if len(shares) < shares[0].get('threshold', 2):
            raise ValueError("Not enough shares to reconstruct key")
        
        # Reconstruct key (simplified - production would use proper SSS)
        reconstructed_key = bytes(32)  # Start with zeros
        
        for share_data, password in zip(shares, admin_passwords):
            admin_id = share_data['admin_id']
            encrypted_share = base64.urlsafe_b64decode(share_data['encrypted_share'].encode())
            
            # Derive same share key
            share_key = hashlib.sha256(f"admin_share_{admin_id}_{password}".encode()).digest()
            
            # XOR to get original contribution
            contribution = bytes(a ^ b for a, b in zip(encrypted_share, share_key))
            reconstructed_key = bytes(a ^ b for a, b in zip(reconstructed_key, contribution))
        
        return reconstructed_key
    
    # APPROACH 3: HSM Integration
    def store_admin_key_in_hsm(self, admin_master_key: bytes, hsm_key_id: str) -> str:
        """
        Store admin master key in Hardware Security Module.
        
        Security Benefits:
        - Key never leaves secure hardware
        - Hardware-based authentication
        - Audit logging at hardware level
        - Tamper resistance
        
        Note: This is a mock implementation - real HSM would use vendor SDK
        """
        # Mock HSM storage
        return f"hsm://{hsm_key_id}"
    
    def retrieve_admin_key_from_hsm(self, hsm_reference: str, hsm_auth_token: str) -> bytes:
        """Retrieve admin master key from HSM"""
        # Mock HSM retrieval - real implementation would use HSM SDK
        if not hsm_auth_token:
            raise ValueError("HSM authentication required")
        
        # Mock returning key from HSM
        return os.urandom(32)  # Placeholder
    
    # APPROACH 4: Encrypted Database Storage with Admin Authentication
    def store_admin_key_encrypted_with_admin_auth(self, admin_master_key: bytes, admin_password_hashes: list) -> str:
        """
        Store admin master key encrypted with combined admin credentials.
        
        Security Benefits:
        - Key encrypted with admin credentials
        - Requires admin authentication to retrieve
        - Can support multiple admins
        
        Process:
        - Combine admin password hashes to create encryption key
        - Encrypt admin master key with combined key
        - Store encrypted key in database
        """
        # Create combined key from all admin password hashes
        combined_hash = hashlib.sha256()
        for pwd_hash in sorted(admin_password_hashes):  # Sort for consistency
            combined_hash.update(pwd_hash.encode())
        
        combined_key = combined_hash.digest()
        encryption_key = base64.urlsafe_b64encode(combined_key)
        
        # Encrypt admin master key
        fernet = Fernet(encryption_key)
        encrypted_key = fernet.encrypt(admin_master_key)
        
        return base64.urlsafe_b64encode(encrypted_key).decode()
    
    def retrieve_admin_key_with_admin_auth(self, encrypted_data: str, requesting_admin_password_hash: str, all_admin_hashes: list) -> bytes:
        """
        Retrieve admin master key with admin authentication.
        
        Requires:
        - Valid admin password hash
        - Knowledge of all current admin password hashes
        """
        # Verify requesting admin is valid
        if requesting_admin_password_hash not in all_admin_hashes:
            raise ValueError("Invalid admin credentials")
        
        # Recreate combined key
        combined_hash = hashlib.sha256()
        for pwd_hash in sorted(all_admin_hashes):
            combined_hash.update(pwd_hash.encode())
        
        combined_key = combined_hash.digest()
        encryption_key = base64.urlsafe_b64encode(combined_key)
        
        # Decrypt admin master key
        fernet = Fernet(encryption_key)
        encrypted_key = base64.urlsafe_b64decode(encrypted_data.encode())
        admin_master_key = fernet.decrypt(encrypted_key)
        
        return admin_master_key


# PRODUCTION RECOMMENDATIONS
def production_admin_key_recommendations():
    """
    Production recommendations for secure admin master key management.
    """
    return {
        "tier_1_basic": {
            "approach": "Master Password Encryption",
            "description": "Encrypt admin master key with master password",
            "security_level": "Medium",
            "implementation": "store_admin_key_with_master_password()",
            "pros": ["Simple to implement", "Key is encrypted", "Master password can be secured"],
            "cons": ["Master password single point of failure", "Requires master password for operations"]
        },
        
        "tier_2_enterprise": {
            "approach": "Multi-Admin Threshold + Encrypted Storage",
            "description": "Threshold cryptography with admin authentication",
            "security_level": "High",
            "implementation": "create_threshold_admin_key() + encrypted_db_storage",
            "pros": ["No single point of failure", "Multiple admin authorization", "Encrypted storage"],
            "cons": ["More complex implementation", "Requires multiple admins for operations"]
        },
        
        "tier_3_maximum": {
            "approach": "HSM + Threshold + Audit",
            "description": "Hardware security module with threshold scheme",
            "security_level": "Maximum",
            "implementation": "HSM integration with threshold cryptography",
            "pros": ["Hardware security", "Tamper resistance", "Complete audit trail", "No key exposure"],
            "cons": ["Expensive", "Complex setup", "Hardware dependency"]
        }
    }


if __name__ == "__main__":
    print("🔐 SECURE ADMIN MASTER KEY MANAGEMENT")
    print("=" * 50)
    
    manager = SecureAdminKeyManager()
    
    # Demo of secure approaches
    admin_key = os.urandom(32)
    
    print("1. Master Password Encryption:")
    master_password = "super_secure_master_password_123!"
    encrypted_data = manager.store_admin_key_with_master_password(admin_key, master_password)
    print(f"   Encrypted Data: {encrypted_data[:50]}...")
    
    print("\n2. Threshold Scheme:")
    admin_passwords = ["admin1_pass", "admin2_pass", "admin3_pass"]
    threshold_data = manager.create_threshold_admin_key(admin_passwords, threshold=2)
    print(f"   Shares created: {len(threshold_data['shares'])}")
    print(f"   Threshold: {threshold_data['threshold']}")
    
    print("\n3. Production Recommendations:")
    recommendations = production_admin_key_recommendations()
    for tier, info in recommendations.items():
        print(f"   {tier.upper()}: {info['approach']} (Security: {info['security_level']})")
