from datetime import datetime, timedelta
from flask_login import UserMixin
from mongoengine import Document, EmbeddedDocument, fields
import secrets
import string

class SecurityQuestion(EmbeddedDocument):
    question = fields.StringField(required=True)
    answer_hash = fields.StringField(required=True)

class EmergencyContact(EmbeddedDocument):
    name = fields.StringField(required=True)
    email = fields.EmailField(required=True)
    relationship = fields.StringField(required=True)

class User(UserMixin, Document):
    username = fields.StringField(max_length=80, required=True, unique=True)
    email = fields.EmailField(required=True, unique=True)
    password_hash = fields.StringField(max_length=256, required=True)
    is_admin = fields.BooleanField(default=False)
    is_active = fields.BooleanField(default=True)
    email_verified = fields.BooleanField(default=False)
    force_password_change = fields.BooleanField(default=False)  # For admin-created accounts
    
    # Recovery data
    recovery_phrase = fields.StringField(max_length=500)  # Encrypted recovery phrase
    security_questions = fields.ListField(fields.EmbeddedDocumentField(SecurityQuestion))
    recovery_email = fields.EmailField()
    
    # Emergency contacts
    emergency_contacts = fields.ListField(fields.EmbeddedDocumentField(EmergencyContact))
    
    # Timestamps
    created_at = fields.DateTimeField(default=datetime.utcnow)
    last_login = fields.DateTimeField()
    password_changed_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'users',
        'indexes': ['username', 'email']
    }

class UserKeys(Document):
    user = fields.ReferenceField(User, required=True)
    
    # Five encrypted copies of the Data Encryption Key (DEK)
    password_encrypted_key = fields.StringField()  # Optional for escrow mode
    security_questions_encrypted_key = fields.StringField()  # Optional for escrow mode
    recovery_phrase_encrypted_key = fields.StringField()  # Optional for escrow mode
    admin_master_encrypted_key = fields.StringField(required=True)
    email_encrypted_key = fields.StringField()  # E-DEK for email recovery (Requirement 18)
    time_lock_encrypted_key = fields.StringField()  # Optional
    
    # Salts for key derivation
    password_salt = fields.StringField()
    security_questions_salt = fields.StringField()
    recovery_phrase_salt = fields.StringField()
    
    # Key version for rotation
    key_version = fields.IntField(default=1)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    rotated_at = fields.DateTimeField()
    
    # Admin escrow mode (for admin-created accounts)
    escrow_mode = fields.BooleanField(default=False)
    
    meta = {
        'collection': 'user_keys',
        'indexes': ['user']
    }

class Secret(Document):
    user = fields.ReferenceField(User, required=True)
    
    title = fields.StringField(max_length=200, required=True)
    encrypted_data = fields.StringField(required=True)
    
    # Metadata
    notes = fields.StringField()
    
    key_version = fields.IntField(required=True)
    needs_migration = fields.BooleanField(default=False)  # ✅ NEW: Flag for old encrypted data
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'secrets',
        'indexes': ['user', 'created_at']
    }
    
    def save(self, *args, **kwargs):
        if not self.created_at:
            self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        return super(Secret, self).save(*args, **kwargs)

class JournalEntry(Document):
    user = fields.ReferenceField(User, required=True)
    entry_date = fields.DateTimeField(required=True)
    content = fields.StringField(required=True)
    mood = fields.StringField(max_length=20)  # happy, sad, neutral, etc.
    tags = fields.ListField(fields.StringField(max_length=50))
    
    created_at = fields.DateTimeField(default=datetime.utcnow)
    updated_at = fields.DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'journal_entries',
        'indexes': ['user', 'entry_date', 'mood', 'tags']
    }
    
    def save(self, *args, **kwargs):
        if not self.created_at:
            self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        return super(JournalEntry, self).save(*args, **kwargs)

class SharedSecret(Document):
    secret = fields.ReferenceField(Secret, required=True)
    shared_with_user = fields.ReferenceField(User, required=True)
    shared_by_user = fields.ReferenceField(User, required=True)
    
    permission_level = fields.StringField(max_length=20, default='read')  # read, write
    encrypted_content = fields.StringField(required=True)  # Encrypted with recipient's key
    
    created_at = fields.DateTimeField(default=datetime.utcnow)
    expires_at = fields.DateTimeField()
    
    meta = {
        'collection': 'shared_secrets',
        'indexes': ['secret', 'shared_with_user', 'expires_at']
    }

class AuditLog(Document):
    user = fields.ReferenceField(User)
    admin = fields.ReferenceField(User)
    
    action = fields.StringField(max_length=100, required=True)
    resource_type = fields.StringField(max_length=50, required=True)
    resource_id = fields.StringField(max_length=50)
    details = fields.DictField()
    
    ip_address = fields.StringField(max_length=45)
    user_agent = fields.StringField(max_length=500)
    
    timestamp = fields.DateTimeField(default=datetime.utcnow)
    success = fields.BooleanField(default=True)
    error_message = fields.StringField()
    
    meta = {
        'collection': 'audit_logs',
        'indexes': ['user', 'admin', 'timestamp', 'action', 'resource_type']
    }

class RecoveryToken(Document):
    user = fields.ReferenceField(User, required=True)
    token = fields.StringField(max_length=100, required=True, unique=True)
    token_type = fields.StringField(max_length=50, required=True)  # email_verify, password_reset, etc.
    
    created_at = fields.DateTimeField(default=datetime.utcnow)
    expires_at = fields.DateTimeField(required=True)
    used = fields.BooleanField(default=False)
    
    meta = {
        'collection': 'recovery_tokens',
        'indexes': ['token', 'user', 'expires_at', 'used']
    }

class AdminApproval(EmbeddedDocument):
    admin_id = fields.StringField(required=True)
    approved_at = fields.DateTimeField(default=datetime.utcnow)

class AdminMasterKey(Document):
    key_hash = fields.StringField(max_length=256, required=True)
    encrypted_key = fields.StringField(required=True)
    
    created_by_admin = fields.ReferenceField(User, required=True)
    created_at = fields.DateTimeField(default=datetime.utcnow)
    is_active = fields.BooleanField(default=True)
    
    # For multi-admin approval
    approval_count = fields.IntField(default=0)
    required_approvals = fields.IntField(default=2)
    approved_by = fields.ListField(fields.EmbeddedDocumentField(AdminApproval))
    
    meta = {
        'collection': 'admin_master_keys',
        'indexes': ['created_by_admin', 'is_active']
    }

class RotationToken(Document):
    user_id = fields.StringField(required=True)
    admin_id = fields.StringField()  # Not required initially, set when approved
    temporary_password_hash = fields.StringField()
    temporary_password_salt = fields.StringField()  # Store salt for temp password encryption
    expires_at = fields.DateTimeField(required=True)
    status = fields.StringField(choices=['pending', 'approved', 'in_progress', 'completed', 'finalized', 'expired', 'failed'], default='pending')
    created_at = fields.DateTimeField(default=datetime.utcnow)
    used_at = fields.DateTimeField()
    
    # Request details
    request_reason = fields.StringField(max_length=500)
    description = fields.StringField(max_length=1000)  # Additional details field
    
    # Failure recovery data
    backup_keys = fields.DictField()  # Store original keys for rollback
    new_dek = fields.StringField()    # Store new DEK during rotation
    rotation_stage = fields.StringField(choices=['created', 'approved', 'dek_generated', 'keys_created', 'data_encrypted', 'completed'], default='created')
    
    # Admin approval tracking
    approved_by_admin = fields.ReferenceField(User)
    approved_at = fields.DateTimeField()
    a_dek_finalized = fields.BooleanField(default=False)  # Track if A-DEK was finalized with admin master key
    
    # A-DEK finalization tracking
    a_dek_finalized = fields.BooleanField(default=False)
    
    meta = {
        'collection': 'rotation_tokens',
        'indexes': ['user_id', 'expires_at', 'status']  # Removed token_hash index
    }

def generate_recovery_phrase():
    """Generate a 12-word recovery phrase"""
    words = [
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
        'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
        'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit',
        'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'against', 'age',
        'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol',
        'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also',
        'alter', 'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient',
        'anger', 'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna',
        'antique', 'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april', 'area'
    ]
    return ' '.join(secrets.choice(words) for _ in range(12))

def generate_token():
    """Generate a secure random token"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
