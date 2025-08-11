from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import JSONB
from app import db
import secrets
import string

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Recovery data
    recovery_phrase = db.Column(db.String(500))  # Encrypted recovery phrase
    security_questions = db.Column(JSONB)  # [{question: str, answer_hash: str}]
    recovery_email = db.Column(db.String(120))
    
    # Emergency contacts
    emergency_contacts = db.Column(JSONB)  # [{name: str, email: str, relationship: str}]
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user_keys = db.relationship('UserKeys', backref='user', uselist=False, cascade='all, delete-orphan')
    secrets = db.relationship('SecretData', backref='user', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', foreign_keys='AuditLog.user_id', backref='user', cascade='all, delete-orphan')
    admin_audit_logs = db.relationship('AuditLog', foreign_keys='AuditLog.admin_id', backref='admin_user', cascade='all, delete-orphan')

class UserKeys(db.Model):
    __tablename__ = 'user_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Five encrypted copies of the Data Encryption Key (DEK)
    password_encrypted_key = db.Column(db.Text, nullable=False)
    security_questions_encrypted_key = db.Column(db.Text, nullable=False)
    recovery_phrase_encrypted_key = db.Column(db.Text, nullable=False)
    admin_master_encrypted_key = db.Column(db.Text, nullable=False)
    time_lock_encrypted_key = db.Column(db.Text, nullable=False)
    
    # Key version for rotation
    key_version = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rotated_at = db.Column(db.DateTime)

class SecretData(db.Model):
    __tablename__ = 'secret_data'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    title = db.Column(db.String(200), nullable=False)
    secret_type = db.Column(db.String(50), nullable=False)  # password, api_key, note, etc.
    encrypted_content = db.Column(db.Text, nullable=False)
    
    # Metadata
    url = db.Column(db.String(500))  # For password entries
    username = db.Column(db.String(200))  # For password entries
    notes = db.Column(db.Text)
    
    key_version = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class JournalEntry(db.Model):
    __tablename__ = 'journal_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    entry_date = db.Column(db.Date, nullable=False)
    content = db.Column(db.Text, nullable=False)
    mood = db.Column(db.String(20))  # happy, sad, neutral, etc.
    tags = db.Column(JSONB)  # Array of tags
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SharedSecret(db.Model):
    __tablename__ = 'shared_secrets'
    
    id = db.Column(db.Integer, primary_key=True)
    secret_id = db.Column(db.Integer, db.ForeignKey('secret_data.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    permission_level = db.Column(db.String(20), default='read', nullable=False)  # read, write
    encrypted_content = db.Column(db.Text, nullable=False)  # Encrypted with recipient's key
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(50))
    details = db.Column(JSONB)
    
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)

class RecoveryToken(db.Model):
    __tablename__ = 'recovery_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    token_type = db.Column(db.String(50), nullable=False)  # email_verify, password_reset, etc.
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

class AdminMasterKey(db.Model):
    __tablename__ = 'admin_master_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(256), nullable=False)
    encrypted_key = db.Column(db.Text, nullable=False)
    
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # For multi-admin approval
    approval_count = db.Column(db.Integer, default=0)
    required_approvals = db.Column(db.Integer, default=2)
    approved_by = db.Column(JSONB)  # Array of admin IDs who approved

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
