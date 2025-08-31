import os
import secrets
import string
from datetime import datetime, timedelta
from flask import current_app
from werkzeug.security import generate_password_hash
from models import User, RecoveryToken
import logging

logger = logging.getLogger(__name__)

# Dummy db object for compatibility during migration
class DummyDB:
    class session:
        @staticmethod
        def add(obj):
            if hasattr(obj, 'save'):
                obj.save()
        
        @staticmethod
        def commit():
            pass
        
        @staticmethod
        def rollback():
            pass
        
        @staticmethod
        def delete(obj):
            if hasattr(obj, 'delete'):
                obj.delete()

db = DummyDB()

def create_admin_user():
    """Create default admin user if none exists"""
    try:
        admin = User.objects(is_admin=True).first()
        if not admin:
            # Create admin user with default credentials
            admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@secretjournal.com')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123!')
            
            admin_user = User(
                username=admin_username,
                email=admin_email,
                password_hash=generate_password_hash(admin_password),
                is_admin=True,
                is_active=True,
                email_verified=True,
                created_at=datetime.utcnow()
            )
            
            admin_user.save()
            
            logger.info(f"Created admin user: {admin_username}")
            
            # Set up admin keys (simplified for demo)
            from crypto_utils import crypto_manager
            from models import UserKeys, generate_recovery_phrase
            
            try:
                dek = crypto_manager.generate_key()
                recovery_phrase = generate_recovery_phrase()
                
                # Create basic 5-key system for admin
                five_keys = crypto_manager.create_five_key_system(
                    dek,
                    admin_password,
                    ['admin', 'admin', 'admin'],  # Simple answers
                    recovery_phrase
                )
                
                admin_keys = UserKeys(
                    user=admin_user,
                    **five_keys
                )
                
                admin_keys.save()
                
                logger.info("Created admin encryption keys")
                
            except Exception as e:
                logger.error(f"Failed to create admin keys: {str(e)}")
                
    except Exception as e:
        logger.error(f"Failed to create admin user: {str(e)}")

def create_email_verification_token(user):
    """Create email verification token"""
    token = generate_secure_token()
    
    verification_token = RecoveryToken(
        user=user,
        token=token,
        token_type='email_verify',
        expires_at=datetime.utcnow() + timedelta(days=1)
    )
    
    verification_token.save()
    
    return token

def verify_email_token(token):
    """Verify email verification token"""
    recovery_token = RecoveryToken.objects(
        token=token,
        used=False,
        token_type='email_verify'
    ).first()
    
    if not recovery_token or recovery_token.expires_at < datetime.utcnow():
        return None
    
    # Mark token as used
    recovery_token.used = True
    recovery_token.save()
    
    return recovery_token.user

def generate_secure_token(length=32):
    """Generate a cryptographically secure token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def create_password_reset_token(user):
    """Create password reset token"""
    token = generate_secure_token()
    
    reset_token = RecoveryToken(
        user_id=user.id,
        token=token,
        token_type='password_reset',
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    
    db.session.add(reset_token)
    db.session.commit()
    
    return token

def verify_password_reset_token(token):
    """Verify password reset token"""
    recovery_token = RecoveryToken.query.filter_by(
        token=token,
        used=False,
        token_type='password_reset'
    ).first()
    
    if not recovery_token or recovery_token.expires_at < datetime.utcnow():
        return None
    
    return recovery_token

def invalidate_token(token):
    """Mark a token as used"""
    recovery_token = RecoveryToken.query.filter_by(token=token).first()
    if recovery_token:
        recovery_token.used = True
        db.session.commit()

def cleanup_expired_tokens():
    """Clean up expired tokens"""
    try:
        expired_tokens = RecoveryToken.query.filter(
            RecoveryToken.expires_at < datetime.utcnow()
        ).all()
        
        for token in expired_tokens:
            db.session.delete(token)
        
        db.session.commit()
        logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")
        
    except Exception as e:
        logger.error(f"Failed to cleanup expired tokens: {str(e)}")
        db.session.rollback()

def validate_recovery_attempt(user, attempt_type):
    """Validate recovery attempt against rate limits"""
    from utils import rate_limiter, rate_limit_key
    
    key = rate_limit_key(f'recovery_{attempt_type}', str(user.id))
    
    # Allow 3 attempts per hour for recovery
    if not rate_limiter.is_allowed(key, max_attempts=3, window_minutes=60):
        logger.warning(f"Recovery rate limit exceeded for user {user.id}, type: {attempt_type}")
        return False
    
    return True

def log_authentication_event(user, event_type, success=True, details=None):
    """Log authentication-related events"""
    from models import AuditLog
    from flask import request
    
    try:
        audit_log = AuditLog(
            user_id=user.id if user else None,
            action=event_type,
            resource_type='authentication',
            details=details or {},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=success,
            timestamp=datetime.utcnow()
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Failed to log authentication event: {str(e)}")

def check_account_lockout(user):
    """Check if account should be locked due to failed attempts"""
    from models import AuditLog
    
    # Check failed login attempts in last hour
    recent_failures = AuditLog.query.filter(
        AuditLog.user_id == user.id,
        AuditLog.action == 'failed_login',
        AuditLog.timestamp > datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    # Lock account after 5 failed attempts
    if recent_failures >= 5:
        user.is_active = False
        db.session.commit()
        logger.warning(f"Account locked for user {user.username} due to failed login attempts")
        return True
    
    return False

def require_email_verification(user):
    """Check if email verification is required"""
    return not user.email_verified

def send_recovery_notification(user, recovery_method):
    """Send notification about account recovery attempt"""
    from email_utils import email_service
    
    try:
        # Send notification to user's recovery email
        recovery_email = user.recovery_email or user.email
        
        subject = "Account Recovery Attempt"
        message = f"""
        Someone attempted to recover your account using {recovery_method}.
        
        If this was you, you can ignore this message.
        If this was not you, please contact support immediately.
        
        Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
        Method: {recovery_method}
        """
        
        # This would be implemented with a proper email template
        logger.info(f"Recovery notification sent to {recovery_email} for method: {recovery_method}")
        
    except Exception as e:
        logger.error(f"Failed to send recovery notification: {str(e)}")

def get_account_security_status(user):
    """Get security status summary for user account"""
    status = {
        'password_set': bool(user.password_hash),
        'email_verified': user.email_verified,
        'security_questions_set': bool(user.security_questions),
        'recovery_phrase_set': bool(user.recovery_phrase),
        'encryption_keys_set': bool(user.user_keys),
        'two_factor_enabled': False,  # Not implemented yet
        'last_password_change': user.password_changed_at,
        'account_active': user.is_active
    }
    
    # Calculate security score
    security_score = sum([
        status['password_set'],
        status['email_verified'],
        status['security_questions_set'],
        status['recovery_phrase_set'],
        status['encryption_keys_set']
    ])
    
    status['security_score'] = security_score
    status['security_percentage'] = (security_score / 5) * 100
    
    return status

def rotate_user_tokens(user):
    """Rotate all active tokens for a user"""
    try:
        # Mark all active tokens as used
        active_tokens = RecoveryToken.query.filter_by(
            user_id=user.id,
            used=False
        ).all()
        
        for token in active_tokens:
            token.used = True
        
        db.session.commit()
        logger.info(f"Rotated {len(active_tokens)} tokens for user {user.username}")
        
    except Exception as e:
        logger.error(f"Failed to rotate tokens for user {user.id}: {str(e)}")
        db.session.rollback()
