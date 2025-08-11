import re
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps
from flask import current_app, request, session, redirect, url_for, flash
from flask_login import current_user
import logging

logger = logging.getLogger(__name__)

def validate_password_strength(password):
    """
    Validate password strength and return score with feedback
    """
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password must be at least 8 characters long")
    
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Consider using 12+ characters for better security")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Include lowercase letters")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Include uppercase letters")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Include numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Include special characters")
    
    strength_levels = {
        0: "Very Weak",
        1: "Very Weak", 
        2: "Weak",
        3: "Fair",
        4: "Good",
        5: "Strong",
        6: "Very Strong"
    }
    
    return {
        'score': score,
        'max_score': 6,
        'strength': strength_levels.get(score, "Very Weak"),
        'feedback': feedback,
        'is_acceptable': score >= 3
    }

def generate_secure_token(length=32):
    """Generate a cryptographically secure random token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_verification_code(length=6):
    """Generate a numeric verification code"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def is_safe_url(target):
    """Check if a URL is safe for redirects"""
    from urllib.parse import urlparse, urljoin
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def get_client_ip():
    """Get the real client IP address"""
    # Check for X-Forwarded-For header (proxy/load balancer)
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    # Check for X-Real-IP header (nginx proxy)
    elif request.environ.get('HTTP_X_REAL_IP'):
        return request.environ['HTTP_X_REAL_IP']
    # Fall back to remote_addr
    else:
        return request.environ.get('REMOTE_ADDR', 'unknown')

def sanitize_filename(filename):
    """Sanitize filename for safe storage"""
    # Remove path components
    filename = filename.split('/')[-1].split('\\')[-1]
    # Remove potentially dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:255-len(ext)-1] + '.' + ext if ext else name[:255]
    return filename

def rate_limit_key(endpoint, identifier=None):
    """Generate a rate limiting key"""
    if identifier is None:
        identifier = get_client_ip()
    return f"rate_limit:{endpoint}:{identifier}"

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.attempts = {}
    
    def is_allowed(self, key, max_attempts=5, window_minutes=15):
        """Check if an action is allowed based on rate limits"""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=window_minutes)
        
        # Clean old attempts
        if key in self.attempts:
            self.attempts[key] = [t for t in self.attempts[key] if t > cutoff]
        else:
            self.attempts[key] = []
        
        # Check if limit exceeded
        if len(self.attempts[key]) >= max_attempts:
            return False
        
        # Record this attempt
        self.attempts[key].append(now)
        return True
    
    def get_remaining_attempts(self, key, max_attempts=5, window_minutes=15):
        """Get remaining attempts for a key"""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=window_minutes)
        
        if key in self.attempts:
            recent_attempts = [t for t in self.attempts[key] if t > cutoff]
            return max(0, max_attempts - len(recent_attempts))
        return max_attempts
    
    def reset_attempts(self, key):
        """Reset attempts for a key"""
        if key in self.attempts:
            del self.attempts[key]

# Global rate limiter instance
rate_limiter = RateLimiter()

def require_rate_limit(max_attempts=5, window_minutes=15, endpoint=None):
    """Decorator to add rate limiting to routes"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            route_endpoint = endpoint or f.__name__
            key = rate_limit_key(route_endpoint)
            
            if not rate_limiter.is_allowed(key, max_attempts, window_minutes):
                remaining = rate_limiter.get_remaining_attempts(key, max_attempts, window_minutes)
                flash(f'Too many attempts. Please try again later. ({remaining} attempts remaining)', 'error')
                logger.warning(f"Rate limit exceeded for {route_endpoint} from {get_client_ip()}")
                return redirect(request.referrer or url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        if not current_user.is_admin:
            flash('Admin privileges required.', 'error')
            logger.warning(f"Non-admin user {current_user.username} attempted to access admin function: {f.__name__}")
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(event_type, details=None, user_id=None, ip_address=None):
    """Log security-related events"""
    from models import AuditLog
    from app import db
    
    try:
        audit_log = AuditLog(
            user_id=user_id or (current_user.id if current_user.is_authenticated else None),
            action=event_type,
            resource_type='security',
            details=details or {},
            ip_address=ip_address or get_client_ip(),
            user_agent=request.headers.get('User-Agent'),
            timestamp=datetime.utcnow()
        )
        db.session.add(audit_log)
        db.session.commit()
        logger.info(f"Security event logged: {event_type}")
    except Exception as e:
        logger.error(f"Failed to log security event: {str(e)}")

def format_datetime(dt, format_type='default'):
    """Format datetime for display"""
    if not dt:
        return 'N/A'
    
    formats = {
        'default': '%Y-%m-%d %H:%M:%S',
        'date': '%Y-%m-%d',
        'time': '%H:%M:%S',
        'friendly': '%B %d, %Y at %I:%M %p',
        'relative': None  # Will calculate relative time
    }
    
    if format_type == 'relative':
        return get_relative_time(dt)
    
    return dt.strftime(formats.get(format_type, formats['default']))

def get_relative_time(dt):
    """Get relative time string (e.g., '2 hours ago')"""
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 0:
        if diff.days == 1:
            return "1 day ago"
        elif diff.days < 7:
            return f"{diff.days} days ago"
        elif diff.days < 30:
            weeks = diff.days // 7
            return f"{weeks} week{'s' if weeks > 1 else ''} ago"
        else:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
    
    hours = diff.seconds // 3600
    if hours > 0:
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    
    minutes = diff.seconds // 60
    if minutes > 0:
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    
    return "Just now"

def validate_email(email):
    """Validate email address format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def clean_text(text, max_length=None):
    """Clean and sanitize text input"""
    if not text:
        return ''
    
    # Strip whitespace
    text = text.strip()
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Limit length if specified
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text

def mask_sensitive_data(data, mask_char='*', visible_chars=4):
    """Mask sensitive data for display"""
    if not data or len(data) <= visible_chars:
        return mask_char * 8
    
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)

def generate_recovery_questions():
    """Get predefined security questions"""
    return [
        "What was the name of your first pet?",
        "What city were you born in?",
        "What was your mother's maiden name?",
        "What was the make of your first car?",
        "What elementary school did you attend?",
        "What was your favorite food as a child?",
        "What was the name of your best friend in high school?",
        "What street did you grow up on?",
        "What was your favorite book as a child?",
        "What was your first job?",
        "What was your grandmother's first name?",
        "What was the model of your first phone?",
        "What city did you meet your spouse in?",
        "What was your favorite teacher's name?",
        "What was your childhood nickname?"
    ]

def estimate_password_entropy(password):
    """Estimate password entropy (bits)"""
    character_space = 0
    
    if re.search(r'[a-z]', password):
        character_space += 26
    if re.search(r'[A-Z]', password):
        character_space += 26
    if re.search(r'\d', password):
        character_space += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        character_space += 32
    
    if character_space == 0:
        return 0
    
    import math
    return len(password) * math.log2(character_space)

def check_password_common(password):
    """Check if password is in common password list (simplified)"""
    common_passwords = {
        'password', '123456', '123456789', 'qwerty', 'abc123', 
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
        'dragon', 'princess', 'sunshine', 'master', 'shadow'
    }
    return password.lower() in common_passwords

class SecurityHeaders:
    """Security headers utility"""
    
    @staticmethod
    def apply_headers(response):
        """Apply security headers to response"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

def setup_security_headers(app):
    """Setup security headers for the Flask app"""
    @app.after_request
    def after_request(response):
        return SecurityHeaders.apply_headers(response)

# Context processor for templates
def template_utils():
    """Utility functions available in templates"""
    return {
        'format_datetime': format_datetime,
        'get_relative_time': get_relative_time,
        'mask_sensitive_data': mask_sensitive_data
    }
