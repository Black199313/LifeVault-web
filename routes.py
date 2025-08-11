from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
import secrets
import json
import logging
import base64

from app import app, db
from models import (User, UserKeys, SecretData, JournalEntry, AuditLog, 
                   RecoveryToken, generate_recovery_phrase, generate_token)
from crypto_utils import crypto_manager
from email_utils import email_service
from utils import require_rate_limit, admin_required, log_security_event
from auth import create_admin_user, verify_email_token, create_email_verification_token

logger = logging.getLogger(__name__)

def log_audit(action, resource_type, resource_id=None, details=None, success=True, error_message=None):
    """Create audit log entry"""
    try:
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=success,
            error_message=error_message
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to create audit log: {str(e)}")

@app.route('/')
def index():
    # Create admin user if none exists
    if not User.query.filter_by(is_admin=True).first():
        create_admin_user()
    
    return render_template('index.html')

@app.route('/journal')
def journal():
    # Get journal entries for the calendar
    entries = JournalEntry.query.all()
    calendar_events = []
    for entry in entries:
        calendar_events.append({
            'id': entry.id,
            'title': f"Journal Entry - {entry.mood or 'No mood'}",
            'start': entry.entry_date.isoformat(),
            'color': get_mood_color(entry.mood)
        })
    
    return render_template('journal.html', calendar_events=calendar_events)

def get_mood_color(mood):
    """Get color for mood"""
    mood_colors = {
        'happy': '#28a745',
        'sad': '#6c757d',
        'angry': '#dc3545',
        'excited': '#ffc107',
        'calm': '#17a2b8',
        'anxious': '#fd7e14',
        'content': '#6f42c1'
    }
    return mood_colors.get(mood, '#007bff')

@app.route('/journal/entry', methods=['GET', 'POST'])
def journal_entry():
    if request.method == 'POST':
        entry_date = datetime.strptime(request.form['entry_date'], '%Y-%m-%d').date()
        content = request.form['content']
        mood = request.form.get('mood', '')
        tags = request.form.get('tags', '').split(',')
        tags = [tag.strip() for tag in tags if tag.strip()]
        
        # Check if entry exists for this date
        existing_entry = JournalEntry.query.filter_by(entry_date=entry_date).first()
        
        if existing_entry:
            existing_entry.content = content
            existing_entry.mood = mood
            existing_entry.tags = tags
            existing_entry.updated_at = datetime.utcnow()
            flash('Journal entry updated successfully!', 'success')
        else:
            new_entry = JournalEntry(
                entry_date=entry_date,
                content=content,
                mood=mood,
                tags=tags
            )
            db.session.add(new_entry)
            flash('Journal entry saved successfully!', 'success')
        
        db.session.commit()
        log_audit('create_journal_entry' if not existing_entry else 'update_journal_entry', 
                 'journal_entry', entry_date)
        
        return redirect(url_for('journal'))
    
    # GET request - get entry for specific date if provided
    entry_date = request.args.get('date')
    entry = None
    if entry_date:
        entry_date = datetime.strptime(entry_date, '%Y-%m-%d').date()
        entry = JournalEntry.query.filter_by(entry_date=entry_date).first()
    
    return render_template('journal_entry.html', entry=entry, entry_date=entry_date)

@app.route('/register', methods=['GET', 'POST'])
@require_rate_limit(max_attempts=5, window_minutes=15)
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'error')
            return render_template('register.html')
        
        try:
            # Create user
            password_hash = generate_password_hash(password)
            user = User(
                username=username,
                email=email,
                password_hash=password_hash
            )
            db.session.add(user)
            db.session.flush()  # Get user ID
            
            # Generate recovery phrase
            recovery_phrase = generate_recovery_phrase()
            
            # Store recovery phrase temporarily in session for setup
            session['recovery_phrase'] = recovery_phrase
            session['user_id'] = user.id
            session['registration_password'] = password  # Store temporarily for key setup
            
            # Send verification email
            token = create_email_verification_token(user)
            email_service.send_verification_email(user, token)
            
            db.session.commit()
            log_audit('user_registration', 'user', user.id)
            
            flash('Registration successful! Please set up your recovery options.', 'success')
            return redirect(url_for('setup_recovery'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/setup_recovery', methods=['GET', 'POST'])
def setup_recovery():
    if 'user_id' not in session or 'recovery_phrase' not in session:
        flash('Invalid session. Please register again.', 'error')
        return redirect(url_for('register'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found. Please register again.', 'error')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        # Security questions
        questions = [
            request.form['question1'],
            request.form['question2'],
            request.form['question3']
        ]
        answers = [
            request.form['answer1'],
            request.form['answer2'],
            request.form['answer3']
        ]
        
        recovery_email = request.form.get('recovery_email', user.email)
        password = session.get('registration_password')  # Get password from session
        
        try:
            # Hash security question answers
            hashed_answers = []
            for answer in answers:
                answer_hash = generate_password_hash(answer.lower().strip())
                hashed_answers.append(answer_hash)
            
            # Store security questions
            security_questions = [
                {'question': questions[i], 'answer_hash': hashed_answers[i]} 
                for i in range(3)
            ]
            
            user.security_questions = security_questions
            user.recovery_email = recovery_email
            
            # Generate DEK and create 5-key system
            dek = crypto_manager.generate_key()
            recovery_phrase = session['recovery_phrase']
            
            five_keys = crypto_manager.create_five_key_system(
                dek, 
                password,
                answers,
                recovery_phrase
            )
            
            # Create UserKeys record
            user_keys = UserKeys(
                user_id=user.id,
                **five_keys
            )
            
            db.session.add(user_keys)
            db.session.commit()
            
            # Clear session data
            session.pop('user_id', None)
            session.pop('recovery_phrase', None)
            session.pop('registration_password', None)
            
            log_audit('setup_recovery', 'user', user.id)
            flash('Recovery options set up successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Setup recovery error: {str(e)}")
            flash('Setup failed. Please try again.', 'error')
    
    return render_template('setup_recovery.html', 
                         recovery_phrase=session.get('recovery_phrase'))

@app.route('/login', methods=['GET', 'POST'])
@require_rate_limit(max_attempts=3, window_minutes=15)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if user.is_active:
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                log_audit('login', 'user', user.id)
                
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('secrets'))
            else:
                flash('Account is deactivated. Contact admin.', 'error')
        else:
            log_audit('failed_login', 'user', details={'username': username}, success=False)
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit('logout', 'user', current_user.id)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/verify_email/<token>')
def verify_email(token):
    user = verify_email_token(token)
    if user:
        user.email_verified = True
        db.session.commit()
        log_audit('email_verified', 'user', user.id)
        flash('Email verified successfully!', 'success')
        return render_template('verify_email.html', success=True)
    else:
        flash('Invalid or expired verification link.', 'error')
        return render_template('verify_email.html', success=False)

@app.route('/secrets')
@login_required
def secrets():
    user_secrets = SecretData.query.filter_by(user_id=current_user.id).all()
    
    # Decrypt secrets for display
    decrypted_secrets = []
    try:
        # Get user's DEK
        user_keys = current_user.user_keys
        if user_keys:
            # For display, we'll use admin key recovery (simplified)
            dek = crypto_manager.recover_dek_with_admin_key(user_keys)
            
            for secret in user_secrets:
                try:
                    decrypted_content = crypto_manager.decrypt_data(secret.encrypted_content, dek)
                    decrypted_secrets.append({
                        'id': secret.id,
                        'title': secret.title,
                        'secret_type': secret.secret_type,
                        'content': decrypted_content,
                        'url': secret.url,
                        'username': secret.username,
                        'notes': secret.notes,
                        'created_at': secret.created_at
                    })
                except Exception as e:
                    logger.error(f"Failed to decrypt secret {secret.id}: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to recover DEK for user {current_user.id}: {str(e)}")
        flash('Unable to access secrets. Please contact support.', 'error')
    
    return render_template('secrets.html', secrets=decrypted_secrets)

@app.route('/secrets/add', methods=['POST'])
@login_required
def add_secret():
    title = request.form['title']
    secret_type = request.form['secret_type']
    content = request.form['content']
    url = request.form.get('url', '')
    username = request.form.get('username', '')
    notes = request.form.get('notes', '')
    
    try:
        # Get user's DEK
        user_keys = current_user.user_keys
        if not user_keys:
            flash('User keys not found. Please contact support.', 'error')
            return redirect(url_for('secrets'))
        
        dek = crypto_manager.recover_dek_with_admin_key(user_keys)
        encrypted_content = crypto_manager.encrypt_data(content, dek)
        
        secret = SecretData(
            user_id=current_user.id,
            title=title,
            secret_type=secret_type,
            encrypted_content=encrypted_content,
            url=url,
            username=username,
            notes=notes,
            key_version=user_keys.key_version
        )
        
        db.session.add(secret)
        db.session.commit()
        
        log_audit('create_secret', 'secret', secret.id)
        flash('Secret added successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Add secret error: {str(e)}")
        flash('Failed to add secret. Please try again.', 'error')
    
    return redirect(url_for('secrets'))

@app.route('/secrets/delete/<int:secret_id>')
@login_required
def delete_secret(secret_id):
    secret = SecretData.query.filter_by(id=secret_id, user_id=current_user.id).first()
    if secret:
        db.session.delete(secret)
        db.session.commit()
        log_audit('delete_secret', 'secret', secret_id)
        flash('Secret deleted successfully!', 'success')
    else:
        flash('Secret not found!', 'error')
    
    return redirect(url_for('secrets'))

@app.route('/recovery', methods=['GET', 'POST'])
def recovery():
    if request.method == 'POST':
        recovery_type = request.form['recovery_type']
        username = request.form['username']
        
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found!', 'error')
            return render_template('recovery.html')
        
        if recovery_type == 'security_questions':
            return redirect(url_for('security_questions_recovery', username=username))
        elif recovery_type == 'recovery_phrase':
            return redirect(url_for('recovery_phrase_recovery', username=username))
        elif recovery_type == 'email':
            return redirect(url_for('email_recovery', username=username))
    
    return render_template('recovery.html')

@app.route('/recovery/security_questions/<username>')
def security_questions_recovery(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.security_questions:
        flash('Security questions not set up for this user.', 'error')
        return redirect(url_for('recovery'))
    
    return render_template('security_questions.html', 
                         username=username,
                         questions=[q['question'] for q in user.security_questions])

@app.route('/recovery/security_questions/<username>', methods=['POST'])
@require_rate_limit(max_attempts=3, window_minutes=30)
def process_security_questions(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.security_questions:
        flash('Security questions not set up for this user.', 'error')
        return redirect(url_for('recovery'))
    
    answers = [
        request.form['answer1'],
        request.form['answer2'], 
        request.form['answer3']
    ]
    
    # Verify answers
    correct_answers = 0
    for i, answer in enumerate(answers):
        stored_hash = user.security_questions[i]['answer_hash']
        if check_password_hash(stored_hash, answer.lower().strip()):
            correct_answers += 1
    
    if correct_answers >= 2:  # At least 2 correct answers
        session['recovery_user_id'] = user.id
        session['recovery_method'] = 'security_questions'
        return redirect(url_for('reset_password_form'))
    else:
        log_audit('failed_security_questions_recovery', 'user', user.id, success=False)
        flash('Incorrect answers. Please try again.', 'error')
        return render_template('security_questions.html', 
                             username=username,
                             questions=[q['question'] for q in user.security_questions])

@app.route('/recovery/phrase/<username>', methods=['GET', 'POST'])
def recovery_phrase_recovery(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('recovery'))
    
    if request.method == 'POST':
        recovery_phrase = request.form['recovery_phrase']
        
        try:
            # Try to recover DEK with the phrase
            user_keys = user.user_keys
            if user_keys:
                crypto_manager.recover_dek_with_recovery_phrase(user_keys, recovery_phrase)
                session['recovery_user_id'] = user.id
                session['recovery_method'] = 'recovery_phrase'
                return redirect(url_for('reset_password_form'))
        except:
            pass
        
        log_audit('failed_recovery_phrase', 'user', user.id, success=False)
        flash('Invalid recovery phrase!', 'error')
    
    return render_template('recovery_phrase.html')

@app.route('/recovery/email/<username>')
def email_recovery(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('recovery'))
    
    # Generate recovery token
    token = generate_token()
    recovery_token = RecoveryToken(
        user_id=user.id,
        token=token,
        token_type='password_reset',
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    
    db.session.add(recovery_token)
    db.session.commit()
    
    # Send email
    if email_service.send_password_reset_email(user, token):
        flash('Password reset email sent! Check your inbox.', 'success')
    else:
        flash('Failed to send email. Please try again.', 'error')
    
    return redirect(url_for('recovery'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    recovery_token = RecoveryToken.query.filter_by(
        token=token, 
        used=False,
        token_type='password_reset'
    ).first()
    
    if not recovery_token or recovery_token.expires_at < datetime.utcnow():
        flash('Invalid or expired reset link!', 'error')
        return redirect(url_for('recovery'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password.html')
        
        user = recovery_token.user
        user.password_hash = generate_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        
        # Update password-encrypted key
        if user.user_keys:
            try:
                # Use admin key to recover DEK and re-encrypt with new password
                dek = crypto_manager.recover_dek_with_admin_key(user.user_keys)
                
                # Create new password key
                password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
                password_encrypted = crypto_manager.encrypt_data(
                    base64.urlsafe_b64encode(dek).decode(), password_key
                )
                
                user.user_keys.password_encrypted_key = json.dumps({
                    'encrypted': password_encrypted,
                    'salt': base64.urlsafe_b64encode(password_salt).decode()
                })
                
            except Exception as e:
                logger.error(f"Failed to update password key: {str(e)}")
        
        # Mark token as used
        recovery_token.used = True
        
        db.session.commit()
        log_audit('password_reset', 'user', user.id)
        
        flash('Password reset successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/reset_password_form', methods=['GET', 'POST'])
def reset_password_form():
    if 'recovery_user_id' not in session:
        flash('Invalid session!', 'error')
        return redirect(url_for('recovery'))
    
    user = User.query.get(session['recovery_user_id'])
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('recovery'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password_form.html')
        
        # Update password and re-encrypt keys
        user.password_hash = generate_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        
        if user.user_keys:
            try:
                # Use admin key to recover DEK and re-encrypt with new password
                dek = crypto_manager.recover_dek_with_admin_key(user.user_keys)
                
                # Create new password key
                password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
                password_encrypted = crypto_manager.encrypt_data(
                    base64.urlsafe_b64encode(dek).decode(), password_key
                )
                
                user.user_keys.password_encrypted_key = json.dumps({
                    'encrypted': password_encrypted,
                    'salt': base64.urlsafe_b64encode(password_salt).decode()
                })
                
            except Exception as e:
                logger.error(f"Failed to update password key: {str(e)}")
        
        db.session.commit()
        log_audit('password_reset_recovery', 'user', user.id, 
                 details={'method': session.get('recovery_method')})
        
        # Clear session
        session.pop('recovery_user_id', None)
        session.pop('recovery_method', None)
        
        flash('Password reset successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password_form.html')

# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # Get statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_secrets = SecretData.query.count()
    total_journals = JournalEntry.query.count()
    
    # Recent activity
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         active_users=active_users,
                         total_secrets=total_secrets,
                         total_journals=total_journals,
                         recent_logs=recent_logs)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
@admin_required
def admin_reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form['new_password']
    
    try:
        # Update password
        user.password_hash = generate_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        
        # Update password-encrypted key using admin master key
        if user.user_keys:
            dek = crypto_manager.recover_dek_with_admin_key(user.user_keys)
            
            # Re-encrypt with new password
            password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
            password_encrypted = crypto_manager.encrypt_data(
                base64.urlsafe_b64encode(dek).decode(), password_key
            )
            
            user.user_keys.password_encrypted_key = json.dumps({
                'encrypted': password_encrypted,
                'salt': base64.urlsafe_b64encode(password_salt).decode()
            })
        
        db.session.commit()
        log_audit('admin_password_reset', 'user', user_id, 
                 details={'admin_id': current_user.id})
        
        flash(f'Password reset for user {user.username} successful!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Admin password reset error: {str(e)}")
        flash('Password reset failed!', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/audit')
@login_required
@admin_required
def admin_audit():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    return render_template('admin_audit.html', logs=logs)

@app.route('/profile')
@login_required
def user_profile():
    journal_count = JournalEntry.query.count()
    shared_count = 0  # Placeholder for shared secrets count
    return render_template('user_profile.html', 
                         journal_count=journal_count, 
                         shared_count=shared_count)

# API endpoints for AJAX calls (minimal usage as per guidelines)
@app.route('/api/journal/<date>')
def get_journal_entry(date):
    try:
        entry_date = datetime.strptime(date, '%Y-%m-%d').date()
        entry = JournalEntry.query.filter_by(entry_date=entry_date).first()
        if entry:
            return jsonify({
                'content': entry.content,
                'mood': entry.mood,
                'tags': entry.tags or []
            })
        return jsonify({'content': '', 'mood': '', 'tags': []})
    except:
        return jsonify({'error': 'Invalid date'}), 400

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
