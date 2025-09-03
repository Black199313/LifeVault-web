from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from mongoengine.errors import DoesNotExist, NotUniqueError
import secrets as secure_random
import json
import logging
import base64
import os

from app import app
from models import (User, UserKeys, Secret, JournalEntry, AuditLog, 
                   RecoveryToken, RotationToken, generate_recovery_phrase, generate_token, SecurityQuestion)
from crypto_utils import crypto_manager
from email_utils import email_service
from utils import require_rate_limit, admin_required, log_security_event, log_audit
from auth import verify_email_token, create_email_verification_token

logger = logging.getLogger(__name__)

def password_change_required(f):
    """Decorator to check if user needs to change password first"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.force_password_change:
            return redirect(url_for('force_password_change'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/journal')
@login_required
@password_change_required
def journal():
    # Get journal entries for the calendar
    entries = JournalEntry.objects(user=current_user)
    calendar_events = []
    
    for entry in entries:
        # Ensure all values are properly set to avoid JSON serialization issues
        mood = entry.mood or 'neutral'
        title = mood or 'Journal Entry'
        entry_date = entry.entry_date
        
        if entry_date:  # Only add if date exists
            calendar_events.append({
                'title': title,
                'start': entry_date.isoformat(),
                'url': url_for('journal_entry', date=entry_date.strftime('%Y-%m-%d')),
                'backgroundColor': get_mood_color(mood),
                'borderColor': get_mood_color(mood)
            })
    
    # Add date object to template context
    from datetime import date
    return render_template('journal.html', events=calendar_events, calendar_events=calendar_events, date=date)

def get_mood_color(mood):
    colors = {
        'happy': '#28a745',
        'sad': '#dc3545', 
        'angry': '#fd7e14',
        'excited': '#ffc107',
        'calm': '#17a2b8',
        'anxious': '#6f42c1',
        'grateful': '#20c997'
    }
    return colors.get(mood, '#6c757d')

@app.route('/journal/entry', methods=['GET', 'POST'])
@app.route('/journal/entry/<date>', methods=['GET', 'POST'])
@login_required
@password_change_required
def journal_entry(date=None):
    # Check for date parameter in URL path or query string
    if not date:
        date = request.args.get('date')
    
    if date:
        try:
            # Parse date and convert to datetime at start of day
            parsed_date = datetime.strptime(date, '%Y-%m-%d').date()
            entry_date = datetime.combine(parsed_date, datetime.min.time())
        except ValueError:
            flash('Invalid date format!', 'error')
            return redirect(url_for('journal'))
    else:
        # Use current date at start of day
        today = datetime.now().date()
        entry_date = datetime.combine(today, datetime.min.time())
    
    # Get existing entry for this date (search for entries on the same day)
    start_of_day = entry_date
    end_of_day = entry_date.replace(hour=23, minute=59, second=59, microsecond=999999)
    existing_entry = JournalEntry.objects(
        user=current_user, 
        entry_date__gte=start_of_day,
        entry_date__lte=end_of_day
    ).first()
    
    if request.method == 'POST':
        # Get the date from the form submission
        form_date = request.form.get('entry_date')
        if form_date:
            try:
                # Parse form date and convert to datetime at start of day
                parsed_date = datetime.strptime(form_date, '%Y-%m-%d').date()
                entry_date = datetime.combine(parsed_date, datetime.min.time())
            except ValueError:
                pass  # Keep the originally parsed entry_date
        
        content = request.form.get('content', '').strip()
        mood = request.form.get('mood', '')
        tags_str = request.form.get('tags', '')
        tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()]
        
        if content:
            # Check if entry already exists for this date (search for entries on the same day)
            start_of_day = entry_date
            end_of_day = entry_date.replace(hour=23, minute=59, second=59, microsecond=999999)
            existing_entry = JournalEntry.objects(
                user=current_user,
                entry_date__gte=start_of_day,
                entry_date__lte=end_of_day
            ).first()
            
            if existing_entry:
                # Update existing entry
                existing_entry.content = content
                existing_entry.mood = mood
                existing_entry.tags = tags
                existing_entry.save()
                flash('Journal entry updated successfully!', 'success')
            else:
                # Create new entry
                new_entry = JournalEntry(
                    user=current_user,
                    entry_date=entry_date,
                    content=content,
                    mood=mood,
                    tags=tags
                )
                new_entry.save()
                flash('Journal entry saved successfully!', 'success')
            
            log_audit('journal_entry_save', 'journal', 
                     details={'date': entry_date.date().isoformat(), 'mood': mood})
            
            return redirect(url_for('journal'))
        else:
            flash('Please enter some content for your journal entry.', 'error')
    
    return render_template('journal_entry.html', 
                         entry=existing_entry, 
                         date=entry_date.date().strftime('%Y-%m-%d'))

@app.route('/journal/entry/<entry_id>/delete', methods=['POST'])
@login_required
@password_change_required
def delete_journal_entry(entry_id):
    """Delete a journal entry"""
    try:
        # Find the entry that belongs to the current user
        entry = JournalEntry.objects(id=entry_id, user=current_user).first()
        
        if not entry:
            flash('Journal entry not found or you do not have permission to delete it.', 'error')
            return redirect(url_for('journal'))
        
        # Store entry details for audit log before deletion
        entry_date = entry.entry_date.date().isoformat()
        entry_mood = entry.mood
        
        # Delete the entry
        entry.delete()
        
        # Log the deletion
        log_audit('journal_entry_delete', 'journal', 
                 details={'date': entry_date, 'mood': entry_mood})
        
        flash('Journal entry deleted successfully!', 'success')
        
    except Exception as e:
        flash('An error occurred while deleting the journal entry.', 'error')
        log_audit('journal_entry_delete_error', 'journal', 
                 details={'error': str(e), 'entry_id': entry_id})
    
    return redirect(url_for('journal'))

@app.route('/journal/list')
@login_required
@password_change_required
def journal_list():
    """List view of all journal entries with search and filter capabilities"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search_query = request.args.get('search', '')
    mood_filter = request.args.get('mood', '')
    tag_filter = request.args.get('tag', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Build query
    query = JournalEntry.objects(user=current_user)
    
    # Apply search filter
    if search_query:
        query = query.filter(content__icontains=search_query)
    
    # Apply mood filter
    if mood_filter:
        query = query.filter(mood=mood_filter)
    
    # Apply tag filter
    if tag_filter:
        query = query.filter(tags__icontains=tag_filter)
    
    # Apply date range filter
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(entry_date__gte=from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(entry_date__lte=to_date)
        except ValueError:
            pass
    
    # Order by date (newest first)
    query = query.order_by('-entry_date')
    
    # Paginate results
    total = query.count()
    entries = query.skip((page - 1) * per_page).limit(per_page)
    
    # Get all unique moods and tags for filter options
    all_entries = JournalEntry.objects(user=current_user)
    moods = list(set([entry.mood for entry in all_entries if entry.mood]))
    all_tags = []
    for entry in all_entries:
        if entry.tags:
            all_tags.extend(entry.tags)
    unique_tags = list(set(all_tags))
    
    # Pagination info
    has_prev = page > 1
    has_next = (page * per_page) < total
    prev_num = page - 1 if has_prev else None
    next_num = page + 1 if has_next else None
    
    return render_template('journal_list.html',
                         entries=entries,
                         pagination={
                             'page': page,
                             'per_page': per_page,
                             'total': total,
                             'has_prev': has_prev,
                             'has_next': has_next,
                             'prev_num': prev_num,
                             'next_num': next_num
                         },
                         search_query=search_query,
                         mood_filter=mood_filter,
                         tag_filter=tag_filter,
                         date_from=date_from,
                         date_to=date_to,
                         moods=moods,
                         tags=unique_tags)

@app.route('/journal/search')
@login_required
@password_change_required
def journal_search():
    """AJAX endpoint for journal search"""
    search_query = request.args.get('q', '')
    limit = request.args.get('limit', 10, type=int)
    
    if not search_query:
        return jsonify([])
    
    # Search in content and tags
    entries = JournalEntry.objects(
        user=current_user,
        content__icontains=search_query
    ).order_by('-entry_date').limit(limit)
    
    results = []
    for entry in entries:
        results.append({
            'id': str(entry.id),
            'date': entry.entry_date.strftime('%Y-%m-%d'),
            'title': entry.content[:100] + '...' if len(entry.content) > 100 else entry.content,
            'mood': entry.mood,
            'tags': entry.tags,
            'url': url_for('journal_entry', date=entry.entry_date.strftime('%Y-%m-%d'))
        })
    
    return jsonify(results)

@app.route('/register', methods=['GET', 'POST'])
@require_rate_limit(max_attempts=5, window_minutes=15)
def register():
    # Check if registrations are allowed
    if not app.config.get('ALLOW_REGISTRATIONS', False):
        flash('New registrations are disabled. Please contact an administrator.', 'error')
        return redirect(url_for('login'))
    
    logger.info(f"Register route accessed with method: {request.method}")
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        logger.info(f"Registration attempt - Username: {username}, Email: {email}")
        
        # Validate input
        if not username or not email or not password:
            logger.warning("Registration failed - missing required fields")
            flash('All fields are required!', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            logger.warning("Registration failed - passwords don't match")
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        try:
            if User.objects(username=username).first():
                logger.warning(f"Registration failed - username {username} already exists")
                flash('Username already exists!', 'error')
                return render_template('register.html')
            
            if User.objects(email=email).first():
                logger.warning(f"Registration failed - email {email} already exists")
                flash('Email already registered!', 'error')
                return render_template('register.html')
        except Exception as e:
            logger.error(f"Error checking existing users: {str(e)}")
            flash('Registration error. Please try again.', 'error')
            return render_template('register.html')
        
        try:
            # Create new user
            logger.info(f"Creating new user: {username}")
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            user.save()
            logger.info(f"User {username} created successfully with ID: {user.id}")
            
            # Send verification email (skip for now to avoid hanging)
            # try:
            #     verification_token = create_email_verification_token(user)
            #     logger.info(f"Sending verification email to {email}")
            #     try:
            #         email_sent = email_service.send_verification_email(user, verification_token)
            #         if email_sent:
            #             logger.info(f"Verification email sent successfully to {email}")
            #         else:
            #             logger.warning(f"Failed to send verification email to {email}")
            #     except Exception as email_error:
            #         logger.error(f"Email service error: {str(email_error)}")
            #         # Continue with registration even if email fails
            # except Exception as e:
            #     logger.error(f"Email token creation error: {str(e)}")
            #     # Continue with registration even if email fails
            
            logger.info("Skipping email verification for faster registration")
            
            log_audit('user_register', 'user', user.id, {'username': username, 'email': email})
            logger.info(f"Registration completed for {username}, showing success page")
            
            # Render success page with auto-redirect
            return render_template('registration_success.html')
            
        except NotUniqueError:
            logger.error("Registration failed - NotUniqueError (username or email already exists)")
            flash('Username or email already exists!', 'error')
            return render_template('register.html')
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html')
    
    logger.info("Serving registration form (GET request)")
    return render_template('register.html')

@app.route('/setup_recovery', methods=['GET', 'POST'])
@login_required
@password_change_required
def setup_recovery():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        user = User.objects(id=session['user_id']).first()
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error fetching user: {str(e)}")
        flash('Error accessing user data!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        recovery_email = request.form.get('recovery_email', '').strip()
        security_questions = []
        
        # Process security questions
        for i in range(1, 4):  # Assuming 3 security questions
            question = request.form.get(f'question_{i}', '').strip()
            answer = request.form.get(f'answer_{i}', '').strip()
            
            if question and answer:
                sq = SecurityQuestion(
                    question=question,
                    answer_hash=generate_password_hash(answer.lower())
                )
                security_questions.append(sq)
        
        if len(security_questions) < 3:
            flash('Please provide all 3 security questions and answers!', 'error')
            return render_template('setup_recovery.html')
        
        try:
            # Generate recovery phrase
            recovery_phrase = generate_recovery_phrase()
            user_password = request.form.get('password', '')
            
            # Update user with recovery data
            user.recovery_email = recovery_email
            user.security_questions = security_questions
            user.recovery_phrase = crypto_manager.encrypt_with_password(
                recovery_phrase, user_password
            )
            user.save()
            
            # Create user keys using the 5-key system
            dek = crypto_manager.generate_key()
            answers = [request.form.get(f'answer_{i}', '').lower().strip() for i in range(1, 4)]
            
            five_keys = crypto_manager.create_five_key_system(
                dek, 
                user_password,
                answers,
                recovery_phrase
            )
            
            # Create UserKeys record
            user_keys = UserKeys(
                user=user,
                **five_keys,
                key_version=1
            )
            
            # Add E-DEK if recovery email is provided (Requirement 18)
            if recovery_email:
                try:
                    email_password = crypto_manager.setup_email_recovery(user_keys, user_password, recovery_email)
                    
                    # Send email password to user's recovery email
                    from email_utils import email_service
                    email_sent = email_service.send_recovery_code_email(user, email_password)
                    
                    if email_sent:
                        flash(f'Recovery email password sent to {recovery_email}. Please save it securely!', 'info')
                    else:
                        flash(f'E-DEK created but failed to send email to {recovery_email}. Please contact support.', 'warning')
                        
                except Exception as e:
                    flash(f'Failed to setup email recovery: {str(e)}', 'warning')
                    logger.error(f"E-DEK setup failed: {str(e)}")
            
            user_keys.save()
            
            session.pop('user_id', None)
            flash('Recovery setup completed successfully! Please save your recovery phrase securely.', 'success')
            
            log_audit('recovery_setup', 'user', user.id)
            return render_template('recovery_phrase.html', recovery_phrase=recovery_phrase)
            
        except Exception as e:
            logger.error(f"Recovery setup error: {str(e)}")
            flash('Failed to setup recovery. Please try again.', 'error')
            return render_template('setup_recovery.html')
    
    return render_template('setup_recovery.html')

@app.route('/setup_keys', methods=['GET', 'POST'])
@login_required
def setup_keys():
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        # Verify the current user's password
        if not check_password_hash(current_user.password_hash, password):
            flash('Invalid password!', 'error')
            return render_template('setup_keys.html')
        
        try:
            # Create basic encryption keys
            dek = crypto_manager.generate_key()
            
            # Create simplified UserKeys (just using password for now)
            password_key, password_salt = crypto_manager.derive_key_from_password(password)
            encrypted_dek = crypto_manager.encrypt_data(base64.urlsafe_b64encode(dek).decode(), password_key)
            
            user_keys = UserKeys(
                user=current_user,
                password_encrypted_key=f"{base64.urlsafe_b64encode(password_salt).decode()}:{encrypted_dek}",
                security_questions_encrypted_key="",  # Will be set up later via update_recovery
                recovery_phrase_encrypted_key="",     # Will be set up later via update_recovery
                admin_master_encrypted_key=f"{base64.urlsafe_b64encode(password_salt).decode()}:{encrypted_dek}",
                time_lock_encrypted_key=f"{base64.urlsafe_b64encode(password_salt).decode()}:{encrypted_dek}",
                key_version=1
            )
            user_keys.save()
            
            flash('Encryption keys created successfully!', 'success')
            return redirect(url_for('secrets'))
            
        except Exception as e:
            logger.error(f"Key setup error: {str(e)}")
            flash('Failed to create encryption keys. Please try again.', 'error')
    
    return render_template('setup_keys.html')

@app.route('/update_recovery', methods=['GET', 'POST'])
@login_required
@password_change_required
def update_recovery():
    user = current_user
    
    if request.method == 'POST':
        recovery_email = request.form.get('recovery_email', '').strip()
        update_questions = request.form.get('update_questions') == 'on'
        update_phrase = request.form.get('update_phrase') == 'on'
        password = request.form.get('password', '').strip()  # Get password from form
        current_password = request.form.get('current_password', '').strip()  # Also check current_password field
        password = password or current_password  # Use whichever is provided
        
        try:
            # Update recovery email if provided
            if recovery_email and recovery_email != user.recovery_email:
                old_email = user.recovery_email
                user.recovery_email = recovery_email
                
                # Create or update E-DEK when recovery email is added/changed (Requirement 18)
                if recovery_email and password:  # Setting up new email recovery - need password
                    user_keys = crypto_manager.get_user_keys(str(user.id))
                    if user_keys:
                        try:
                            email_password = crypto_manager.setup_email_recovery(user_keys, password, recovery_email)
                            
                            # Save the E-DEK to database first
                            user_keys.save()
                            print(f"✅ E-DEK saved to database")
                            
                            # Verify E-DEK was saved by reloading from database
                            user_keys.reload()
                            if user_keys.email_encrypted_key:
                                print(f"✅ E-DEK verified in database: {len(user_keys.email_encrypted_key)} chars")
                            else:
                                print(f"❌ E-DEK not found in database after save!")
                            
                            # Send email password to new recovery email (with timeout protection)
                            from email_utils import email_service
                            
                            print("🔄 Attempting to send recovery email...")
                            try:
                                # Set a shorter timeout for email to prevent hanging
                                import threading
                                import time
                                
                                email_result = [False]
                                
                                def send_email_thread():
                                    try:
                                        email_result[0] = email_service.send_recovery_code_email(user, email_password)
                                    except:
                                        pass  # Timeout will handle this
                                
                                # Try sending email with 5-second timeout
                                thread = threading.Thread(target=send_email_thread)
                                thread.daemon = True
                                thread.start()
                                thread.join(timeout=5)  # 5 second timeout
                                
                                if thread.is_alive():
                                    print("⚠️ Email sending timed out after 5 seconds")
                                    flash(f'Recovery email updated and E-DEK created! Email sending timed out - your recovery password is: {email_password}', 'warning')
                                elif email_result[0]:
                                    print("✅ Email sent successfully")
                                    flash(f'Recovery email updated and E-DEK password sent to {recovery_email}!', 'success')
                                else:
                                    print("❌ Email sending failed")
                                    flash(f'Recovery email updated and E-DEK created! Email failed - your recovery password is: {email_password}', 'warning')
                                    
                            except Exception as email_error:
                                print(f"❌ Email error: {str(email_error)}")
                                flash(f'Recovery email updated and E-DEK created! Email error - your recovery password is: {email_password}', 'warning')
                        except Exception as e:
                            flash(f'Recovery email updated but E-DEK setup failed: {str(e)}', 'warning')
                            logger.error(f"E-DEK setup failed during email update: {str(e)}")
                elif recovery_email and not password:
                    # Check if user is ONLY updating security questions and NOT changing email
                    if update_questions and not update_phrase:
                        # Allow email update without password if only updating security questions
                        flash('Recovery email updated successfully (without E-DEK setup)!', 'info')
                    else:
                        flash('Password is required to set up email recovery. Please enter your current password.', 'error')
                        return render_template('update_recovery.html', user=user)
                else:
                    flash('Recovery email updated successfully!', 'success')
            
            # Update security questions if requested
            if update_questions:
                security_questions = []
                for i in range(1, 4):
                    question = request.form.get(f'question_{i}', '').strip()
                    answer = request.form.get(f'answer_{i}', '').strip()
                    
                    if question and answer:
                        from models import SecurityQuestion
                        sq = SecurityQuestion(
                            question=question,
                            answer_hash=generate_password_hash(answer.lower())
                        )
                        security_questions.append(sq)
                
                if len(security_questions) == 3:
                    user.security_questions = security_questions
                    
                    # ✅ NEW: Update the Q-DEK in UserKeys when security questions are updated
                    user_keys = crypto_manager.get_user_keys(str(user.id))
                    if user_keys:
                        # Get current DEK from session (user must be logged in)
                        if 'user_dek' in session:
                            current_dek = bytes.fromhex(session['user_dek'])
                            
                            # Get the answers for Q-DEK creation
                            answers = [request.form.get(f'answer_{i}', '').lower().strip() for i in range(1, 4)]
                            combined_answers = ''.join(answers)
                            
                            # Create new Q-DEK
                            sq_key, sq_salt = crypto_manager.derive_key_from_password(combined_answers)
                            sq_encrypted = crypto_manager.encrypt_data(base64.urlsafe_b64encode(current_dek).decode(), sq_key)
                            
                            # Store in new JSON format
                            user_keys.security_questions_encrypted_key = json.dumps({
                                'encrypted': sq_encrypted,
                                'salt': base64.urlsafe_b64encode(sq_salt).decode()
                            })
                            user_keys.save()
                            
                            flash('Security questions and Q-DEK updated successfully!', 'success')
                        else:
                            flash('Please log in again to update security questions!', 'error')
                            return redirect(url_for('login'))
                    else:
                        flash('User keys not found! Please contact support.', 'error')
                        return render_template('update_recovery.html', user=user)
                else:
                    flash('Please provide all 3 security questions and answers!', 'error')
                    return render_template('update_recovery.html', user=user)
            
            # Update recovery phrase if requested
            if update_phrase:
                password = request.form.get('current_password', '')
                generated_phrase = request.form.get('generated_phrase', '')
                
                if not generated_phrase:
                    flash('Please generate a recovery phrase first!', 'error')
                    return render_template('update_recovery.html', user=user)
                
                if password and check_password_hash(user.password_hash, password):
                    user.recovery_phrase = crypto_manager.encrypt_with_password(
                        generated_phrase, password
                    )
                    
                    # ✅ NEW: Update the R-DEK in UserKeys when recovery phrase is updated
                    user_keys = crypto_manager.get_user_keys(str(user.id))
                    if user_keys:
                        # Get current DEK from session (user must be logged in)
                        if 'user_dek' in session:
                            current_dek = bytes.fromhex(session['user_dek'])
                            
                            # Create new R-DEK
                            rp_key, rp_salt = crypto_manager.derive_key_from_password(generated_phrase)
                            rp_encrypted = crypto_manager.encrypt_data(base64.urlsafe_b64encode(current_dek).decode(), rp_key)
                            
                            # Store in new JSON format
                            user_keys.recovery_phrase_encrypted_key = json.dumps({
                                'encrypted': rp_encrypted,
                                'salt': base64.urlsafe_b64encode(rp_salt).decode()
                            })
                            user_keys.save()
                            
                            flash('Recovery phrase and R-DEK updated successfully!', 'success')
                        else:
                            flash('Please log in again to update recovery phrase!', 'error')
                            return redirect(url_for('login'))
                    else:
                        flash('User keys not found! Please contact support.', 'error')
                        return render_template('update_recovery.html', user=user)
                else:
                    flash('Current password is required to update recovery phrase!', 'error')
                    return render_template('update_recovery.html', user=user)
            
            user.save()
            log_audit('recovery_options_updated', 'user', user.id)
            
            return redirect(url_for('user_profile'))
            
        except Exception as e:
            logger.error(f"Update recovery error: {str(e)}")
            flash('Failed to update recovery options. Please try again.', 'error')
    
    return render_template('update_recovery.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
@require_rate_limit(max_attempts=50, window_minutes=15)
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        try:
            user = User.objects(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                if user.is_active:
                    # ✅ NEW: Decrypt and store DEK in session for data encryption/decryption
                    try:
                        user_keys = crypto_manager.get_user_keys(str(user.id))
                        if user_keys:
                            print(f"🔍 Found user keys for {user.username}, attempting DEK recovery...")
                            # Decrypt the DEK using the password and store in session
                            dek = crypto_manager.recover_dek_with_password(user_keys, password)
                            session['user_dek'] = dek.hex()  # Store as hex string
                            print(f"✅ DEK successfully recovered and stored in session for user {user.username}")
                            print(f"✅ Session DEK length: {len(session['user_dek'])} chars")
                            
                            # ✅ NEW: Auto-migrate old encrypted data to new DEK system
                            from models import Secret
                            user_secrets = Secret.objects(user=user, needs_migration=True)
                            if user_secrets:
                                try:
                                    session_dek = bytes.fromhex(session['user_dek'])
                                    old_key = crypto_manager.derive_key_from_user_id(str(user.id))
                                    
                                    migrated_count = 0
                                    for secret in user_secrets:
                                        try:
                                            # Decrypt with old key
                                            old_content = crypto_manager.decrypt_data(secret.encrypted_data, old_key)
                                            
                                            # Re-encrypt with new DEK
                                            new_content = crypto_manager.encrypt_data(old_content, session_dek)
                                            
                                            # Update the secret
                                            secret.encrypted_data = new_content
                                            secret.needs_migration = False
                                            secret.save()
                                            
                                            migrated_count += 1
                                            print(f"✅ Migrated secret: {secret.title}")
                                            
                                        except Exception as e:
                                            print(f"❌ Failed to migrate secret {secret.id}: {str(e)}")
                                    
                                    if migrated_count > 0:
                                        flash(f'Successfully migrated {migrated_count} secrets to new encryption!', 'success')
                                        print(f"✅ Migration complete: {migrated_count} secrets updated")
                                        
                                except Exception as e:
                                    print(f"❌ Migration error: {str(e)}")
                            
                        else:
                            print(f"⚠️ No user keys found for {user.username} - they need to complete setup")
                            flash('Please complete your account setup first.', 'info')
                            return redirect(url_for('setup_keys'))
                    except Exception as e:
                        print(f"❌ Failed to decrypt DEK during login for {user.username}: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        flash('Failed to decrypt your data encryption key. Please contact support.', 'error')
                        return redirect(url_for('login'))
                    
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    user.last_activity = datetime.utcnow()
                    user.last_logout = None  # Clear any previous logout
                    user.server_restart_at = None  # Clear server restart marker
                    user.save()
                    
                    log_audit('user_login', 'auth', user.id)
                    
                    # Check if user needs to change password (admin-created accounts)
                    if user.force_password_change:
                        flash('Please change your password to complete account setup.', 'info')
                        return redirect(url_for('force_password_change'))
                    
                    return redirect(url_for('secrets'))
                else:
                    flash('Your account has been deactivated!', 'error')
            else:
                flash('Invalid username or password!', 'error')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit('user_logout', 'auth', current_user.id)
    # ✅ NEW: Clear DEK from session on logout for security
    if 'user_dek' in session:
        del session['user_dek']
        print(f"✅ DEK cleared from session for user {current_user.username}")
    logout_user()
    flash('You have been logged out successfully!', 'info')
    return redirect(url_for('index'))

@app.route('/api/browser_close_logout', methods=['POST'])
@login_required
def browser_close_logout():
    """Handle logout when browser tab is closed or page is unloaded"""
    try:
        # Get logout type from request
        logout_type = 'tab_close'
        if request.is_json:
            data = request.get_json() or {}
            logout_type = data.get('logout_type', 'tab_close')
        elif request.form:
            logout_type = request.form.get('logout_type', 'tab_close')
        
        # Log the tab close logout
        log_audit('tab_close_logout', 'auth', current_user.id, {
            'logout_type': logout_type,
            'user_agent': request.headers.get('User-Agent', ''),
            'ip_address': request.remote_addr
        })
        
        # Update user's last logout time
        current_user.last_logout = datetime.utcnow()
        current_user.save()
        
        # Clear DEK from session for security
        if 'user_dek' in session:
            del session['user_dek']
            print(f"✅ DEK cleared from session for user {current_user.username} (tab close)")
        
        # Remove from active sessions
        session_id = session.get('_id', getattr(session, 'sid', None))
        if session_id and hasattr(app, 'active_sessions'):
            try:
                app.active_sessions.discard(session_id)
            except:
                pass
        
        # Logout the user
        logout_user()
        
        return jsonify({'success': True, 'message': f'Logged out due to {logout_type}'})
    except Exception as e:
        print(f"Error in tab close logout: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/check_session')
@login_required
def check_session():
    """Check if user session is still valid"""
    try:
        # Check for server restart invalidation
        import os
        if os.path.exists('.server_restart_time'):
            with open('.server_restart_time', 'r') as f:
                restart_time_str = f.read().strip()
                restart_time = datetime.fromisoformat(restart_time_str)
                
                # If user logged in before the server restart, session is invalid
                if current_user.last_login and current_user.last_login < restart_time:
                    logout_user()
                    session.clear()
                    return jsonify({'success': False, 'error': 'Session invalidated by server restart', 'redirect': url_for('login')}), 401
        
        # Check if user was logged out due to server restart
        if (current_user.server_restart_at and 
            current_user.last_login and 
            current_user.server_restart_at > current_user.last_login):
            logout_user()
            session.clear()
            return jsonify({'success': False, 'error': 'Session invalidated by server restart', 'redirect': url_for('login')}), 401
        
        # Update last activity time
        current_user.last_activity = datetime.utcnow()
        current_user.save()
        return jsonify({'success': True, 'user': current_user.username})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Session invalid'}), 401

@app.route('/api/force_session_check')
def force_session_check():
    """Force check all sessions for validity - useful for testing restart logout"""
    try:
        import os
        from datetime import datetime
        
        if not os.path.exists('.server_restart_time'):
            return jsonify({'message': 'No server restart marker found'})
            
        with open('.server_restart_time', 'r') as f:
            restart_time_str = f.read().strip()
            restart_time = datetime.fromisoformat(restart_time_str)
        
        # If user is logged in, check if session should be invalidated
        if current_user.is_authenticated:
            if current_user.last_login and current_user.last_login < restart_time:
                logout_user()
                session.clear()
                return jsonify({
                    'message': 'Session invalidated',
                    'reason': 'User logged in before server restart',
                    'user_login': current_user.last_login.isoformat(),
                    'server_restart': restart_time_str,
                    'redirect': url_for('login')
                })
            else:
                return jsonify({
                    'message': 'Session valid',
                    'user': current_user.username,
                    'user_login': current_user.last_login.isoformat() if current_user.last_login else None,
                    'server_restart': restart_time_str
                })
        else:
            return jsonify({
                'message': 'No user logged in',
                'server_restart': restart_time_str
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/force_password_change', methods=['GET', 'POST'])
def force_password_change():
    """Force password change for admin-created accounts - ISOLATED VERSION"""
    
    # Manual authentication check to avoid decorator issues
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
        
    # Only allow if user has force_password_change flag
    if not hasattr(current_user, 'force_password_change') or not current_user.force_password_change:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required!', 'error')
            return render_template('force_password_change.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match!', 'error')
            return render_template('force_password_change.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long!', 'error')
            return render_template('force_password_change.html')
        
        # Verify current password
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect!', 'error')
            return render_template('force_password_change.html')
        
        try:
            # Get user info before operations
            user_id = str(current_user.id)
            username = current_user.username
            
            # Update user password hash FIRST
            current_user.password_hash = generate_password_hash(new_password)
            current_user.force_password_change = False
            current_user.last_password_change = datetime.utcnow()
            current_user.save()
            
            # Update P-DEK using crypto manager
            user_keys = UserKeys.objects(user=current_user).first()
            if user_keys and user_keys.password_encrypted_key:
                try:
                    print(f"🔍 Updating P-DEK for user {username}")
                    # Use the crypto manager to update password
                    updated_keys = crypto_manager.update_user_password_only(user_keys, current_password, new_password)
                    updated_keys.save()
                    print(f"✅ P-DEK successfully updated")
                except Exception as e:
                    print(f"❌ P-DEK update failed for {username}: {str(e)}")
            # Simple audit log (no complex dependencies)
            logger.info(f"Forced password change completed for user {username}")
            
            flash('Password changed successfully! You can now use all features.', 'success')
            return redirect(url_for('login'))  # Go to login instead of secrets to avoid other decorators
            
        except Exception as e:
            logger.error(f"Force password change error: {str(e)}")
            flash('Failed to change password. Please try again.', 'error')
    
    return render_template('force_password_change.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        if verify_email_token(token):
            flash('Email verified successfully! You can now log in.', 'success')
        else:
            flash('Invalid or expired verification token!', 'error')
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}")
        flash('Email verification failed!', 'error')
    
    return redirect(url_for('login'))

@app.route('/secrets')
@login_required
@password_change_required
def secrets():
    try:
        
        # Admins should not access user secret management
        if current_user.is_admin:
            flash('Admins cannot manage secrets. Please use the admin dashboard.', 'info')
            return redirect(url_for('admin_dashboard'))
        
        # Debug: Check if user has keys and session state
        logger.info(f"User {current_user.username} - Session user_dek exists: {'user_dek' in session}")
        if 'user_dek' in session:
            logger.info(f"User {current_user.username} - Session DEK length: {len(session['user_dek'])} chars")
        
        user_keys = UserKeys.objects(user=current_user).first()
        logger.info(f"User {current_user.username} - UserKeys found: {user_keys is not None}")
        
        if not user_keys:
            flash('Please set up your encryption keys first.', 'info')
            return redirect(url_for('setup_keys'))
        
        # Get user's secrets
        user_secrets = Secret.objects(user=current_user).order_by('-created_at')
        
        # Decrypt secrets for display
        decrypted_secrets = []
        for secret in user_secrets:
            try:
                decrypted_content = crypto_manager.decrypt_user_data(secret.encrypted_data, current_user.id)
                secret_data = {
                    'id': str(secret.id),
                    'title': secret.title,
                    'content': decrypted_content,
                    'notes': secret.notes,
                    'created_at': secret.created_at,
                    'updated_at': secret.updated_at
                }
                decrypted_secrets.append(secret_data)
            except Exception as e:
                logger.error(f"Failed to decrypt secret {secret.id}: {str(e)}")
                # Include encrypted secret with error flag
                secret_data = {
                    'id': str(secret.id),
                    'title': secret.title,
                    'content': '[DECRYPTION FAILED]',
                    'notes': secret.notes,
                    'error': True,
                    'created_at': secret.created_at
                }
                decrypted_secrets.append(secret_data)
        
        return render_template('secrets.html', secrets=decrypted_secrets)
        
    except Exception as e:
        logger.error(f"Error loading secrets: {str(e)}")
        flash('Error loading secrets!', 'error')
        return render_template('secrets.html', secrets=[])

@app.route('/secrets/add', methods=['POST'])
@login_required
def add_secret():
    try:
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        notes = request.form.get('notes', '').strip()
        
        if not title or not content:
            flash('Title and content are required!', 'error')
            return redirect(url_for('secrets'))
        
        # Get user's current key version
        user_keys = UserKeys.objects(user=current_user).first()
        if not user_keys:
            flash('User keys not found! Please contact support.', 'error')
            return redirect(url_for('secrets'))
        
        # Encrypt the content
        encrypted_content = crypto_manager.encrypt_user_data(content, current_user.id)
        
        # Create new secret
        secret = Secret(
            user=current_user,
            title=title,
            encrypted_data=encrypted_content,
            notes=notes if notes else None,
            key_version=user_keys.key_version
        )
        secret.save()
        
        log_audit('secret_create', 'secret', secret.id, {'title': title})
        flash('Secret added successfully!', 'success')
        
    except Exception as e:
        logger.error(f"Error adding secret: {str(e)}")
        flash('Failed to add secret!', 'error')
    
    return redirect(url_for('secrets'))

@app.route('/secrets/edit/<secret_id>', methods=['POST'])
@login_required
def edit_secret(secret_id):
    try:
        secret = Secret.objects(id=secret_id, user=current_user).first()
        if not secret:
            flash('Secret not found!', 'error')
            return redirect(url_for('secrets'))
        
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        notes = request.form.get('notes', '').strip()
        
        if not title or not content:
            flash('Title and content are required!', 'error')
            return redirect(url_for('secrets'))
        
        # Encrypt the new content
        encrypted_content = crypto_manager.encrypt_user_data(content, current_user.id)
        
        # Update secret
        secret.title = title
        secret.encrypted_data = encrypted_content
        secret.notes = notes if notes else None
        secret.save()
        
        log_audit('secret_update', 'secret', secret.id, {'title': title})
        flash('Secret updated successfully!', 'success')
        
    except Exception as e:
        logger.error(f"Error editing secret: {str(e)}")
        flash('Failed to update secret!', 'error')
    
    return redirect(url_for('secrets'))

@app.route('/secrets/delete/<secret_id>', methods=['POST'])
@login_required
def delete_secret(secret_id):
    try:
        secret = Secret.objects(id=secret_id, user=current_user).first()
        if not secret:
            flash('Secret not found!', 'error')
            return redirect(url_for('secrets'))
        
        title = secret.title
        secret.delete()
        
        log_audit('secret_delete', 'secret', secret_id, {'title': title})
        flash('Secret deleted successfully!', 'success')
        
    except Exception as e:
        logger.error(f"Error deleting secret: {str(e)}")
        flash('Failed to delete secret!', 'error')
    
    return redirect(url_for('secrets'))

@app.route('/profile')
@login_required
@password_change_required
def user_profile():
    try:
        journal_count = JournalEntry.objects(user=current_user).count()
        shared_count = 0  # Placeholder for shared secrets count
        
        # Get user's encryption keys if they exist
        try:
            user_keys = crypto_manager.get_user_keys(current_user.id)
        except Exception as e:
            logger.warning(f"Could not load user keys: {str(e)}")
            user_keys = None
        
        return render_template('user_profile.html', 
                             journal_count=journal_count, 
                             shared_count=shared_count,
                             user_keys=user_keys)
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        flash('Error loading profile.', 'error')
        return redirect(url_for('secrets'))

@app.route('/export_data')
@login_required
def export_data():
    """Export user data as JSON for backup purposes"""
    try:
        # Collect user data
        export_data = {
            'export_info': {
                'username': current_user.username,
                'export_date': datetime.utcnow().isoformat(),
                'export_version': '1.0',
                'encryption_note': 'Secrets are exported in encrypted form for security'
            },
            'user_profile': {
                'username': current_user.username,
                'email': current_user.email,
                'email_verified': current_user.email_verified,
                'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
                'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
                'is_admin': current_user.is_admin,
                'password_changed_at': current_user.password_changed_at.isoformat() if current_user.password_changed_at else None
            },
            'secrets': [],
            'journal_entries': [],
            'security_setup': {
                'has_security_questions': bool(current_user.security_questions),
                'has_recovery_phrase': bool(current_user.recovery_phrase),
                'has_encryption_keys': bool(UserKeys.objects(user=current_user).first()),
                'key_version': UserKeys.objects(user=current_user).first().key_version if UserKeys.objects(user=current_user).first() else None
            }
        }
        
        # Export secrets (encrypted for security)
        user_secrets = Secret.objects(user=current_user)
        for secret in user_secrets:
            export_data['secrets'].append({
                'id': str(secret.id),
                'title': secret.title,
                'encrypted_data': secret.encrypted_data,  # Keep encrypted for security
                'notes': secret.notes,
                'created_at': secret.created_at.isoformat() if secret.created_at else None,
                'updated_at': secret.updated_at.isoformat() if secret.updated_at else None
            })
        
        # Export journal entries
        user_journal_entries = JournalEntry.objects(user=current_user)
        for entry in user_journal_entries:
            export_data['journal_entries'].append({
                'id': str(entry.id),
                'entry_date': entry.entry_date.isoformat(),
                'content': entry.content,
                'mood': entry.mood,
                'tags': entry.tags,
                'created_at': entry.created_at.isoformat() if entry.created_at else None,
                'updated_at': entry.updated_at.isoformat() if entry.updated_at else None
            })
        
        # Log the export action
        log_audit('data_export', 'system', details={
            'secrets_count': len(export_data['secrets']),
            'journal_entries_count': len(export_data['journal_entries'])
        })
        
        # Create JSON response with proper headers for download
        from flask import Response
        
        json_data = json.dumps(export_data, indent=2, ensure_ascii=False)
        
        # Create filename with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"lifevault_backup_{current_user.username}_{timestamp}.json"
        
        response = Response(
            json_data,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/json; charset=utf-8'
            }
        )
        
        flash('Data export completed successfully!', 'success')
        return response
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        flash('Failed to export data. Please try again.', 'error')
        return redirect(url_for('user_profile'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow users to change their password"""
    if request.method == 'POST':
        logger.info(f"Change password attempt for user {current_user.username}")
        
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        logger.debug(f"Form data received - current_password: {'*' * len(current_password)}, new_password: {'*' * len(new_password)}, confirm_password: {'*' * len(confirm_password)}")
        
        # Validation
        if not all([current_password, new_password, confirm_password]):
            flash('All password fields are required.', 'error')
            logger.warning("Password change failed: Missing required fields")
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            logger.warning("Password change failed: Password confirmation mismatch")
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
            logger.warning("Password change failed: Password too short")
            return render_template('change_password.html')
        
        if current_password == new_password:
            flash('New password must be different from current password.', 'error')
            logger.warning("Password change failed: New password same as current")
            return render_template('change_password.html')
        
        # Verify current password
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'error')
            logger.warning("Password change failed: Incorrect current password")
            log_audit('password_change_failed', 'user', current_user.id, 
                     {'reason': 'incorrect_current_password'}, success=False)
            return render_template('change_password.html')
        
        try:
            logger.info(f"Starting password change process for user {current_user.id}")
            
            # Check if this is an admin user
            if current_user.is_admin:
                logger.info("Admin user detected - using admin password change process")
                
                # Use special admin password change that rotates master key
                success = crypto_manager.update_admin_password_and_rotate_master_key(
                    current_user, current_password, new_password
                )
                
                if success:
                    logger.info("Admin password and master key rotation completed successfully")
                    
                    # Clear session to force re-login with new password
                    session.clear()
                    
                    flash('Admin password changed successfully! All user encryption keys have been updated. Please log in with your new password.', 'success')
                    log_audit('admin_password_changed', 'admin', current_user.id, 
                             {'method': 'admin_initiated', 'a_dek_rotated': True}, success=True)
                    return redirect(url_for('login'))
                else:
                    flash('Failed to update admin password and encryption keys. Please try again.', 'error')
                    logger.error("Admin password change failed")
                    log_audit('admin_password_change_failed', 'admin', current_user.id, 
                             {'reason': 'admin_key_rotation_failed'}, success=False)
                    return render_template('change_password.html')
            
            else:
                # Regular user password change
                logger.info("Regular user detected - using standard password change process")
                
                # Get user keys to re-encrypt with new password
                user_keys = crypto_manager.get_user_keys(current_user.id)
                if not user_keys:
                    flash('Encryption keys not found. Please contact support.', 'error')
                    logger.error("Password change failed: No encryption keys found")
                    return render_template('change_password.html')
                
                logger.info("User keys found, updating password-based encryption key")
                
                # Update the password-based encryption key (P-DEK) - ISOLATED METHOD
                updated_keys = crypto_manager.update_user_password_only(user_keys, current_password, new_password)
                
                if updated_keys:
                    logger.info("Encryption keys updated successfully, saving to database")
                    
                    # Save the updated keys to database
                    updated_keys.save()
                    logger.info("Updated keys saved to database")
                    
                    # Update password hash in user record
                    current_user.password_hash = generate_password_hash(new_password)
                    current_user.password_changed_at = datetime.utcnow()
                    current_user.save()
                    logger.info("User password hash updated")
                    
                    # Clear session to force re-login with new password
                    session.clear()
                    logger.info("Session cleared, password change complete")
                    
                    flash('Password changed successfully! Please log in with your new password.', 'success')
                    log_audit('password_changed', 'user', current_user.id, 
                             {'method': 'user_initiated'}, success=True)
                    return redirect(url_for('login'))
                else:
                    flash('Failed to update encryption keys. Please try again.', 'error')
                    logger.error("Password change failed: update_password_key returned None/False")
                    log_audit('password_change_failed', 'user', current_user.id, 
                             {'reason': 'encryption_key_update_failed'}, success=False)
                    return render_template('change_password.html')
                
        except Exception as e:
            logger.error(f"Password change error for user {current_user.id}: {str(e)}")
            flash('An error occurred while changing password. Please try again.', 'error')
            log_audit('password_change_failed', 'user', current_user.id, 
                     {'reason': 'system_error', 'error': str(e)}, success=False)
            return render_template('change_password.html')
    
    return render_template('change_password.html')

@app.route('/api/initialize_keys', methods=['POST'])
@login_required
def api_initialize_keys():
    try:
        # Check if user already has keys
        try:
            existing_keys = crypto_manager.get_user_keys(current_user.id)
            if existing_keys:
                return jsonify({'success': False, 'error': 'Keys already exist'})
        except:
            pass  # Keys don't exist, which is expected
        
        # Create the user's encryption keys
        success = crypto_manager.create_user_keys(
            user_id=current_user.id,
            password=current_user.password_hash,  # Use hashed password
            security_answers=[current_user.security_question_1_answer, 
                            current_user.security_question_2_answer, 
                            current_user.security_question_3_answer],
            recovery_phrase=current_user.recovery_phrase
        )
        
        if success:
            log_audit('key_initialization', 'encryption_keys', current_user.id, 
                     'Encryption keys initialized successfully')
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to create keys'})
        
    except Exception as e:
        logger.error(f"Key initialization error: {str(e)}")
        log_audit('key_initialization', 'encryption_keys', current_user.id, 
                 f'Key initialization failed: {str(e)}', success=False, error_message=str(e))
        return jsonify({'success': False, 'error': str(e)})

@app.route('/key_rotation', methods=['GET'])
@login_required
def key_rotation():
    """Unified user key rotation management page"""
    return render_template('user_key_rotation.html')

@app.route('/admin/key_rotation_management', methods=['GET'])
@admin_required
def admin_key_rotation_management():
    """Unified admin key rotation management page"""
    return render_template('admin_key_rotation_management.html')

@app.route('/api/user_rotation_requests', methods=['GET'])
@login_required
def get_user_rotation_requests():
    """Get rotation requests for current user"""
    try:
        from models import RotationToken
        requests = RotationToken.objects(user_id=str(current_user.id)).order_by('-created_at')
        
        request_data = []
        for req in requests:
            request_data.append({
                'id': str(req.id),
                'status': req.status,
                'reason': req.request_reason,
                'description': getattr(req, 'description', ''),
                'created_at': req.created_at.isoformat() if req.created_at else None,
                'approved_at': req.approved_at.isoformat() if req.approved_at else None,
                'expires_at': req.expires_at.isoformat() if req.expires_at else None,
                'token_id': str(req.id) if req.status == 'approved' else None
            })
        
        return jsonify({'requests': request_data})
    except Exception as e:
        logger.error(f"Error fetching user rotation requests: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user_recovery_methods', methods=['GET'])
@login_required
def get_user_recovery_methods():
    """Get user's configured recovery methods for key rotation"""
    try:
        from models import UserKeys
        
        # Get user's current recovery setup
        user_keys = UserKeys.objects(user=current_user).first()
        
        if not user_keys:
            return jsonify({
                'success': False,
                'error': 'No user keys found'
            }), 404
        
        recovery_methods = {
            'has_security_questions': bool(user_keys.security_questions_encrypted_key),
            'has_recovery_phrase': bool(user_keys.recovery_phrase_encrypted_key),
            'has_email_recovery': bool(user_keys.email_encrypted_key),
            'recovery_email': current_user.recovery_email if hasattr(current_user, 'recovery_email') else None
        }
        
        return jsonify({
            'success': True,
            'methods': recovery_methods
        })
        
    except Exception as e:
        logger.error(f"Error fetching user recovery methods: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/admin/api/rotation_requests', methods=['GET'])
@admin_required  
def get_all_rotation_requests():
    """Get all rotation requests (admin only)"""
    try:
        from models import RotationToken, User
        
        status_filter = request.args.get('status')
        
        if status_filter:
            requests = RotationToken.objects(status=status_filter).order_by('-created_at')
        else:
            requests = RotationToken.objects().order_by('-created_at')
        
        request_data = []
        for req in requests:
            # Get username
            try:
                user = User.objects(id=req.user_id).first()
                username = user.username if user else 'Unknown User'
            except:
                username = 'Unknown User'
            
            request_data.append({
                'id': str(req.id),
                'user_id': req.user_id,
                'username': username,
                'status': req.status,
                'reason': req.request_reason,
                'description': getattr(req, 'description', ''),
                'created_at': req.created_at.isoformat() if req.created_at else None,
                'approved_at': req.approved_at.isoformat() if req.approved_at else None,
                'expires_at': req.expires_at.isoformat() if req.expires_at else None,
                'token_id': str(req.id) if req.status == 'approved' else None
            })
        
        return jsonify({'requests': request_data})
    except Exception as e:
        logger.error(f"Error fetching rotation requests: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/delete_rotation_request/<request_id>', methods=['DELETE'])
@admin_required
def delete_rotation_request(request_id):
    """Delete a specific rotation request"""
    try:
        from models import RotationToken
        
        rotation_request = RotationToken.objects(id=request_id).first()
        if not rotation_request:
            return jsonify({'error': 'Request not found'}), 404
        
        rotation_request.delete()
        logger.info(f"Admin {current_user.username} deleted rotation request {request_id}")
        
        return jsonify({'success': True, 'message': 'Request deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting rotation request: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/cleanup_requests', methods=['DELETE'])
@admin_required
def cleanup_rotation_requests():
    """Cleanup rotation requests based on type"""
    try:
        from models import RotationToken
        cleanup_type = request.args.get('type', 'expired')
        user_id = request.args.get('user_id')
        
        deleted_count = 0
        
        if cleanup_type == 'expired':
            # Delete expired requests
            from datetime import datetime
            expired_requests = RotationToken.objects(expires_at__lt=datetime.utcnow())
            deleted_count = expired_requests.count()
            expired_requests.delete()
            
        elif cleanup_type == 'finalized':
            # Delete finalized requests
            finalized_requests = RotationToken.objects(status='finalized')
            deleted_count = finalized_requests.count()
            finalized_requests.delete()
            
        elif cleanup_type == 'failed':
            # Delete failed requests
            failed_requests = RotationToken.objects(status='failed')
            deleted_count = failed_requests.count()
            failed_requests.delete()
            
        elif cleanup_type == 'user' and user_id:
            # Delete all requests for specific user
            user_requests = RotationToken.objects(user_id=user_id)
            deleted_count = user_requests.count()
            user_requests.delete()
            
        elif cleanup_type == 'all':
            # Delete ALL requests (dangerous!)
            all_requests = RotationToken.objects()
            deleted_count = all_requests.count()
            all_requests.delete()
            
        else:
            return jsonify({'error': 'Invalid cleanup type'}), 400
        
        logger.info(f"Admin {current_user.username} cleaned up {deleted_count} rotation requests (type: {cleanup_type})")
        
        return jsonify({
            'success': True, 
            'message': f'Cleanup completed',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/finalize_a_dek', methods=['POST'])
@admin_required
def finalize_a_dek_route():
    """Finalize A-DEK for a user"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        admin_password = data.get('admin_password')
        
        if not user_id or not admin_password:
            return jsonify({'error': 'User ID and admin password required'}), 400
        
        # Verify admin password
        if not check_password_hash(current_user.password_hash, admin_password):
            return jsonify({'error': 'Invalid admin password'}), 401
        
        # Find user
        from models import User, UserKeys
        user = User.objects(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys:
            return jsonify({'error': 'User keys not found'}), 404
        
        # Finalize A-DEK
        from crypto_utils import crypto_manager
        crypto_manager.finalize_a_dek(user_keys, current_user.username, admin_password)
        
        logger.info(f"Admin {current_user.username} finalized A-DEK for user {user.username}")
        
        return jsonify({
            'success': True,
            'message': f'A-DEK finalized successfully for user {user.username}'
        })
        
    except Exception as e:
        logger.error(f"Error finalizing A-DEK: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rotate_keys', methods=['POST'])
@login_required
def api_rotate_keys():
    """
    Full key rotation - requires user to provide all credential values again
    because Q-DEK and R-DEK cannot be rotated without the actual answers/phrase.
    """
    try:
        # Get required parameters from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request data required'})
        
        current_password = data.get('current_password')
        new_password = data.get('new_password', current_password)  # Optional new password
        security_answers = data.get('security_answers', [])  # List of 3 answers
        recovery_phrase = data.get('recovery_phrase')
        
        # Validate required inputs
        if not current_password:
            return jsonify({'success': False, 'error': 'Current password required'})
        
        if not security_answers or len(security_answers) != 3:
            return jsonify({'success': False, 'error': 'All 3 security question answers required'})
        
        if not recovery_phrase:
            return jsonify({'success': False, 'error': 'Recovery phrase required'})
        
        # Verify current password
        from werkzeug.security import check_password_hash
        if not check_password_hash(current_user.password_hash, current_password):
            return jsonify({'success': False, 'error': 'Invalid current password'})
        
        # Get current keys to verify they exist
        try:
            current_keys = crypto_manager.get_user_keys(current_user.id)
            if not current_keys:
                return jsonify({'success': False, 'error': 'No keys to rotate'})
        except Exception as e:
            return jsonify({'success': False, 'error': 'Keys not found'})
        
        # Get all user's secrets for re-encryption
        secrets = Secret.objects(user=current_user)
        
        # Decrypt all secrets with current keys
        decrypted_secrets = []
        for secret in secrets:
            try:
                decrypted_content = crypto_manager.decrypt_user_data(secret.encrypted_data, current_user.id)
                decrypted_secrets.append({
                    'secret': secret,
                    'content': decrypted_content
                })
            except Exception as e:
                logger.error(f"Failed to decrypt secret {secret.id} during key rotation: {str(e)}")
                return jsonify({'success': False, 'error': f'Failed to decrypt existing data'})
        
        # Generate new DEK and rotate all keys while preserving admin access
        try:
            new_dek, updated_keys = crypto_manager.rotate_user_keys_preserve_admin_access(
                user_keys=current_keys,
                password=new_password,
                security_answers=security_answers,
                recovery_phrase=recovery_phrase
            )
            
            # Save updated keys to database
            updated_keys.save()
            
            # Store new DEK in session for re-encryption
            session['user_dek'] = new_dek.hex()
            
        except Exception as e:
            logger.error(f"Failed to rotate keys: {str(e)}")
            return jsonify({'success': False, 'error': 'Failed to rotate encryption keys'})
        
        # Update user password if it changed
        if new_password != current_password:
            from werkzeug.security import generate_password_hash
            current_user.password_hash = generate_password_hash(new_password)
            current_user.password_changed_at = datetime.utcnow()
            current_user.save()
        
        # Re-encrypt all secrets with new DEK (this preserves admin access through new A-DEK)
        for item in decrypted_secrets:
            try:
                new_encrypted_content = crypto_manager.encrypt_user_data(item['content'], current_user.id)
                item['secret'].encrypted_data = new_encrypted_content
                item['secret'].save()
            except Exception as e:
                logger.error(f"Failed to re-encrypt secret {item['secret'].id}: {str(e)}")
                return jsonify({'success': False, 'error': 'Failed to re-encrypt data'})
        
        log_audit('key_rotation', 'encryption_keys', current_user.id, 
                 f'Complete key rotation successful: new DEK generated, all 5 keys rotated (P-DEK, Q-DEK, R-DEK, A-DEK, T-DEK), {len(secrets)} secrets re-encrypted, admin access preserved')
        return jsonify({'success': True, 'message': 'All encryption keys rotated successfully. Admin recovery access has been preserved.'})
        
    except Exception as e:
        logger.error(f"Key rotation error: {str(e)}")
        log_audit('key_rotation', 'encryption_keys', current_user.id, 
                 f'Key rotation failed: {str(e)}', success=False)
        return jsonify({'success': False, 'error': str(e)})

# Password Recovery Routes (for users who forgot their password)

@app.route('/recovery', methods=['GET', 'POST'])
def recovery():
    """Main recovery route - entry point for password recovery"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        recovery_type = request.form.get('recovery_type', '').strip()
        
        if not username:
            flash('Please enter your username.', 'error')
            return render_template('recovery.html')
        
        try:
            user = User.objects(username=username).first()
            if not user:
                flash('User not found.', 'error')
                return render_template('recovery.html')
            
            if recovery_type == 'security_questions':
                return redirect(url_for('security_questions_recovery', username=username))
            elif recovery_type == 'recovery_phrase':
                return redirect(url_for('recover_password_with_phrase', username=username))
            elif recovery_type == 'email':
                return redirect(url_for('email_recovery', username=username))
            else:
                flash('Please select a recovery method.', 'error')
                return render_template('recovery.html')
                
        except Exception as e:
            logger.error(f"Recovery error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
            return render_template('recovery.html')
    
    return render_template('recovery.html')

@app.route('/recovery/security_questions/<username>', methods=['GET', 'POST'])
def security_questions_recovery(username):
    """Security questions recovery route"""
    try:
        user = User.objects(username=username).first()
        if not user or not user.security_questions:
            flash('Security questions not set up for this user.', 'error')
            return redirect(url_for('recovery'))
        
        if request.method == 'POST':
            answers = [
                request.form.get('answer1', '').strip(),
                request.form.get('answer2', '').strip(), 
                request.form.get('answer3', '').strip()
            ]
            
            # Try to recover DEK using security questions
            try:
                user_keys = UserKeys.objects(user=user).first()
                if not user_keys or not user_keys.security_questions_encrypted_key:
                    flash('Recovery keys not properly set up.', 'error')
                    return render_template('security_questions_recovery.html', 
                                         username=username,
                                         questions=[sq.question for sq in user.security_questions])
                
                # Attempt recovery using crypto manager
                dek = crypto_manager.recover_dek_with_security_questions(user_keys, answers)
                
                # If successful, store recovery session
                session['recovery_user_id'] = str(user.id)
                session['recovery_method'] = 'security_questions'
                flash('Security questions verified! You can now reset your password.', 'success')
                return redirect(url_for('reset_password_form'))
                
            except Exception as e:
                logger.error(f"Security questions recovery failed for user {username}: {str(e)}")
                flash('Incorrect answers. Please try again.', 'error')
                return render_template('security_questions_recovery.html', 
                                     username=username,
                                     questions=[sq.question for sq in user.security_questions])
        
        return render_template('security_questions_recovery.html', 
                             username=username,
                             questions=[sq.question for sq in user.security_questions])
        
    except Exception as e:
        logger.error(f"Security questions recovery error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('recovery'))

@app.route('/recovery/phrase/<username>', methods=['GET', 'POST'])
def recovery_phrase_recovery(username):
    """Recovery phrase recovery route"""
    try:
        user = User.objects(username=username).first()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('recovery'))
        
        if request.method == 'POST':
            recovery_phrase = request.form.get('recovery_phrase', '').strip()
            
            if not recovery_phrase:
                flash('Please enter your recovery phrase.', 'error')
                return render_template('recovery_phrase.html', username=username)
            
            try:
                user_keys = UserKeys.objects(user=user).first()
                if not user_keys or not user_keys.recovery_phrase_encrypted_key:
                    flash('Recovery phrase not properly set up.', 'error')
                    return render_template('recovery_phrase.html', username=username)
                
                # Check if the provided recovery phrase is correct
                # The recovery phrase should be compared as-is since it was generated and stored during setup
                # We use the recovery phrase directly to decrypt the DEK from user_keys
                dek = crypto_manager.recover_dek_with_recovery_phrase(user_keys, recovery_phrase)
                
                # If successful, store recovery session
                session['recovery_user_id'] = str(user.id)
                session['recovery_method'] = 'recovery_phrase'
                flash('Recovery phrase verified! You can now reset your password.', 'success')
                return redirect(url_for('reset_password_form'))
                
            except Exception as e:
                logger.error(f"Recovery phrase recovery failed for user {username}: {str(e)}")
                flash('Invalid recovery phrase. Please try again.', 'error')
                return render_template('recovery_phrase.html', username=username)
        
        return render_template('recovery_phrase.html', username=username)
        
    except Exception as e:
        logger.error(f"Recovery phrase recovery error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('recovery'))

@app.route('/recovery/email/<username>', methods=['GET', 'POST'])
def email_recovery(username):
    """E-DEK based email recovery route (Requirement 18d)"""
    try:
        user = User.objects(username=username).first()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('recovery'))
        
        if not user.recovery_email:
            flash('No recovery email configured for this account. Please contact support.', 'error')
            return render_template('email_recovery.html', username=username)
        
        user_keys = UserKeys.objects(user=user).first()
        if not user_keys or not user_keys.email_encrypted_key:
            flash('Email recovery not properly configured. Please contact support.', 'error')
            return render_template('email_recovery.html', username=username)
        
        if request.method == 'POST':
            action = request.form.get('action', 'request_password')
            
            if action == 'request_password':
                # Send/resend the email password to user
                try:
                    # In production, we would regenerate and send a new password
                    # For now, we'll generate a new email password and update E-DEK
                    current_password = request.form.get('current_password', '')
                    if current_password:
                        # User wants to reset email recovery password
                        new_email_password = crypto_manager.reset_email_recovery(user_keys, current_password, user.recovery_email)
                    else:
                        # User requesting password (we can't retrieve the old one)
                        flash('Email recovery password cannot be retrieved. You need to reset it with your current password.', 'error')
                        return render_template('email_recovery.html', username=username, show_reset=True)
                    
                    # Send new email password
                    from email_utils import email_service
                    email_sent = email_service.send_recovery_code_email(user, new_email_password)
                    
                    if email_sent:
                        flash(f'New recovery password sent to {user.recovery_email}. Check your email!', 'success')
                        user_keys.save()
                    else:
                        flash('Failed to send recovery email. Please try again later.', 'error')
                        
                except Exception as e:
                    logger.error(f"E-DEK email password reset failed for user {username}: {str(e)}")
                    flash('Failed to reset email recovery. Please try again.', 'error')
                    
            elif action == 'recover_account':
                # User has the email password and wants to recover account
                email_password = request.form.get('email_password', '').strip()
                new_password = request.form.get('new_password', '').strip()
                confirm_password = request.form.get('confirm_password', '').strip()
                
                if not email_password:
                    flash('Please enter the email recovery password.', 'error')
                    return render_template('email_recovery.html', username=username)
                
                if not new_password or new_password != confirm_password:
                    flash('Please enter a valid new password.', 'error')
                    return render_template('email_recovery.html', username=username)
                
                try:
                    # Recover DEK using email password (E-DEK)
                    dek = crypto_manager.recover_dek_with_email_password(user_keys, email_password)
                    
                    # Create new P-DEK with new password
                    password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
                    encrypted_dek_b64 = crypto_manager.encrypt_data(base64.urlsafe_b64encode(dek).decode(), password_key)
                    
                    # Update user password and P-DEK
                    user.password_hash = generate_password_hash(new_password)
                    user_keys.password_encrypted_key = json.dumps({
                        'salt': base64.urlsafe_b64encode(password_salt).decode(),
                        'encrypted': encrypted_dek_b64
                    })
                    user_keys.key_version += 1
                    
                    user.save()
                    user_keys.save()
                    
                    flash('Account recovered successfully! You can now login with your new password.', 'success')
                    log_audit('email_recovery_success', 'recovery', 
                             details={'user': username, 'method': 'email_password'})
                    return redirect(url_for('login'))
                    
                except ValueError as e:
                    flash('Invalid email recovery password. Please check and try again.', 'error')
                    log_audit('email_recovery_failed', 'recovery', 
                             details={'user': username, 'error': 'invalid_password'})
                except Exception as e:
                    logger.error(f"E-DEK recovery failed for user {username}: {str(e)}")
                    flash('Recovery failed. Please try again or contact support.', 'error')
                    log_audit('email_recovery_error', 'recovery', 
                             details={'user': username, 'error': str(e)})
            
            return render_template('email_recovery.html', username=username)
        
        return render_template('email_recovery.html', username=username)
    
    except Exception as e:
        logger.error(f"Email recovery error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('recovery'))@app.route('/reset_password_form', methods=['GET', 'POST'])
def reset_password_form():
    """Reset password form after successful recovery verification"""
    if 'recovery_user_id' not in session:
        flash('Please complete the recovery process first.', 'error')
        return redirect(url_for('recovery'))
    
    if request.method == 'POST':
        new_password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not new_password or not confirm_password:
            flash('Please fill in all fields.', 'error')
            return render_template('reset_password_form.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password_form.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password_form.html')
        
        try:
            user = User.objects(id=session['recovery_user_id']).first()
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('recovery'))
            
            # Update password
            user.password_hash = generate_password_hash(new_password)
            user.save()
            
            # Update password-encrypted key if it exists
            try:
                user_keys = UserKeys.objects(user=user).first()
                if user_keys:
                    # Re-encrypt DEK with new password
                    dek = crypto_manager.derive_key_from_user_id(str(user.id))
                    password_key, password_salt = crypto_manager.derive_key_from_password(new_password)
                    password_encrypted = crypto_manager.encrypt_data(
                        base64.urlsafe_b64encode(dek).decode(), password_key
                    )
                    
                    user_keys.password_encrypted_key = json.dumps({
                        'encrypted': password_encrypted,
                        'salt': base64.urlsafe_b64encode(password_salt).decode()
                    })
                    user_keys.save()
                    
            except Exception as e:
                logger.error(f"Failed to update password key: {str(e)}")
            
            # Clear recovery session
            session.pop('recovery_user_id', None)
            session.pop('recovery_method', None)
            
            log_audit('password_reset_recovery', 'user', user.id, 
                     details={'method': session.get('recovery_method', 'unknown')})
            
            flash('Password reset successful! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            flash('Failed to reset password. Please try again.', 'error')
            return render_template('reset_password_form.html')
    
    return render_template('reset_password_form.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using email token"""
    # Verify token (simplified - in production use database)
    token_data = None
    for key in session.keys():
        if key.startswith('recovery_token_') and session[key].get('token') == token:
            token_data = session[key]
            break
    
    if not token_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('recovery'))
    
    # Check if token expired
    try:
        expires = datetime.fromisoformat(token_data['expires'])
        if datetime.utcnow() > expires:
            flash('Reset link has expired.', 'error')
            return redirect(url_for('recovery'))
    except:
        flash('Invalid reset link.', 'error')
        return redirect(url_for('recovery'))
    
    if request.method == 'POST':
        new_password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not new_password or not confirm_password:
            flash('Please fill in all fields.', 'error')
            return render_template('reset_password.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password.html')
        
        try:
            user = User.objects(id=token_data['user_id']).first()
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('recovery'))
            
            # Update password
            user.password_hash = generate_password_hash(new_password)
            user.save()
            
            # Clear the token
            for key in list(session.keys()):
                if key.startswith('recovery_token_') and session[key].get('token') == token:
                    session.pop(key)
            
            log_audit('password_reset', 'user', user.id)
            
            flash('Password reset successful! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            flash('Failed to reset password. Please try again.', 'error')
            return render_template('reset_password.html')
    
    return render_template('reset_password.html')

# ✅ NEW: Q-DEK Password Recovery System
@app.route('/recover-password-questions', methods=['GET', 'POST'])
def recover_password_with_questions():
    """Recover password using security questions (Q-DEK system)"""
    if request.method == 'POST':
        # Check if we're getting username only (step 1) or full form (step 2)
        username = request.form.get('username', '').strip()
        
        # Step 1: Just username provided, fetch and show security questions
        if username and not request.form.get('answer1'):
            try:
                user = User.objects(username=username).first()
                if not user:
                    flash('User not found!', 'error')
                    return render_template('security_questions_recovery.html')
                
                if not user.security_questions or len(user.security_questions) != 3:
                    flash('This user does not have security questions set up!', 'error')
                    return render_template('security_questions_recovery.html')
                
                # Pass the user's actual security questions to the template
                questions = [sq.question for sq in user.security_questions]
                return render_template('security_questions_recovery.html', 
                                     username=username, 
                                     questions=questions,
                                     show_questions=True)
                
            except Exception as e:
                logger.error(f"Error fetching security questions: {str(e)}")
                flash('Error loading security questions. Please try again.', 'error')
                return render_template('security_questions_recovery.html')
        
        # Step 2: Full form with answers
        answer1 = request.form.get('answer1', '').strip()
        answer2 = request.form.get('answer2', '').strip()
        answer3 = request.form.get('answer3', '').strip()
        
        if not all([username, answer1, answer2, answer3]):
            flash('All fields are required!', 'error')
            # If we have username, reload with questions
            if username:
                user = User.objects(username=username).first()
                if user and user.security_questions:
                    questions = [sq.question for sq in user.security_questions]
                    return render_template('security_questions_recovery.html', 
                                         username=username, 
                                         questions=questions,
                                         show_questions=True)
            return render_template('security_questions_recovery.html')
        
        try:
            # Find the user
            user = User.objects(username=username).first()
            if not user:
                flash('User not found!', 'error')
                return render_template('security_questions_recovery.html')
            
            # Get user's encryption keys
            user_keys = crypto_manager.get_user_keys(str(user.id))
            if not user_keys:
                flash('No recovery keys found for this user!', 'error')
                questions = [sq.question for sq in user.security_questions]
                return render_template('security_questions_recovery.html', 
                                     username=username, 
                                     questions=questions,
                                     show_questions=True)
            
            # Try to recover DEK using security question answers (Q-DEK)
            answers = [answer1, answer2, answer3]
            try:
                recovered_dek = crypto_manager.recover_dek_with_security_questions(user_keys, answers)
                print(f"✅ DEK recovered successfully using Q-DEK for user {username}")
                
                # Store the recovered DEK and user info in session for password reset
                session['password_recovery'] = {
                    'user_id': str(user.id),
                    'username': username,
                    'dek': recovered_dek.hex(),
                    'method': 'security_questions',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                flash('Security questions verified successfully! You can now set a new password.', 'success')
                return redirect(url_for('set_new_password_from_recovery'))
                
            except Exception as e:
                print(f"❌ Q-DEK recovery failed for user {username}: {str(e)}")
                flash('Incorrect answers to security questions!', 'error')
                log_audit('password_recovery_failed', 'auth', user.id, {'method': 'security_questions'})
                # Show questions again with error
                questions = [sq.question for sq in user.security_questions]
                return render_template('security_questions_recovery.html', 
                                     username=username, 
                                     questions=questions,
                                     show_questions=True)
        
        except Exception as e:
            logger.error(f"Password recovery error: {str(e)}")
            flash('Recovery failed. Please try again.', 'error')
    
    return render_template('security_questions_recovery.html')

@app.route('/recover-password-phrase', methods=['GET', 'POST'])
@app.route('/recover-password-phrase/<username>', methods=['GET', 'POST'])
def recover_password_with_phrase(username=None):
    """Recover password using recovery phrase (R-DEK system)"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        recovery_phrase = request.form.get('recovery_phrase', '').strip()
        
        if not all([username, recovery_phrase]):
            flash('All fields are required!', 'error')
            return render_template('recovery_phrase.html', username=username)
        
        try:
            # Find the user
            user = User.objects(username=username).first()
            if not user:
                flash('User not found!', 'error')
                return render_template('recovery_phrase.html', username=username)
            
            # Check if user has recovery phrase set up
            if not user.recovery_phrase:
                flash('Recovery phrase not set up for this user.', 'error')
                return render_template('recovery_phrase.html', username=username)
            
            # Get user's encryption keys
            user_keys = crypto_manager.get_user_keys(str(user.id))
            if not user_keys:
                flash('No recovery keys found for this user!', 'error')
                return render_template('recovery_phrase.html')
            
            # Try to recover DEK using recovery phrase (R-DEK)
            try:
                recovered_dek = crypto_manager.recover_dek_with_recovery_phrase(user_keys, recovery_phrase)
                print(f"✅ DEK recovered successfully using R-DEK for user {username}")
                
                # Store the recovered DEK and user info in session for password reset
                session['password_recovery'] = {
                    'user_id': str(user.id),
                    'username': username,
                    'dek': recovered_dek.hex(),
                    'method': 'recovery_phrase',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                flash('Recovery phrase verified successfully! You can now set a new password.', 'success')
                return redirect(url_for('set_new_password_from_recovery'))
                
            except Exception as e:
                print(f"❌ R-DEK recovery failed for user {username}: {str(e)}")
                flash('Incorrect recovery phrase!', 'error')
                log_audit('password_recovery_failed', 'auth', user.id, {'method': 'recovery_phrase'})
        
        except Exception as e:
            logger.error(f"Password recovery error: {str(e)}")
            flash('Recovery failed. Please try again.', 'error')
    
    return render_template('recovery_phrase.html', username=username)

@app.route('/set-new-password-from-recovery', methods=['GET', 'POST'])
def set_new_password_from_recovery():
    """Set new password after successful Q-DEK or R-DEK recovery"""
    
    # Check if user has valid recovery session
    if 'password_recovery' not in session:
        flash('Invalid recovery session. Please start recovery process again.', 'error')
        return redirect(url_for('recover_password_with_questions'))
    
    recovery_data = session['password_recovery']
    
    # Check if recovery session is still valid (30 minutes timeout)
    from datetime import datetime, timedelta
    recovery_time = datetime.fromisoformat(recovery_data['timestamp'])
    if datetime.utcnow() - recovery_time > timedelta(minutes=30):
        session.pop('password_recovery', None)
        flash('Recovery session expired. Please start recovery process again.', 'error')
        return redirect(url_for('recover_password_with_questions'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not new_password or len(new_password) < 8:
            flash('Password must be at least 8 characters long!', 'error')
            return render_template('reset_password_form.html', recovery_data=recovery_data)
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password_form.html', recovery_data=recovery_data)
        
        try:
            # Get the user
            user = User.objects(id=recovery_data['user_id']).first()
            if not user:
                flash('User not found!', 'error')
                session.pop('password_recovery', None)
                return redirect(url_for('login'))
            
            # Get the recovered DEK from session
            recovered_dek = bytes.fromhex(recovery_data['dek'])
            
            # ✅ CORE IMPLEMENTATION: Create new P-DEK with new password
            # Encrypt the recovered DEK with the new password to create new P-DEK
            new_password_key, new_password_salt = crypto_manager.derive_key_from_password(new_password)
            new_password_encrypted = crypto_manager.encrypt_data(
                base64.urlsafe_b64encode(recovered_dek).decode(), 
                new_password_key
            )
            
            # Update user's password hash
            user.password_hash = generate_password_hash(new_password)
            user.save()
            
            # Update user's P-DEK with new password
            user_keys = crypto_manager.get_user_keys(str(user.id))
            if user_keys:
                user_keys.password_encrypted_key = json.dumps({
                    'encrypted': new_password_encrypted,
                    'salt': base64.urlsafe_b64encode(new_password_salt).decode()
                })
                user_keys.save()
                print(f"✅ P-DEK updated with new password for user {user.username}")
            
            # Log the successful recovery
            log_audit('password_reset_success', 'auth', user.id, {
                'method': recovery_data['method'],
                'new_password_set': True
            })
            
            # Clear recovery session
            session.pop('password_recovery', None)
            
            flash('Password reset successful! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Password reset completion error: {str(e)}")
            flash('Failed to complete password reset. Please try again.', 'error')
    
    return render_template('reset_password_form.html', recovery_data=recovery_data)

# =====================================================================================
# TOKEN-BASED KEY ROTATION ROUTES
# =====================================================================================

@app.route('/api/request_key_rotation', methods=['POST'])
@login_required
def request_key_rotation():
    """User requests key rotation"""
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        reason = data.get('reason', 'User requested rotation')
        description = data.get('description', '')
        
        # Validate reason
        if not reason or reason.strip() == '':
            return jsonify({'error': 'Reason is required'}), 400
        
        # Allow multiple requests - no longer checking for existing pending requests
        # Users can submit additional requests if needed
        
        # Create rotation request (token will be MongoDB _id)
        rotation_token = RotationToken(
            user_id=str(current_user.id),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            status='pending',
            request_reason=reason
        )
        
        # Add description if provided
        if description:
            rotation_token.description = description
        
        rotation_token.save()
        
        log_audit('request_rotation', 'key_rotation', current_user.id, 
                 f'Rotation requested: {reason}')
        
        return jsonify({
            'success': True,
            'token': str(rotation_token.id),  # Use MongoDB _id as token
            'message': 'Rotation request submitted. Awaiting admin approval.',
            'request_id': str(rotation_token.id)
        })
        
    except Exception as e:
        logger.error(f"Key rotation request error: {str(e)}")
        return jsonify({'error': f'Failed to submit rotation request: {str(e)}'}), 500

@app.route('/api/rotate_keys_with_token', methods=['POST'])
@login_required
def rotate_keys_with_token():
    """User performs key rotation with approved token"""
    from crypto_utils import atomic_rotation
    from models import UserKeys
    
    try:
        data = request.get_json()
        token = data.get('token')
        temp_password = data.get('temporary_password')
        current_password = data.get('current_password')  # Required for decryption
        new_password = data.get('new_password', current_password)
        
        # Conditional recovery method fields
        security_answers = data.get('security_answers')
        recovery_phrase = data.get('recovery_phrase')
        email_password = data.get('email_password')
        
        # Basic required fields
        if not all([token, temp_password, current_password]):
            return jsonify({'error': 'Token, temporary password, and current password are required'}), 400
        
        # Validate current password
        if not check_password_hash(current_user.password_hash, current_password):
            return jsonify({'error': 'Invalid current password'}), 401
        
        # Get user's configured recovery methods to validate required fields
        user_keys = UserKeys.objects(user=current_user).first()
        if not user_keys:
            return jsonify({'error': 'User keys not found'}), 404
        
        # Validate required recovery method fields based on user's setup
        validation_errors = []
        
        if user_keys.security_questions_encrypted_key and not security_answers:
            validation_errors.append('Security question answers are required')
        elif security_answers and len(security_answers) != 3:
            validation_errors.append('All 3 security question answers must be provided')
        
        if user_keys.recovery_phrase_encrypted_key and not recovery_phrase:
            validation_errors.append('Recovery phrase is required')
        elif recovery_phrase:
            # Validate recovery phrase format
            words = recovery_phrase.strip().split()
            if len(words) != 12:
                validation_errors.append('Recovery phrase must contain exactly 12 words')
        
        if user_keys.email_encrypted_key and not email_password:
            validation_errors.append('Email recovery password is required')
        
        if validation_errors:
            return jsonify({'error': '; '.join(validation_errors)}), 400
        
        # Perform atomic rotation with conditional parameters
        result = atomic_rotation.start_rotation_with_token(
            str(current_user.id), token, temp_password,
            current_password, new_password, security_answers, recovery_phrase, email_password
        )
        
        # Update user password if changed
        if new_password != current_password:
            current_user.password_hash = generate_password_hash(new_password)
            current_user.save()
            
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Key rotation with token error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/rotation_request')
@login_required
@password_change_required
def rotation_request():
    """Key rotation request page"""
    from models import RotationToken
    
    # Check for existing pending requests (show most recent)
    existing_request = RotationToken.objects(
        user_id=str(current_user.id),
        status__in=['pending', 'approved'],
        expires_at__gt=datetime.utcnow()
    ).order_by('-created_at').first()
    
    return render_template('rotation_request.html', 
                         existing_request=existing_request,
                         user=current_user)

@app.route('/key_rotation_with_token')
@login_required
@password_change_required
def key_rotation_with_token():
    """Key rotation execution page"""
    token = request.args.get('token')
    if not token:
        flash('Invalid rotation link', 'error')
        return redirect(url_for('rotation_request'))
        
    return render_template('key_rotation_with_token.html', token=token)
