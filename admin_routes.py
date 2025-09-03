"""
Admin routes for LifeVault Secret Manager
Provides admin dashboard, user management, and audit functionality.
"""

import base64
import json
import secrets
from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from models import User, UserKeys, Secret, AuditLog
from utils import admin_required, log_audit
from crypto_utils import crypto_manager
from auth import generate_secure_token
from admin_escrow import admin_escrow
import logging

logger = logging.getLogger(__name__)

def register_admin_routes(app):
    """Register all admin routes with the Flask app"""
    
    @app.route('/admin')
    @app.route('/admin/dashboard')
    @admin_required
    def admin_dashboard():
        """Admin dashboard with system overview"""
        try:
            # Get system statistics
            total_users = User.objects.count()
            active_users = User.objects(is_active=True).count()
            admin_users = User.objects(is_admin=True).count()
            total_secrets = Secret.objects.count()
            
            # Get recent audit logs (last 10)
            recent_logs = AuditLog.objects.order_by('-timestamp').limit(10)
            
            # Get user registration trend (last 30 days)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_registrations = User.objects(created_at__gte=thirty_days_ago).count()
            
            return render_template('admin_dashboard.html',
                                 total_users=total_users,
                                 active_users=active_users,
                                 admin_users=admin_users,
                                 total_secrets=total_secrets,
                                 recent_logs=recent_logs,
                                 recent_registrations=recent_registrations)
                                 
        except Exception as e:
            logger.error(f"Admin dashboard error: {str(e)}")
            flash('Error loading admin dashboard.', 'error')
            return redirect(url_for('index'))
    
    @app.route('/admin/users')
    @admin_required 
    def admin_users():
        """User management page"""
        try:
            users = User.objects.order_by('-created_at')
            return render_template('admin_users.html', users=users)
        except Exception as e:
            logger.error(f"Admin users page error: {str(e)}")
            flash('Error loading users.', 'error')
            return redirect(url_for('admin_dashboard'))
    
    @app.route('/admin/users/create', methods=['GET', 'POST'])
    @admin_required
    def admin_create_user():
        """Create new user account (including admin accounts)"""
        if request.method == 'POST':
            try:
                username = request.form.get('username', '').strip()
                email = request.form.get('email', '').strip()
                password = request.form.get('password', '').strip()
                confirm_password = request.form.get('confirm_password', '').strip()
                is_admin = request.form.get('is_admin') == 'on'
                send_welcome_email = request.form.get('send_welcome_email') == 'on'
                
                # Validation
                if not all([username, email, password, confirm_password]):
                    flash('All fields are required!', 'error')
                    return render_template('admin_create_user.html')
                
                if password != confirm_password:
                    flash('Passwords do not match!', 'error')
                    return render_template('admin_create_user.html')
                
                if len(password) < 8:
                    flash('Password must be at least 8 characters long!', 'error')
                    return render_template('admin_create_user.html')
                
                # Check if user already exists
                if User.objects(username=username).first():
                    flash('Username already exists!', 'error')
                    return render_template('admin_create_user.html')
                
                if User.objects(email=email).first():
                    flash('Email already registered!', 'error')
                    return render_template('admin_create_user.html')
                
                # Create user using admin escrow system
                user, temp_password = admin_escrow.create_user_with_admin_escrow(
                    username=username,
                    email=email,
                    temp_password=password,  # Admin-chosen password
                    is_admin=is_admin
                )
                
                log_audit('admin_create_user', 'user', user.id, {
                    'created_username': username,
                    'is_admin': is_admin,
                    'created_by': current_user.username
                })
                
                user_type = 'admin user' if is_admin else 'user'
                flash(f'Successfully created {user_type}: {username}', 'success')
                
                # TODO: Send welcome email if requested
                if send_welcome_email:
                    flash('Welcome email sending not implemented yet.', 'info')
                    
                return redirect(url_for('admin_users'))
                
            except Exception as e:
                logger.error(f"Admin create user error: {str(e)}")
                flash('Failed to create user. Please try again.', 'error')
                return render_template('admin_create_user.html')
        
        return render_template('admin_create_user.html')
    
    @app.route('/admin/users/<user_id>/reset_password', methods=['POST'])
    @admin_required
    def admin_reset_user_password(user_id):
        """Reset a user's password (admin function)"""
        try:
            new_password = request.form.get('new_password', '').strip()
            admin_password = request.form.get('admin_password', '').strip()
            
            if not new_password:
                flash('New password is required!', 'error')
                return redirect(url_for('admin_users'))
            
            if not admin_password:
                flash('Admin password is required for security verification!', 'error')
                return redirect(url_for('admin_users'))
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long!', 'error')
                return redirect(url_for('admin_users'))
            
            # Verify admin password
            from werkzeug.security import check_password_hash
            if not check_password_hash(current_user.password_hash, admin_password):
                flash('Invalid admin password!', 'error')
                return redirect(url_for('admin_users'))
            
            # Find user
            user = User.objects(id=user_id).first()
            if not user:
                flash('User not found!', 'error')
                return redirect(url_for('admin_users'))
            
            # Use admin escrow system for password reset with admin password
            success = admin_escrow.admin_password_reset_with_escrow(user_id, new_password, admin_password)
            
            if success:
                log_audit('admin_password_reset', 'user', user.id, {
                    'target_username': user.username,
                    'reset_by': current_user.username
                })
                
                flash(f'Password reset successfully for user: {user.username}', 'success')
            else:
                flash('Failed to reset password. Please try again.', 'error')
            
        except Exception as e:
            logger.error(f"Admin password reset error: {str(e)}")
            flash('Failed to reset password. Please try again.', 'error')
        
        return redirect(url_for('admin_users'))
    
    @app.route('/admin/users/<user_id>/toggle_status', methods=['POST'])
    @admin_required
    def admin_toggle_user_status(user_id):
        """Activate or deactivate a user account"""
        try:
            user = User.objects(id=user_id).first()
            if not user:
                return jsonify({'success': False, 'message': 'User not found'})
            
            # Prevent admins from deactivating themselves
            if user.id == current_user.id:
                return jsonify({'success': False, 'message': 'Cannot deactivate your own account'})
            
            user.is_active = not user.is_active
            user.save()
            
            action = 'activated' if user.is_active else 'deactivated'
            log_audit(f'admin_user_{action}', 'user', user.id, {
                'target_username': user.username,
                'action_by': current_user.username
            })
            
            return jsonify({
                'success': True, 
                'message': f'User {action} successfully',
                'new_status': user.is_active
            })
            
        except Exception as e:
            logger.error(f"Admin toggle user status error: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to update user status'})
    
    @app.route('/admin/users/<user_id>/make_admin', methods=['POST'])
    @admin_required
    def admin_make_user_admin(user_id):
        """Grant or revoke admin privileges for a user"""
        try:
            user = User.objects(id=user_id).first()
            if not user:
                return jsonify({'success': False, 'message': 'User not found'})
            
            # Prevent admins from removing their own admin status
            if user.id == current_user.id and user.is_admin:
                return jsonify({'success': False, 'message': 'Cannot remove your own admin privileges'})
            
            user.is_admin = not user.is_admin
            user.save()
            
            action = 'granted admin privileges to' if user.is_admin else 'revoked admin privileges from'
            log_audit('admin_privilege_change', 'user', user.id, {
                'target_username': user.username,
                'granted_admin': user.is_admin,
                'action_by': current_user.username
            })
            
            return jsonify({
                'success': True,
                'message': f'Successfully {action} user: {user.username}',
                'is_admin': user.is_admin
            })
            
        except Exception as e:
            logger.error(f"Admin privilege change error: {str(e)}")
            return jsonify({'success': False, 'message': 'Failed to change admin privileges'})
    
    @app.route('/admin/audit')
    @admin_required
    def admin_audit():
        """Audit logs viewer"""
        try:
            # Get filter parameters
            page = request.args.get('page', 1, type=int)
            action_filter = request.args.get('action', '')
            user_filter = request.args.get('user', '')
            date_from = request.args.get('date_from', '')
            date_to = request.args.get('date_to', '')
            
            # Build query
            query = {}
            if action_filter:
                query['action'] = action_filter
            if user_filter:
                users = User.objects(username__icontains=user_filter)
                if users:
                    query['user__in'] = [user for user in users]
            if date_from:
                try:
                    from_date = datetime.strptime(date_from, '%Y-%m-%d')
                    query['timestamp__gte'] = from_date
                except ValueError:
                    pass
            if date_to:
                try:
                    to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                    query['timestamp__lt'] = to_date
                except ValueError:
                    pass
            
            # Get paginated logs (manual pagination for MongoEngine)
            per_page = 50
            skip = (page - 1) * per_page
            
            # Get total count for pagination info
            total_logs = AuditLog.objects(**query).count()
            
            # Get the logs for current page
            logs = AuditLog.objects(**query).order_by('-timestamp').skip(skip).limit(per_page)
            
            # Calculate pagination info
            has_prev = page > 1
            has_next = skip + per_page < total_logs
            prev_num = page - 1 if has_prev else None
            next_num = page + 1 if has_next else None
            total_pages = (total_logs + per_page - 1) // per_page  # Ceiling division
            
            # Create a pagination-like object for template compatibility
            class PaginationInfo:
                def __init__(self, items, page, per_page, total, has_prev, has_next, prev_num, next_num, pages):
                    self.items = items
                    self.page = page
                    self.per_page = per_page
                    self.total = total
                    self.has_prev = has_prev
                    self.has_next = has_next
                    self.prev_num = prev_num
                    self.next_num = next_num
                    self.pages = pages
                
                def iter_pages(self, left_edge=2, left_current=2, right_current=3, right_edge=2):
                    """Generate page numbers for pagination similar to Flask-SQLAlchemy"""
                    last = self.pages
                    for num in range(1, last + 1):
                        if num <= left_edge or \
                           (self.page - left_current - 1 < num < self.page + right_current) or \
                           num > last - right_edge:
                            yield num
                        elif num == left_edge + 1 or num == last - right_edge:
                            yield None
            
            logs_pagination = PaginationInfo(
                items=list(logs),
                page=page,
                per_page=per_page,
                total=total_logs,
                has_prev=has_prev,
                has_next=has_next,
                prev_num=prev_num,
                next_num=next_num,
                pages=total_pages
            )
            
            return render_template('admin_audit.html', logs=logs_pagination)
            
        except Exception as e:
            logger.error(f"Admin audit page error: {str(e)}")
            flash('Error loading audit logs.', 'error')
            return redirect(url_for('admin_dashboard'))

    # =====================================================================================
    # TOKEN-BASED KEY ROTATION ADMIN ROUTES
    # =====================================================================================

    @app.route('/admin/api/rotation_requests', methods=['GET'])
    @admin_required
    def get_rotation_requests():
        """Get pending rotation requests"""
        from models import RotationToken
        
        try:
            pending_tokens = RotationToken.objects(
                status='pending', 
                expires_at__gt=datetime.utcnow()
            ).order_by('-created_at')
            
            requests = []
            for token in pending_tokens:
                user = User.objects(id=token.user_id).first()
                requests.append({
                    'token_id': str(token.id),
                    'user_id': token.user_id,
                    'user_email': user.email if user else 'Unknown',
                    'user_username': user.username if user else 'Unknown',
                    'reason': token.request_reason,
                    'requested_at': token.created_at.isoformat(),
                    'expires_at': token.expires_at.isoformat()
                })
            
            return jsonify({'requests': requests})
            
        except Exception as e:
            logger.error(f"Get rotation requests error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/api/rotation_request_stats', methods=['GET'])
    @admin_required
    def get_rotation_request_stats():
        """Get statistics about all rotation requests"""
        from models import RotationToken
        
        try:
            total_requests = RotationToken.objects.count()
            pending_count = RotationToken.objects(status='pending').count()
            approved_count = RotationToken.objects(status='approved').count()
            completed_count = RotationToken.objects(status='completed').count()
            finalized_count = RotationToken.objects(status='finalized').count()
            other_count = total_requests - (pending_count + approved_count + completed_count + finalized_count)
            
            return jsonify({
                'success': True,
                'total_requests': total_requests,
                'pending': pending_count,
                'approved': approved_count,
                'completed': completed_count,
                'finalized': finalized_count,
                'other': other_count
            })
            
        except Exception as e:
            logger.error(f"Get rotation request stats error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/api/approve_rotation/<token_id>', methods=['POST'])
    @admin_required
    def approve_rotation_request(token_id):
        """Admin approves rotation and generates temporary password"""
        from models import RotationToken
        import hashlib
        
        try:
            token = RotationToken.objects(id=token_id).first()
            if not token:
                return jsonify({'error': 'Token not found'}), 404
                
            if token.status != 'pending':
                return jsonify({'error': 'Token already processed'}), 400
                
            # Generate temporary password with user-friendly characters
            from utils import generate_user_friendly_password
            temp_password = generate_user_friendly_password(16)
            temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
            
            # Update token
            token.temporary_password_hash = temp_hash
            token.admin_id = str(current_user.id)
            token.approved_by_admin = current_user
            token.approved_at = datetime.utcnow()
            token.status = 'approved'
            token.save()
            
            # Log approval
            log_audit('approve_rotation', 'admin_action', current_user.id, 
                     f'Approved rotation for user: {token.user_id}')
            
            return jsonify({
                'success': True,
                'temporary_password': temp_password,
                'expires_at': token.expires_at.isoformat(),
                'message': f'Rotation approved. Temporary password generated.'
            })
            
        except Exception as e:
            logger.error(f"Approve rotation error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/api/get_token/<token_id>', methods=['GET'])
    @admin_required
    def get_rotation_token(token_id):
        """Get the actual token for admin to share with user"""
        try:
            from models import RotationToken

            token = RotationToken.objects(id=token_id).first()
            if not token:
                return jsonify({'error': 'Token not found'}), 404
                
            return jsonify({
                'success': True,
                'token': str(token.id)  # Use MongoDB _id as token
            })
            
        except Exception as e:
            return jsonify({'error': f'Failed to get token: {str(e)}'}), 500

    @app.route('/admin/api/finalize_a_dek/<token_id>', methods=['POST'])
    @admin_required  
    def finalize_a_dek(token_id):
        """Admin finalizes A-DEK with admin master key"""
        from models import RotationToken, UserKeys
        from werkzeug.security import check_password_hash
        import hashlib
        
        try:
            data = request.get_json()
            temp_password = data.get('temporary_password')
            admin_password = data.get('admin_password')
            
            if not all([temp_password, admin_password]):
                return jsonify({'error': 'Temporary password and admin password required'}), 400
            
            # Validate admin password
            if not check_password_hash(current_user.password_hash, admin_password):
                return jsonify({'error': 'Invalid admin password'}), 401
                
            token = RotationToken.objects(id=token_id).first()
            if not token or token.status != 'completed':
                return jsonify({'error': 'Invalid token or rotation not completed'}), 400
            
            # Validate temporary password hash
            temp_hash = hashlib.sha256(temp_password.encode()).hexdigest()
            if token.temporary_password_hash != temp_hash:
                return jsonify({'error': 'Invalid temporary password'}), 401
            
            # Get stored salt for temporary password decryption
            if not token.temporary_password_salt:
                return jsonify({'error': 'Temporary password salt not found in token'}), 400
                
            temp_salt = base64.urlsafe_b64decode(token.temporary_password_salt)
                
            # Get user and their new A-DEK
            user = User.objects(id=token.user_id).first()
            user_keys = UserKeys.objects(user=user).first()
            
            if not user_keys:
                return jsonify({'error': 'User keys not found'}), 404
            
            # Backup current A-DEK for rollback
            original_a_dek = user_keys.admin_master_encrypted_key
            
            try:
                # Decrypt DEK using temporary password with stored salt
                temp_key, _ = crypto_manager.derive_key_from_password(temp_password, temp_salt)
                
                # Handle both old format (string) and new format (JSON) for A-DEK
                a_dek_data = user_keys.admin_master_encrypted_key
                
                if isinstance(a_dek_data, str) and a_dek_data.startswith('{'):
                    # New JSON format
                    parsed_data = json.loads(a_dek_data)
                    encrypted_a_dek = parsed_data['encrypted']
                else:
                    # Old format (direct encrypted string) or temp A-DEK
                    encrypted_a_dek = a_dek_data
                
                user_dek_b64 = crypto_manager.decrypt_data(encrypted_a_dek, temp_key)
                user_dek = base64.urlsafe_b64decode(user_dek_b64)
                
            except Exception as e:
                logger.error(f"Failed to decrypt A-DEK with temp password: {e}")
                return jsonify({'error': 'Failed to decrypt A-DEK with temporary password. Verify temp password is correct.'}), 400
            
            try:
                # Re-encrypt with admin master key
                admin_master_key = crypto_manager.get_or_create_admin_master_key(
                    admin_password_hash=current_user.password_hash
                )
                new_a_dek_encrypted = crypto_manager.encrypt_data(
                    base64.urlsafe_b64encode(user_dek).decode(), 
                    admin_master_key
                )
                
                # Create complete A-DEK structure like other DEKs
                final_adek_data = {
                    'encrypted': new_a_dek_encrypted,
                    'version': 'v2'
                }
                
                # Verify the new A-DEK works before saving
                test_dek_b64 = crypto_manager.decrypt_data(final_adek_data['encrypted'], admin_master_key)
                test_dek = base64.urlsafe_b64decode(test_dek_b64)
                
                if test_dek != user_dek:
                    raise ValueError("A-DEK verification failed - decrypted DEK doesn't match original")
                    
            except Exception as e:
                logger.error(f"Failed to create new A-DEK with admin master key: {e}")
                return jsonify({'error': 'Failed to re-encrypt A-DEK with admin master key'}), 500
            
            try:
                # Update user keys with verified A-DEK (complete JSON structure)
                user_keys.admin_master_encrypted_key = json.dumps(final_adek_data)
                user_keys.save()
                
                # Mark token as finalized
                token.status = 'finalized'
                token.a_dek_finalized = True
                token.save()
                
                log_audit('finalize_a_dek', 'admin_action', current_user.id,
                         f'Finalized A-DEK for user: {token.user_id}')
                
                return jsonify({
                    'success': True, 
                    'message': 'A-DEK finalized with admin master key'
                })
                
            except Exception as e:
                # Rollback on save failure
                try:
                    user_keys.admin_master_encrypted_key = original_a_dek
                    user_keys.save()
                    logger.error(f"A-DEK finalization failed, rolled back: {e}")
                except:
                    logger.error(f"A-DEK finalization failed and rollback failed: {e}")
                
                return jsonify({'error': 'Failed to save finalized A-DEK'}), 500
            
        except Exception as e:
            logger.error(f"Finalize A-DEK error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/key_rotation_management')
    @admin_required
    def key_rotation_management():
        """Key rotation management page"""
        return render_template('admin_key_rotation.html')

    @app.route('/admin/api/delete_all_rotation_requests', methods=['POST'])
    @admin_required
    def delete_all_rotation_requests():
        """Delete all rotation requests for all users (dangerous operation)"""
        from models import RotationToken
        from werkzeug.security import check_password_hash
        
        try:
            data = request.get_json()
            admin_password = data.get('admin_password')
            
            if not admin_password:
                return jsonify({'error': 'Admin password is required'}), 400
            
            # Verify admin password
            if not check_password_hash(current_user.password_hash, admin_password):
                return jsonify({'error': 'Invalid admin password'}), 401
            
            # Count total requests before deletion for reporting
            total_requests = RotationToken.objects.count()
            
            if total_requests == 0:
                return jsonify({
                    'success': True,
                    'deleted_count': 0,
                    'message': 'No rotation requests found to delete'
                })
            
            # Delete ALL rotation requests regardless of status
            RotationToken.objects.delete()
            
            # Log this dangerous action
            log_audit('admin_delete_all_rotation_requests', 'admin_action', current_user.id, {
                'deleted_count': total_requests,
                'admin_username': current_user.username,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            logger.warning(f"Admin {current_user.username} deleted ALL {total_requests} rotation requests")
            
            return jsonify({
                'success': True,
                'deleted_count': total_requests,
                'message': f'Successfully deleted {total_requests} rotation requests'
            })
            
        except Exception as e:
            logger.error(f"Delete all rotation requests error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/export_all_data')
    @admin_required
    def admin_export_all_data():
        """Export all users' data for admin backup purposes"""
        try:
            # Create comprehensive backup data structure
            backup_data = {
                'backup_info': {
                    'admin_username': current_user.username,
                    'backup_date': datetime.utcnow().isoformat(),
                    'backup_version': '1.0',
                    'backup_type': 'complete_system_backup',
                    'total_users': 0,
                    'total_secrets': 0,
                    'total_journal_entries': 0,
                    'encryption_note': 'User secrets remain encrypted with their individual keys'
                },
                'users': []
            }
            
            # Get all users
            all_users = User.objects()
            
            for user in all_users:
                # Get user keys for this user
                user_keys = UserKeys.objects(user=user).first()
                
                user_data = {
                    'user_info': {
                        'id': str(user.id),
                        'username': user.username,
                        'email': user.email,
                        'email_verified': user.email_verified,
                        'is_admin': user.is_admin,
                        'is_active': user.is_active,
                        'created_at': user.created_at.isoformat() if user.created_at else None,
                        'last_login': user.last_login.isoformat() if user.last_login else None,
                        'password_changed_at': user.password_changed_at.isoformat() if user.password_changed_at else None,
                        'failed_attempts': getattr(user, 'failed_attempts', 0),
                        'locked_until': user.locked_until.isoformat() if getattr(user, 'locked_until', None) else None
                    },
                    'security_setup': {
                        'has_security_questions': bool(user.security_questions),
                        'security_questions_count': len(user.security_questions) if user.security_questions else 0,
                        'has_recovery_phrase': bool(user.recovery_phrase),
                        'has_encryption_keys': bool(user_keys),
                        'key_version': user_keys.key_version if user_keys else None,
                        'keys_created_at': user_keys.created_at.isoformat() if user_keys and user_keys.created_at else None
                    },
                    'secrets': [],
                    'journal_entries': [],
                    'audit_logs': []
                }
                
                # Export user's secrets (keep encrypted for security)
                user_secrets = Secret.objects(user=user)
                for secret in user_secrets:
                    user_data['secrets'].append({
                        'id': str(secret.id),
                        'title': secret.title,
                        'encrypted_data': secret.encrypted_data,  # Keep encrypted
                        'notes': secret.notes,
                        'created_at': secret.created_at.isoformat() if secret.created_at else None,
                        'updated_at': secret.updated_at.isoformat() if secret.updated_at else None,
                        'needs_migration': getattr(secret, 'needs_migration', False)
                    })
                
                # Export user's journal entries
                from models import JournalEntry
                user_journal_entries = JournalEntry.objects(user=user)
                for entry in user_journal_entries:
                    user_data['journal_entries'].append({
                        'id': str(entry.id),
                        'entry_date': entry.entry_date.isoformat(),
                        'content': entry.content,
                        'mood': entry.mood,
                        'tags': entry.tags,
                        'created_at': entry.created_at.isoformat() if entry.created_at else None,
                        'updated_at': entry.updated_at.isoformat() if entry.updated_at else None
                    })
                
                # Export recent audit logs for this user (last 100 entries)
                user_audit_logs = AuditLog.objects(user=user).order_by('-timestamp').limit(100)
                for log in user_audit_logs:
                    user_data['audit_logs'].append({
                        'id': str(log.id),
                        'action': log.action,
                        'resource_type': log.resource_type,
                        'resource_id': log.resource_id,
                        'details': log.details,
                        'ip_address': log.ip_address,
                        'user_agent': log.user_agent,
                        'timestamp': log.timestamp.isoformat()
                    })
                
                # Add user data to backup
                backup_data['users'].append(user_data)
                
                # Update totals
                backup_data['backup_info']['total_secrets'] += len(user_data['secrets'])
                backup_data['backup_info']['total_journal_entries'] += len(user_data['journal_entries'])
            
            # Update total users count
            backup_data['backup_info']['total_users'] = len(backup_data['users'])
            
            # Add system-wide audit logs (last 500 entries)
            backup_data['system_audit_logs'] = []
            system_logs = AuditLog.objects().order_by('-timestamp').limit(500)
            for log in system_logs:
                backup_data['system_audit_logs'].append({
                    'id': str(log.id),
                    'action': log.action,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'user_id': str(log.user.id) if log.user else None,
                    'details': log.details,
                    'ip_address': log.ip_address,
                    'user_agent': log.user_agent,
                    'timestamp': log.timestamp.isoformat()
                })
            
            # Log this admin backup action
            log_audit('admin_full_backup', 'admin_action', current_user.id, {
                'total_users': backup_data['backup_info']['total_users'],
                'total_secrets': backup_data['backup_info']['total_secrets'],
                'total_journal_entries': backup_data['backup_info']['total_journal_entries']
            })
            
            # Create JSON response with proper headers for download
            import json
            from flask import Response
            
            json_data = json.dumps(backup_data, indent=2, ensure_ascii=False)
            
            # Create filename with timestamp
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"lifevault_admin_backup_{timestamp}.json"
            
            response = Response(
                json_data,
                mimetype='application/json',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}',
                    'Content-Type': 'application/json; charset=utf-8'
                }
            )
            
            flash(f'Complete system backup created successfully! ({backup_data["backup_info"]["total_users"]} users, {backup_data["backup_info"]["total_secrets"]} secrets, {backup_data["backup_info"]["total_journal_entries"]} journal entries)', 'success')
            return response
            
        except Exception as e:
            logger.error(f"Admin backup error: {str(e)}")
            flash('Failed to create system backup. Please try again.', 'error')
            return redirect(url_for('admin_dashboard'))
