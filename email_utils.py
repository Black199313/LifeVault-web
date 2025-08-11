from flask import current_app, url_for, render_template_string
from flask_mail import Message
from app import mail
import logging

class EmailService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def send_email(self, to_email, subject, template, **kwargs):
        """Send email using Flask-Mail"""
        try:
            msg = Message(
                subject=subject,
                recipients=[to_email],
                html=template,
                sender=current_app.config['MAIL_DEFAULT_SENDER']
            )
            mail.send(msg)
            self.logger.info(f"Email sent successfully to {to_email}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    def send_verification_email(self, user, token):
        """Send email verification"""
        verification_url = url_for('verify_email', token=token, _external=True)
        
        template = """
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Verify Your Email Address</h2>
            <p>Hello {{ username }},</p>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{{ verification_url }}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create this account, you can safely ignore this email.</p>
        </div>
        """
        
        rendered_template = render_template_string(
            template, 
            username=user.username, 
            verification_url=verification_url
        )
        
        return self.send_email(
            user.email, 
            "Verify Your Email Address", 
            rendered_template
        )
    
    def send_password_reset_email(self, user, token):
        """Send password reset email"""
        reset_url = url_for('reset_password', token=token, _external=True)
        
        template = """
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Password Reset Request</h2>
            <p>Hello {{ username }},</p>
            <p>You requested to reset your password. Click the link below to set a new password:</p>
            <p><a href="{{ reset_url }}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this reset, you can safely ignore this email.</p>
        </div>
        """
        
        rendered_template = render_template_string(
            template, 
            username=user.username, 
            reset_url=reset_url
        )
        
        return self.send_email(
            user.email, 
            "Password Reset Request", 
            rendered_template
        )
    
    def send_recovery_code_email(self, user, code):
        """Send recovery code email"""
        template = """
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Account Recovery Code</h2>
            <p>Hello {{ username }},</p>
            <p>Your recovery code is:</p>
            <div style="background-color: #f8f9fa; padding: 20px; margin: 20px 0; text-align: center; font-size: 24px; font-weight: bold; border-radius: 5px;">
                {{ code }}
            </div>
            <p>This code will expire in 15 minutes.</p>
            <p>If you didn't request this code, please contact support immediately.</p>
        </div>
        """
        
        rendered_template = render_template_string(
            template, 
            username=user.username, 
            code=code
        )
        
        return self.send_email(
            user.email, 
            "Account Recovery Code", 
            rendered_template
        )

# Global instance
email_service = EmailService()
