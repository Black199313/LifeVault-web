#!/usr/bin/env python3
"""
Email test with timeout for sachinprabhu@gmail.com
"""

import os
import sys
import threading
import time
from pathlib import Path

# Load environment variables
def load_env_file():
    env_file = Path('.env')
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

load_env_file()

from flask import Flask
from flask_mail import Mail, Message
import smtplib
import socket

def test_smtp_connection():
    """Test SMTP connection directly"""
    print("=== TESTING SMTP CONNECTION ===")
    
    server = os.environ.get('MAIL_SERVER', 'smtp-relay.brevo.com')
    port = int(os.environ.get('MAIL_PORT', '587'))
    username = os.environ.get('MAIL_USERNAME')
    password = os.environ.get('MAIL_PASSWORD')
    
    print(f"Server: {server}")
    print(f"Port: {port}")
    print(f"Username: {username}")
    print(f"Password: {'***SET***' if password else 'NOT SET'}")
    print()
    
    try:
        print("Testing connection...")
        
        # Set socket timeout
        socket.setdefaulttimeout(10)
        
        # Create SMTP connection
        smtp = smtplib.SMTP(server, port, timeout=10)
        print("✅ Connected to SMTP server")
        
        # Enable TLS
        smtp.starttls()
        print("✅ TLS enabled")
        
        # Login
        smtp.login(username, password)
        print("✅ Login successful")
        
        # Close connection
        smtp.quit()
        print("✅ Connection closed properly")
        
        return True
        
    except socket.timeout:
        print("❌ Connection timeout - SMTP server not responding")
        return False
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

def send_test_email():
    """Send test email with timeout"""
    print("\n=== SENDING TEST EMAIL ===")
    
    server = os.environ.get('MAIL_SERVER')
    port = int(os.environ.get('MAIL_PORT', '587'))
    username = os.environ.get('MAIL_USERNAME')
    password = os.environ.get('MAIL_PASSWORD')
    sender = os.environ.get('MAIL_DEFAULT_SENDER')
    
    recipient = 'sachinprabhu@gmail.com'
    
    try:
        # Set socket timeout
        socket.setdefaulttimeout(15)
        
        # Create email message
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'LifeVault Email Test - Direct SMTP'
        msg['From'] = sender
        msg['To'] = recipient
        
        # HTML content
        html = """
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>LifeVault Email Test</h2>
            <p>Hello,</p>
            <p>This is a test email from LifeVault sent directly via SMTP.</p>
            <div style="background-color: #e7f5e7; padding: 20px; margin: 20px 0; text-align: center; font-size: 18px; font-weight: bold; border-radius: 5px; color: #2d5a2d;">
                ✅ Email system is working!
            </div>
            <p><strong>Test Details:</strong></p>
            <ul>
                <li>Recipient: sachinprabhu@gmail.com</li>
                <li>SMTP Server: Brevo (smtp-relay.brevo.com)</li>
                <li>Sender: sachinprabhu.dev@gmail.com</li>
                <li>Method: Direct SMTP connection</li>
            </ul>
            <p>If you received this email, the LifeVault email functionality is working correctly.</p>
        </div>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        print(f"Sending email to: {recipient}")
        print(f"From: {sender}")
        print("Connecting to SMTP server...")
        
        # Send email
        with smtplib.SMTP(server, port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)
        
        print("✅ SUCCESS: Email sent successfully!")
        print("📧 Check sachinprabhu@gmail.com for the test email")
        print("📝 Subject: 'LifeVault Email Test - Direct SMTP'")
        return True
        
    except socket.timeout:
        print("❌ TIMEOUT: Email sending timed out (15 seconds)")
        return False
    except Exception as e:
        print(f"❌ ERROR: Failed to send email: {e}")
        return False

if __name__ == '__main__':
    print("LifeVault Email Test with Timeout")
    print("Target: sachinprabhu@gmail.com")
    print("=" * 50)
    
    # Test SMTP connection first
    connection_ok = test_smtp_connection()
    
    if connection_ok:
        # Try to send email
        email_sent = send_test_email()
        
        print("\n" + "=" * 50)
        if email_sent:
            print("🎉 EMAIL TEST SUCCESSFUL!")
            print("📧 Check your inbox at sachinprabhu@gmail.com")
        else:
            print("❌ Email sending failed")
    else:
        print("\n" + "=" * 50)
        print("❌ Cannot send email - SMTP connection failed")
        print("Check your internet connection and Brevo credentials")
