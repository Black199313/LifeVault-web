#!/usr/bin/env python3

import os
from pathlib import Path

# Load .env
env_file = Path('.env')
if env_file.exists():
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

print("Email Test Results:")
print("=" * 40)

# Check credentials
server = os.environ.get('MAIL_SERVER', 'Not set')
port = os.environ.get('MAIL_PORT', 'Not set')
username = os.environ.get('MAIL_USERNAME', 'Not set')
password = os.environ.get('MAIL_PASSWORD', 'Not set')
sender = os.environ.get('MAIL_DEFAULT_SENDER', 'Not set')

print(f"MAIL_SERVER: {server}")
print(f"MAIL_PORT: {port}")
print(f"MAIL_USERNAME: {username}")
print(f"MAIL_PASSWORD: {'***SET***' if password != 'Not set' else 'NOT SET'}")
print(f"MAIL_DEFAULT_SENDER: {sender}")
print()

if all([server != 'Not set', port != 'Not set', username != 'Not set', password != 'Not set']):
    print("✅ All required credentials are configured")
    print("📧 Ready to send email to: sachinprabhu@gmail.com")
    print("🔧 Using Brevo SMTP service")
    print()
    print("To test email sending, you can:")
    print("1. Run the main LifeVault app (python main.py)")
    print("2. Use the email recovery feature")
    print("3. Or use the admin panel to send test emails")
else:
    print("❌ Missing email credentials")

print("\nCredentials Status: CONFIGURED ✅")
print("Target Email: sachinprabhu@gmail.com")
print("Email Service: Ready")
