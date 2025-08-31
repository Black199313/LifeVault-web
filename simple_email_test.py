from email_utils import email_service
from app import app
import logging

# Set up logging to see what's happening
logging.basicConfig(level=logging.INFO)

class TestUser:
    def __init__(self, email):
        self.username = 'TestUser'
        self.recovery_email = email

def test_email():
    with app.app_context():
        print("Email Configuration:")
        print(f"MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
        print(f"MAIL_PORT: {app.config.get('MAIL_PORT')}")
        print(f"MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
        print(f"MAIL_PASSWORD: {'Set' if app.config.get('MAIL_PASSWORD') else 'Not set'}")
        print(f"MAIL_DEFAULT_SENDER: {app.config.get('MAIL_DEFAULT_SENDER')}")
        print(f"MAIL_USE_TLS: {app.config.get('MAIL_USE_TLS')}")
        print()
        
        # Test with sachinprabhu.devops@gmail.com
        user = TestUser('sachinprabhu.devops@gmail.com')
        
        print(f"Testing email to: {user.recovery_email}")
        
        try:
            result = email_service.send_recovery_code_email(user, 'TEST12345')
            print(f"Email send result: {result}")
            if result:
                print("✅ Email sent successfully!")
            else:
                print("❌ Email sending failed")
        except Exception as e:
            print(f"❌ Error sending email: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    test_email()
