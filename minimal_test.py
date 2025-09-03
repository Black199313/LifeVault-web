#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("1. Starting basic test...")

try:
    print("2. Importing app...")
    from app import app
    print("3. App imported successfully")
    
    print("4. Checking app context...")
    with app.app_context():
        print("5. App context created")
        
        print("6. Checking email config...")
        mail_server = app.config.get('MAIL_SERVER', 'Not set')
        print(f"7. MAIL_SERVER: {mail_server}")
        
        print("8. Test completed successfully!")
        
except Exception as e:
    print(f"❌ Error during test: {e}")
    import traceback
    traceback.print_exc()

print("9. Script finished")
