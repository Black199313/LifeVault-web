# LifeVault Test Scripts

This folder contains all test scripts for the LifeVault application. Below is a description of each test script:

## API Testing Scripts
- `test_web_application_api.py` - Comprehensive API testing using HTTP requests to test existing features
- `test_key_rotation_complete.py` - Complete key rotation workflow testing
- `test_secrets_management.py` - Secrets CRUD operations testing
- `test_journal_management.py` - Journal entry CRUD operations testing
- `test_dek_recovery_methods.py` - DEK recovery methods testing
- `test_secret_edit_functionality.py` - Secret edit functionality testing
- `test_backup_functionality.py` - User data backup/export functionality testing
- `test_admin_backup_functionality.py` - Admin system backup functionality testing

## Key Management Tests
- `test_key_consistency.py` - Tests for key consistency across the system
- `test_key_lifecycle.py` - Tests for key lifecycle management
- `test_full_rotation.py` - Full key rotation process testing
- `test_token_rotation.py` - Token-based rotation testing
- `test_rotation_with_credentials.py` - Rotation with credential validation

## Recovery System Tests
- `test_recovery.py` - General recovery system testing
- `test_recovery_system.py` - Comprehensive recovery system tests
- `test_recovery_methods.py` - Recovery methods validation
- `test_recovery_encryption.py` - Recovery encryption testing
- `test_q_dek_recovery.py` - Q-DEK specific recovery testing

## Security & Authentication Tests
- `test_security_questions.py` - Security questions functionality
- `test_security_questions_only.py` - Security questions only recovery
- `test_password_generation.py` - Password generation utilities
- `test_password_fix.py` - Password-related fixes testing

## Email Service Tests
- `test_email_delivery.py` - Email delivery functionality
- `test_email_sender.py` - Email sender configuration
- `test_brevo_setup.py` - Brevo email service setup
- `test_brevo_login_sender.py` - Brevo login sender testing
- `test_exact_brevo.py` - Exact Brevo configuration tests
- `test_final_brevo.py` - Final Brevo integration tests
- `test_temp_email.py` - Temporary email handling
- `test_gmail_direct.py` - Direct Gmail integration
- `test_verified_sender.py` - Verified sender functionality

## Database & Encryption Tests
- `test_edek_fix.py` - E-DEK encryption fixes
- `test_fixed_qdek.py` - Fixed Q-DEK testing
- `test_p_dek_debug.py` - P-DEK debugging tests
- `test_phrase_variations.py` - Recovery phrase variations
- `test_real_data.py` - Real data testing scenarios

## Admin & System Tests
- `test_admin_fix.py` - Admin functionality fixes
- `test_end_to_end.py` - End-to-end system testing
- `test_original_method.py` - Original method validation

## Running Tests

To run a specific test:
```bash
cd C:\Users\PrabhSac\IdeaProjects\personal\LifeVault
python tests\test_web_application_api.py
```

To run all tests (if you have a test runner):
```bash
python -m pytest tests/
```

## Note
Make sure the main application is running before executing API tests that require HTTP endpoints.

## Backup System Overview

The LifeVault application includes two types of backup functionality:

### User Data Backup (`/export_data`)
- **Who can access**: Any authenticated user
- **Scope**: Individual user's data only
- **Contents**: User's own secrets (encrypted), journal entries, profile info, security setup
- **File naming**: `lifevault_backup_[username]_[timestamp].json`
- **Access**: User profile page or navigation menu → "Export Data"

### Admin System Backup (`/admin/export_all_data`)
- **Who can access**: Admin users only
- **Scope**: Complete system data for all users
- **Contents**: All users' data, secrets (encrypted), journal entries, audit logs, system statistics
- **File naming**: `lifevault_admin_backup_[timestamp].json`
- **Access**: Admin dashboard or admin navigation menu → "System Backup"

Both backup types preserve security by keeping user secrets in encrypted form.
