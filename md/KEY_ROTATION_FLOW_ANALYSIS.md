# 🔄 Key Rotation System - Complete Flow Analysis

## 🎯 Overview
This document maps out the ENTIRE key rotation workflow to identify where failures occur. Individual recovery methods work, but key rotation fails during specific steps.

---

## 📊 Current Status Summary
- ✅ **Individual Recovery Methods Work**: P-DEK, Q-DEK, R-DEK all decrypt correctly
- ✅ **User Password**: `Test1234*` works perfectly 
- ❌ **Admin Credentials**: Admin password failing to decrypt admin master key
- ❌ **E-DEK Recovery**: Email password not working during rotation
- ❌ **A-DEK Finalization**: Cannot complete due to admin credential failure

---

## 🏗️ Key Rotation Architecture

### Phase 1: Pre-Rotation Validation
**Purpose**: Verify all credentials before starting rotation

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 1-6: PRE-ROTATION VALIDATION                          │
├─────────────────────────────────────────────────────────────┤
│ 1. Locate user and get current key version                 │
│ 2. Verify admin password → Get admin master key            │
│ 3. Decrypt current DEK (A-DEK or P-DEK fallback)          │
│ 4. Generate temporary password and rotation token          │
│ 5. Generate new DEK                                        │
│ 6. Test all current recovery methods with old DEK          │
└─────────────────────────────────────────────────────────────┘
```

**Files Involved**:
- `test_key_rotation_complete.py`: Lines 100-255
- `crypto_utils.py`: `get_or_create_admin_master_key()`, `recover_dek_with_*()` methods

**Current Issues**:
- ❌ **Step 2**: Admin password hash not matching stored admin master key
- ❌ **Step 6**: E-DEK recovery failing with provided email password

### Phase 2: New Key Generation  
**Purpose**: Create new encrypted keys with the new DEK

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 7-11: NEW KEY GENERATION                              │
├─────────────────────────────────────────────────────────────┤
│ 7. Create new P-DEK (new_dek + user_password)              │
│ 8. Create new Q-DEK (new_dek + security_answers)           │
│ 9. Create new R-DEK (new_dek + recovery_phrase)            │
│ 10. Create new E-DEK (new_dek + email_password)            │
│ 11. Create temp A-DEK (new_dek + temp_password)            │
└─────────────────────────────────────────────────────────────┘
```

**Files Involved**:
- `test_key_rotation_complete.py`: Lines 256-361
- `crypto_utils.py`: `derive_key_from_password()`, `encrypt_data()`

**Current Status**: ✅ **All steps working correctly**

### Phase 3: A-DEK Finalization
**Purpose**: Re-encrypt A-DEK with admin master key (security requirement)

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 12: A-DEK FINALIZATION (CRITICAL SECURITY STEP)      │
├─────────────────────────────────────────────────────────────┤
│ 12a. Decrypt temp A-DEK with temp_password → get new_dek   │
│ 12b. Encrypt new_dek with admin_master_key → final A-DEK   │
│ 12c. Verify final A-DEK decrypts correctly                 │
└─────────────────────────────────────────────────────────────┘
```

**Files Involved**:
- `test_key_rotation_complete.py`: Lines 361-410
- `crypto_utils.py`: `get_or_create_admin_master_key()`

**Current Issues**: ❌ **Step 12 COMPLETELY FAILING** - Admin credentials invalid

### Phase 4: Database Update & Verification
**Purpose**: Save new keys and verify they work

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 13-15: DATABASE UPDATE & VERIFICATION                 │
├─────────────────────────────────────────────────────────────┤
│ 13. Update all user keys in database                       │
│ 14. Test new P-DEK by decrypting a secret                  │
│ 15. Complete rotation and update token status              │
└─────────────────────────────────────────────────────────────┘
```

**Files Involved**:
- `test_key_rotation_complete.py`: Lines 411-526
- `models.py`: UserKeys.save()

**Current Status**: ✅ **Working but using fallback A-DEK (insecure)**

---

## 🔍 Detailed Code Analysis

### Critical Method: `get_or_create_admin_master_key()`

**Location**: `crypto_utils.py` lines 137-202

**What it does**:
1. Gets active admin master key record from database
2. Validates admin password hash against all admin users
3. Decrypts master key using validated admin password hash
4. Returns decrypted admin master key

**Failure Point Analysis**:
```python
# Line 239: This is where it's failing
if admin_password_hash not in admin_hashes:
    raise ValueError("Invalid admin credentials")
```

**Root Cause**: Admin password hash from test doesn't match stored admin password hash.

### Critical Method: `recover_dek_with_email_password()`

**Location**: `crypto_utils.py` lines 512-545

**What it does**:
1. Gets E-DEK data from user keys
2. Derives key from provided email password
3. Decrypts E-DEK to recover DEK

**Failure Point Analysis**: The email password provided doesn't match the one used to create E-DEK.

---

## 🛠️ Key Rotation Web Interface Flow

### Frontend: `user_key_rotation.html`
**What happens**:
1. User clicks "Start Key Rotation"
2. Modal asks for token + temp password + user credentials
3. AJAX call to `/api/rotate-keys` with all credentials

### Backend: `routes.py` - `/api/rotate-keys`
**What happens**:
1. Validates rotation token
2. Calls `crypto_manager.rotate_user_keys_with_admin_finalization()`
3. Returns success/failure

### Core Logic: `crypto_utils.py` - `rotate_user_keys_with_admin_finalization()`
**Location**: Lines 1045-1150

**Critical Steps**:
```python
# Step 1: Validate token and get temp password
token_record, temp_password = self._validate_and_lock_token(token)

# Step 2: Decrypt current DEK
current_dek = self.recover_dek_with_password(user_keys, user_password)

# Step 3: Create new keys (P-DEK, Q-DEK, R-DEK, E-DEK, temp A-DEK)
# ... key creation logic ...

# Step 4: CRITICAL - Finalize A-DEK with admin master key
if admin_password:
    # This is where it fails in web interface
    admin_password_hash = self.hash_password(admin_password)[0]
    admin_master_key = self.get_or_create_admin_master_key(admin_password_hash)
    # Re-encrypt A-DEK with admin master key
```

---

## 🚨 Identified Problems

### Problem 1: Admin Password Mismatch
**Symptom**: `Invalid admin credentials` error
**Root Cause**: The admin password you're entering doesn't match the stored admin password hash
**Impact**: A-DEK cannot be properly finalized, leaving it encrypted with temporary password (security risk)

**Debug Steps**:
1. Find what admin password is actually stored
2. Verify admin master key exists and is readable
3. Check if admin master key was created properly

### Problem 2: E-DEK Password Mismatch  
**Symptom**: `Failed to decrypt data` during E-DEK recovery
**Root Cause**: Email password provided doesn't match the one used when E-DEK was created
**Impact**: E-DEK recovery fails during pre-rotation validation

**Debug Steps**:
1. Check what email password was used when E-DEK was created
2. Verify E-DEK format and encryption method
3. Test if E-DEK was corrupted during previous operations

### Problem 3: Web Interface vs Test Script Discrepancy
**Symptom**: Test script "succeeds" but leaves system in insecure state
**Root Cause**: Test script falls back to temp A-DEK when admin credentials fail
**Impact**: System appears to work but A-DEK is not properly secured

---

## 🎯 Specific Failure Points in Code

### 1. Admin Master Key Decryption (`crypto_utils.py:239`)
```python
if admin_password_hash not in admin_hashes:
    raise ValueError("Invalid admin credentials")
```
**This line is throwing the error** - admin password hash not found in admin_hashes list.

### 2. E-DEK Decryption (`crypto_utils.py:540`)
```python
dek_b64 = self.decrypt_data(encrypted_data, email_key)
```
**This line is failing** - email_key derived from password cannot decrypt the stored E-DEK.

### 3. Token Validation (`crypto_utils.py:885-920`)
The `_validate_and_lock_token()` method has multiple fallback mechanisms, but may not be using the right one.

---

## 🔧 Recommended Fix Strategy

### Phase 1: Fix Admin Credentials
1. **Identify correct admin password**
2. **Verify admin master key storage format**
3. **Test admin master key decryption manually**

### Phase 2: Fix E-DEK Recovery
1. **Identify correct email password for this user**
2. **Test E-DEK decryption manually**
3. **Regenerate E-DEK if corrupted**

### Phase 3: Test Complete Flow
1. **Run test script with correct credentials**
2. **Verify A-DEK finalization works**
3. **Test web interface key rotation**

---

## 📝 Next Steps

1. **Create admin password finder script**
2. **Create E-DEK password finder script**  
3. **Create manual A-DEK finalization test**
4. **Fix and retest complete key rotation flow**

This analysis shows that the key rotation logic itself is sound, but **credential validation is failing at specific points**, causing the security-critical A-DEK finalization to be skipped.
