# Overview

This is a Flask-based web application called "Secret Journal Manager" that implements a secure secret management system with a revolutionary 5-key recovery mechanism. The application allows users to store sensitive information (passwords, API keys, personal secrets) and journal entries while ensuring they never lose access to their data, even if they forget their primary password.

The core concept revolves around encrypting user data with a single Data Encryption Key (DEK) that is then stored in 5 different encrypted forms, each unlockable through different recovery methods: password, security questions, recovery phrase, admin master key, and time-lock key.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5 for responsive UI
- **JavaScript Framework**: Vanilla JavaScript with Bootstrap components
- **CSS Framework**: Bootstrap with custom CSS variables and dark theme support
- **Calendar Integration**: FullCalendar library for journal entry visualization
- **Icons**: Font Awesome for consistent iconography

## Backend Architecture
- **Web Framework**: Flask with SQLAlchemy ORM for database operations
- **Authentication**: Flask-Login for session management and user authentication
- **Database Models**: User-centric design with relationships for UserKeys, SecretData, JournalEntry, and AuditLog
- **Middleware**: ProxyFix for handling reverse proxy headers
- **Security**: Werkzeug for password hashing and security utilities

## Data Storage Solutions
- **Primary Database**: PostgreSQL with SQLAlchemy ORM
- **Schema Design**: Relational model with proper foreign key relationships
- **JSON Storage**: PostgreSQL JSONB fields for flexible data like security questions and emergency contacts
- **Connection Management**: Connection pooling with pre-ping and recycle settings

## Authentication and Authorization
- **Multi-Factor Recovery**: 5-key system (password, security questions, recovery phrase, admin master key, time-lock)
- **Admin System**: Role-based access control with admin dashboard and user management
- **Session Management**: Flask-Login with secure session handling
- **Email Verification**: Token-based email verification system
- **Audit Logging**: Comprehensive logging of all security-related actions

## Encryption Architecture
- **Symmetric Encryption**: Fernet (AES 128 in CBC mode) for data encryption
- **Key Derivation**: PBKDF2HMAC with SHA-256 for password-based key derivation
- **Key Management**: Single DEK encrypted with 5 different methods for redundancy
- **Recovery System**: Multiple encrypted copies of the same decryption key using different unlock mechanisms

## Application Structure
- **Route Handling**: Centralized in routes.py with proper error handling and logging
- **Utility Functions**: Separated concerns with dedicated modules for crypto, email, and general utilities
- **Template Organization**: Modular template system with base template and specialized pages
- **Static Assets**: Organized CSS, JavaScript, and documentation files

# External Dependencies

## Core Framework Dependencies
- **Flask**: Web framework with extensions for SQLAlchemy, Login, and Mail
- **SQLAlchemy**: ORM with PostgreSQL dialect support
- **Werkzeug**: WSGI utilities and security functions

## Cryptographic Libraries
- **cryptography**: Comprehensive cryptographic library for Fernet encryption, PBKDF2, and RSA operations
- **hashlib**: Standard library for hashing functions

## Frontend Libraries
- **Bootstrap 5**: CSS framework with dark theme support from Replit
- **Font Awesome 6**: Icon library for UI elements
- **FullCalendar 6**: Calendar component for journal visualization

## Email Service
- **Flask-Mail**: Email sending capabilities with SMTP configuration
- **Gmail SMTP**: Default email service provider (configurable)

## Environment Configuration
- **Environment Variables**: Database URL, mail credentials, session secrets, and admin credentials
- **Logging**: Python standard logging with configurable levels

## Database Requirements
- **PostgreSQL**: Primary database with JSONB support for flexible data storage
- **Connection Pooling**: Configured for production deployment with proper connection management

## Security Infrastructure
- **Password Hashing**: Werkzeug's secure password hashing
- **Session Security**: Flask's secure session management
- **Rate Limiting**: Built-in utilities for preventing abuse
- **Audit Trail**: Comprehensive logging system for security events