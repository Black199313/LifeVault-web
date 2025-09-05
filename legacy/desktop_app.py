#!/usr/bin/env python3
"""
Secret Journal Manager - Desktop Application
A standalone desktop version with encrypted secret storage and journal functionality
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
from tkinter.ttk import Notebook, Frame
import sqlite3
import hashlib
import base64
import json
from datetime import datetime, date
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import secrets
import string

class CryptoManager:
    """Handle encryption/decryption operations"""
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """Encrypt data with key"""
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> str:
        """Decrypt data with key"""
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate random salt"""
        return os.urandom(16)
    
    @staticmethod
    def generate_password(length=16):
        """Generate secure password"""
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        numbers = '0123456789'
        symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        all_chars = lowercase + uppercase + numbers + symbols
        password = ''
        
        # Ensure at least one character from each category
        password += secrets.choice(lowercase)
        password += secrets.choice(uppercase)
        password += secrets.choice(numbers)
        password += secrets.choice(symbols)
        
        # Fill the rest randomly
        for _ in range(length - 4):
            password += secrets.choice(all_chars)
        
        # Shuffle the password
        return ''.join(secrets.choice(password) for _ in range(len(password)))

class DatabaseManager:
    """Handle database operations"""
    
    def __init__(self, db_path="secret_journal.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                security_questions TEXT,
                recovery_phrase_hash TEXT
            )
        ''')
        
        # Secrets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                url TEXT,
                username TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Journal entries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS journal_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_date DATE NOT NULL,
                content TEXT NOT NULL,
                mood TEXT,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def execute_query(self, query, params=None):
        """Execute database query"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        result = cursor.fetchall()
        conn.commit()
        conn.close()
        return result

class LoginWindow:
    """Login/Registration window"""
    
    def __init__(self, app):
        self.app = app
        self.root = tk.Toplevel()
        self.root.title("Secret Journal Manager - Login")
        self.root.geometry("400x500")
        self.root.resizable(False, False)
        
        # Center the window
        self.root.transient(app.root)
        self.root.grab_set()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup login UI"""
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Secret Journal Manager", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Login frame
        login_frame = ttk.LabelFrame(main_frame, text="Login", padding="15")
        login_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(login_frame, text="Username:").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(login_frame, width=30)
        self.username_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(login_frame, text="Password:").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(login_frame, show="*", width=30)
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(login_frame, text="Login", command=self.login).pack(fill=tk.X)
        
        # Register frame
        register_frame = ttk.LabelFrame(main_frame, text="New User Registration", padding="15")
        register_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(register_frame, text="Username:").pack(anchor=tk.W)
        self.reg_username_entry = ttk.Entry(register_frame, width=30)
        self.reg_username_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(register_frame, text="Password:").pack(anchor=tk.W)
        self.reg_password_entry = ttk.Entry(register_frame, show="*", width=30)
        self.reg_password_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(register_frame, text="Confirm Password:").pack(anchor=tk.W)
        self.reg_confirm_entry = ttk.Entry(register_frame, show="*", width=30)
        self.reg_confirm_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(register_frame, text="Register", command=self.register).pack(fill=tk.X)
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.login())
    
    def login(self):
        """Handle login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        # Check user credentials
        user_data = self.app.db.execute_query(
            "SELECT id, password_hash, salt FROM users WHERE username = ?",
            (username,)
        )
        
        if user_data:
            user_id, stored_hash, salt = user_data[0]
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            
            if hashlib.pbkdf2_hmac('sha256', stored_hash.encode(), b'verify', 1) == \
               hashlib.pbkdf2_hmac('sha256', base64.b64encode(password_hash).decode().encode(), b'verify', 1):
                
                self.app.current_user = {'id': user_id, 'username': username}
                self.app.user_key = CryptoManager.derive_key(password, salt)
                messagebox.showinfo("Success", f"Welcome back, {username}!")
                self.root.destroy()
                return
        
        messagebox.showerror("Error", "Invalid username or password")
    
    def register(self):
        """Handle registration"""
        username = self.reg_username_entry.get().strip()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        
        # Check if username exists
        existing = self.app.db.execute_query(
            "SELECT id FROM users WHERE username = ?", (username,)
        )
        
        if existing:
            messagebox.showerror("Error", "Username already exists")
            return
        
        # Create new user
        salt = CryptoManager.generate_salt()
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        self.app.db.execute_query(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, base64.b64encode(password_hash).decode(), salt)
        )
        
        messagebox.showinfo("Success", f"Account created successfully! You can now login.")
        
        # Clear registration fields
        self.reg_username_entry.delete(0, tk.END)
        self.reg_password_entry.delete(0, tk.END)
        self.reg_confirm_entry.delete(0, tk.END)

class SecretsTab:
    """Secrets management tab"""
    
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup secrets UI"""
        # Top frame with add button
        top_frame = ttk.Frame(self.frame)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(top_frame, text="Add New Secret", 
                  command=self.add_secret).pack(side=tk.LEFT)
        ttk.Button(top_frame, text="Generate Password", 
                  command=self.generate_password).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(top_frame, text="Refresh", 
                  command=self.refresh_secrets).pack(side=tk.RIGHT)
        
        # Secrets list
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview for secrets
        columns = ('Title', 'Type', 'URL', 'Username', 'Created')
        self.secrets_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.secrets_tree.heading(col, text=col)
            self.secrets_tree.column(col, width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.secrets_tree.yview)
        self.secrets_tree.configure(yscrollcommand=scrollbar.set)
        
        self.secrets_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to view secret
        self.secrets_tree.bind('<Double-1>', self.view_secret)
        
        # Context menu
        self.context_menu = tk.Menu(self.secrets_tree, tearoff=0)
        self.context_menu.add_command(label="View", command=self.view_secret)
        self.context_menu.add_command(label="Edit", command=self.edit_secret)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete", command=self.delete_secret)
        
        self.secrets_tree.bind('<Button-3>', self.show_context_menu)
        
        self.refresh_secrets()
    
    def refresh_secrets(self):
        """Refresh secrets list"""
        if not self.app.current_user:
            return
        
        # Clear existing items
        for item in self.secrets_tree.get_children():
            self.secrets_tree.delete(item)
        
        # Get secrets from database
        secrets = self.app.db.execute_query(
            """SELECT id, title, secret_type, url, username, created_at 
               FROM secrets WHERE user_id = ? ORDER BY created_at DESC""",
            (self.app.current_user['id'],)
        )
        
        for secret in secrets:
            self.secrets_tree.insert('', tk.END, values=secret[1:])
    
    def add_secret(self):
        """Add new secret"""
        if not self.app.current_user:
            messagebox.showerror("Error", "Please login first")
            return
        
        self.secret_dialog()
    
    def secret_dialog(self, secret_id=None):
        """Secret add/edit dialog"""
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Add Secret" if not secret_id else "Edit Secret")
        dialog.geometry("500x600")
        dialog.resizable(False, False)
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Title:").pack(anchor=tk.W)
        title_entry = ttk.Entry(main_frame, width=50)
        title_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Type
        ttk.Label(main_frame, text="Type:").pack(anchor=tk.W)
        type_var = tk.StringVar(value="password")
        type_combo = ttk.Combobox(main_frame, textvariable=type_var, 
                                 values=["password", "api_key", "note", "card", "other"],
                                 state="readonly", width=47)
        type_combo.pack(fill=tk.X, pady=(0, 10))
        
        # URL
        ttk.Label(main_frame, text="URL (optional):").pack(anchor=tk.W)
        url_entry = ttk.Entry(main_frame, width=50)
        url_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Username
        ttk.Label(main_frame, text="Username (optional):").pack(anchor=tk.W)
        username_entry = ttk.Entry(main_frame, width=50)
        username_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Content
        ttk.Label(main_frame, text="Secret Content:").pack(anchor=tk.W)
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.X, pady=(0, 10))
        
        content_text = scrolledtext.ScrolledText(content_frame, height=8, width=50)
        content_text.pack(fill=tk.X)
        
        # Notes
        ttk.Label(main_frame, text="Notes (optional):").pack(anchor=tk.W)
        notes_text = scrolledtext.ScrolledText(main_frame, height=4, width=50)
        notes_text.pack(fill=tk.X, pady=(0, 15))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def save_secret():
            title = title_entry.get().strip()
            secret_type = type_var.get()
            url = url_entry.get().strip()
            username = username_entry.get().strip()
            content = content_text.get(1.0, tk.END).strip()
            notes = notes_text.get(1.0, tk.END).strip()
            
            if not title or not content:
                messagebox.showerror("Error", "Title and content are required")
                return
            
            try:
                # Encrypt content
                encrypted_content = CryptoManager.encrypt_data(content, self.app.user_key)
                
                if secret_id:
                    # Update existing
                    self.app.db.execute_query(
                        """UPDATE secrets SET title=?, secret_type=?, encrypted_content=?, 
                           url=?, username=?, notes=? WHERE id=? AND user_id=?""",
                        (title, secret_type, encrypted_content, url, username, notes, 
                         secret_id, self.app.current_user['id'])
                    )
                else:
                    # Insert new
                    self.app.db.execute_query(
                        """INSERT INTO secrets (user_id, title, secret_type, encrypted_content, 
                           url, username, notes) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (self.app.current_user['id'], title, secret_type, encrypted_content, 
                         url, username, notes)
                    )
                
                messagebox.showinfo("Success", "Secret saved successfully!")
                dialog.destroy()
                self.refresh_secrets()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save secret: {str(e)}")
        
        ttk.Button(button_frame, text="Save", command=save_secret).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        title_entry.focus()
    
    def view_secret(self, event=None):
        """View selected secret"""
        selection = self.secrets_tree.selection()
        if not selection:
            return
        
        # Get secret data
        item = self.secrets_tree.item(selection[0])
        title = item['values'][0]
        
        # Find secret in database
        secret_data = self.app.db.execute_query(
            """SELECT id, encrypted_content, url, username, notes FROM secrets 
               WHERE title = ? AND user_id = ?""",
            (title, self.app.current_user['id'])
        )
        
        if not secret_data:
            messagebox.showerror("Error", "Secret not found")
            return
        
        secret_id, encrypted_content, url, username, notes = secret_data[0]
        
        try:
            # Decrypt content
            content = CryptoManager.decrypt_data(encrypted_content, self.app.user_key)
            
            # Show view dialog
            dialog = tk.Toplevel(self.app.root)
            dialog.title(f"View Secret: {title}")
            dialog.geometry("500x400")
            dialog.transient(self.app.root)
            dialog.grab_set()
            
            main_frame = ttk.Frame(dialog, padding="20")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Display fields
            ttk.Label(main_frame, text=f"Title: {title}", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
            
            if url:
                ttk.Label(main_frame, text=f"URL: {url}").pack(anchor=tk.W, pady=(0, 5))
            
            if username:
                ttk.Label(main_frame, text=f"Username: {username}").pack(anchor=tk.W, pady=(0, 5))
            
            ttk.Label(main_frame, text="Content:").pack(anchor=tk.W, pady=(10, 0))
            
            content_frame = ttk.Frame(main_frame)
            content_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
            
            content_text = scrolledtext.ScrolledText(content_frame, height=8, state=tk.DISABLED)
            content_text.pack(fill=tk.BOTH, expand=True)
            content_text.config(state=tk.NORMAL)
            content_text.insert(1.0, content)
            content_text.config(state=tk.DISABLED)
            
            if notes:
                ttk.Label(main_frame, text="Notes:").pack(anchor=tk.W)
                notes_text = scrolledtext.ScrolledText(main_frame, height=3, state=tk.DISABLED)
                notes_text.pack(fill=tk.X, pady=(5, 10))
                notes_text.config(state=tk.NORMAL)
                notes_text.insert(1.0, notes)
                notes_text.config(state=tk.DISABLED)
            
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X)
            
            def copy_content():
                dialog.clipboard_clear()
                dialog.clipboard_append(content)
                messagebox.showinfo("Success", "Content copied to clipboard!")
            
            ttk.Button(button_frame, text="Copy Content", command=copy_content).pack(side=tk.LEFT)
            ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt secret: {str(e)}")
    
    def edit_secret(self):
        """Edit selected secret"""
        selection = self.secrets_tree.selection()
        if not selection:
            return
        
        item = self.secrets_tree.item(selection[0])
        title = item['values'][0]
        
        # Find secret ID
        secret_data = self.app.db.execute_query(
            "SELECT id FROM secrets WHERE title = ? AND user_id = ?",
            (title, self.app.current_user['id'])
        )
        
        if secret_data:
            self.secret_dialog(secret_data[0][0])
    
    def delete_secret(self):
        """Delete selected secret"""
        selection = self.secrets_tree.selection()
        if not selection:
            return
        
        item = self.secrets_tree.item(selection[0])
        title = item['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Delete secret '{title}'?"):
            self.app.db.execute_query(
                "DELETE FROM secrets WHERE title = ? AND user_id = ?",
                (title, self.app.current_user['id'])
            )
            self.refresh_secrets()
            messagebox.showinfo("Success", "Secret deleted successfully")
    
    def generate_password(self):
        """Generate secure password"""
        password = CryptoManager.generate_password()
        
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Generated Password")
        dialog.geometry("400x200")
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Generated Password:", font=("Arial", 12)).pack(pady=(0, 10))
        
        password_entry = ttk.Entry(main_frame, width=40, font=("Courier", 12))
        password_entry.pack(fill=tk.X, pady=(0, 15))
        password_entry.insert(0, password)
        password_entry.config(state="readonly")
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def copy_password():
            dialog.clipboard_clear()
            dialog.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        
        ttk.Button(button_frame, text="Copy", command=copy_password).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Generate New", 
                  command=lambda: self.update_password(password_entry)).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def update_password(self, entry):
        """Update password in entry widget"""
        new_password = CryptoManager.generate_password()
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, new_password)
        entry.config(state="readonly")
    
    def show_context_menu(self, event):
        """Show context menu"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

class JournalTab:
    """Journal functionality tab"""
    
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup journal UI"""
        # Top frame with date picker and add button
        top_frame = ttk.Frame(self.frame)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(top_frame, text="Date:").pack(side=tk.LEFT)
        
        # Date selection
        self.date_var = tk.StringVar(value=date.today().strftime("%Y-%m-%d"))
        date_entry = ttk.Entry(top_frame, textvariable=self.date_var, width=12)
        date_entry.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Button(top_frame, text="Add Entry", 
                  command=self.add_entry).pack(side=tk.LEFT)
        ttk.Button(top_frame, text="Refresh", 
                  command=self.refresh_entries).pack(side=tk.RIGHT)
        
        # Entries list
        list_frame = ttk.Frame(self.frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview for entries
        columns = ('Date', 'Mood', 'Preview', 'Created')
        self.entries_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.entries_tree.heading(col, text=col)
            
        self.entries_tree.column('Date', width=100)
        self.entries_tree.column('Mood', width=80)
        self.entries_tree.column('Preview', width=300)
        self.entries_tree.column('Created', width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.entries_tree.yview)
        self.entries_tree.configure(yscrollcommand=scrollbar.set)
        
        self.entries_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to view entry
        self.entries_tree.bind('<Double-1>', self.view_entry)
        
        # Context menu
        self.context_menu = tk.Menu(self.entries_tree, tearoff=0)
        self.context_menu.add_command(label="View", command=self.view_entry)
        self.context_menu.add_command(label="Edit", command=self.edit_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete", command=self.delete_entry)
        
        self.entries_tree.bind('<Button-3>', self.show_context_menu)
        
        self.refresh_entries()
    
    def refresh_entries(self):
        """Refresh journal entries list"""
        # Clear existing items
        for item in self.entries_tree.get_children():
            self.entries_tree.delete(item)
        
        # Get entries from database
        entries = self.app.db.execute_query(
            """SELECT id, entry_date, mood, content, created_at 
               FROM journal_entries ORDER BY entry_date DESC"""
        )
        
        for entry in entries:
            entry_id, entry_date, mood, content, created_at = entry
            preview = content[:50] + "..." if len(content) > 50 else content
            self.entries_tree.insert('', tk.END, values=(entry_date, mood or "None", preview, created_at))
    
    def add_entry(self):
        """Add new journal entry"""
        self.entry_dialog()
    
    def entry_dialog(self, entry_id=None):
        """Journal entry add/edit dialog"""
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Add Journal Entry" if not entry_id else "Edit Journal Entry")
        dialog.geometry("600x500")
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Date
        date_frame = ttk.Frame(main_frame)
        date_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(date_frame, text="Date:").pack(side=tk.LEFT)
        date_entry = ttk.Entry(date_frame, width=12)
        date_entry.pack(side=tk.LEFT, padx=(10, 20))
        date_entry.insert(0, self.date_var.get())
        
        ttk.Label(date_frame, text="Mood:").pack(side=tk.LEFT)
        mood_var = tk.StringVar()
        mood_combo = ttk.Combobox(date_frame, textvariable=mood_var, width=15,
                                 values=["happy", "sad", "excited", "calm", "anxious", "angry", "content"],
                                 state="readonly")
        mood_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # Content
        ttk.Label(main_frame, text="Journal Entry:").pack(anchor=tk.W, pady=(10, 0))
        content_text = scrolledtext.ScrolledText(main_frame, height=15, width=70)
        content_text.pack(fill=tk.BOTH, expand=True, pady=(5, 15))
        
        # Tags
        ttk.Label(main_frame, text="Tags (comma-separated):").pack(anchor=tk.W)
        tags_entry = ttk.Entry(main_frame, width=70)
        tags_entry.pack(fill=tk.X, pady=(5, 15))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def save_entry():
            entry_date = date_entry.get().strip()
            mood = mood_var.get() if mood_var.get() else None
            content = content_text.get(1.0, tk.END).strip()
            tags = tags_entry.get().strip()
            
            if not entry_date or not content:
                messagebox.showerror("Error", "Date and content are required")
                return
            
            try:
                # Validate date format
                datetime.strptime(entry_date, '%Y-%m-%d')
                
                tags_json = json.dumps([tag.strip() for tag in tags.split(',') if tag.strip()]) if tags else None
                
                if entry_id:
                    # Update existing
                    self.app.db.execute_query(
                        """UPDATE journal_entries SET entry_date=?, mood=?, content=?, tags=? 
                           WHERE id=?""",
                        (entry_date, mood, content, tags_json, entry_id)
                    )
                else:
                    # Insert new
                    self.app.db.execute_query(
                        """INSERT INTO journal_entries (entry_date, mood, content, tags) 
                           VALUES (?, ?, ?, ?)""",
                        (entry_date, mood, content, tags_json)
                    )
                
                messagebox.showinfo("Success", "Journal entry saved successfully!")
                dialog.destroy()
                self.refresh_entries()
                
            except ValueError:
                messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save entry: {str(e)}")
        
        ttk.Button(button_frame, text="Save", command=save_entry).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        content_text.focus()
    
    def view_entry(self, event=None):
        """View selected journal entry"""
        selection = self.entries_tree.selection()
        if not selection:
            return
        
        item = self.entries_tree.item(selection[0])
        entry_date = item['values'][0]
        
        # Find entry in database
        entry_data = self.app.db.execute_query(
            """SELECT id, mood, content, tags FROM journal_entries 
               WHERE entry_date = ? ORDER BY created_at DESC LIMIT 1""",
            (entry_date,)
        )
        
        if not entry_data:
            messagebox.showerror("Error", "Entry not found")
            return
        
        entry_id, mood, content, tags_json = entry_data[0]
        
        # Show view dialog
        dialog = tk.Toplevel(self.app.root)
        dialog.title(f"Journal Entry - {entry_date}")
        dialog.geometry("600x500")
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text=f"Date: {entry_date}", 
                 font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        if mood:
            ttk.Label(header_frame, text=f"Mood: {mood.title()}", 
                     font=("Arial", 10)).pack(side=tk.RIGHT)
        
        # Content
        ttk.Label(main_frame, text="Content:").pack(anchor=tk.W)
        content_text = scrolledtext.ScrolledText(main_frame, height=15, state=tk.DISABLED)
        content_text.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        content_text.config(state=tk.NORMAL)
        content_text.insert(1.0, content)
        content_text.config(state=tk.DISABLED)
        
        # Tags
        if tags_json:
            tags = json.loads(tags_json)
            if tags:
                ttk.Label(main_frame, text=f"Tags: {', '.join(tags)}").pack(anchor=tk.W, pady=(5, 10))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def edit_entry(self):
        """Edit selected journal entry"""
        selection = self.entries_tree.selection()
        if not selection:
            return
        
        item = self.entries_tree.item(selection[0])
        entry_date = item['values'][0]
        
        # Find entry ID
        entry_data = self.app.db.execute_query(
            "SELECT id FROM journal_entries WHERE entry_date = ? ORDER BY created_at DESC LIMIT 1",
            (entry_date,)
        )
        
        if entry_data:
            self.entry_dialog(entry_data[0][0])
    
    def delete_entry(self):
        """Delete selected journal entry"""
        selection = self.entries_tree.selection()
        if not selection:
            return
        
        item = self.entries_tree.item(selection[0])
        entry_date = item['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Delete journal entry for {entry_date}?"):
            self.app.db.execute_query(
                "DELETE FROM journal_entries WHERE entry_date = ?",
                (entry_date,)
            )
            self.refresh_entries()
            messagebox.showinfo("Success", "Journal entry deleted successfully")
    
    def show_context_menu(self, event):
        """Show context menu"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

class SecretJournalApp:
    """Main application class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secret Journal Manager")
        self.root.geometry("800x600")
        
        # Application state
        self.current_user = None
        self.user_key = None
        
        # Initialize database
        self.db = DatabaseManager()
        
        self.setup_ui()
        self.setup_menu()
        
        # Show login on startup
        self.show_login()
    
    def setup_ui(self):
        """Setup main UI"""
        # Status bar
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = ttk.Label(self.status_frame, text="Not logged in")
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Main content area
        self.notebook = Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.secrets_tab = SecretsTab(self.notebook, self)
        self.journal_tab = JournalTab(self.notebook, self)
        
        self.notebook.add(self.secrets_tab.frame, text="Secrets Manager")
        self.notebook.add(self.journal_tab.frame, text="Journal")
        
        # Initially disable secrets tab until login
        self.notebook.tab(0, state="disabled")
    
    def setup_menu(self):
        """Setup application menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Login", command=self.show_login)
        file_menu.add_command(label="Logout", command=self.logout)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Generate Password", command=self.generate_password_tool)
        tools_menu.add_command(label="Export Data", command=self.export_data)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def show_login(self):
        """Show login window"""
        LoginWindow(self)
        self.update_ui_state()
    
    def logout(self):
        """Logout current user"""
        self.current_user = None
        self.user_key = None
        self.update_ui_state()
        messagebox.showinfo("Success", "Logged out successfully")
    
    def update_ui_state(self):
        """Update UI based on login state"""
        if self.current_user:
            self.status_label.config(text=f"Logged in as: {self.current_user['username']}")
            self.notebook.tab(0, state="normal")
            self.secrets_tab.refresh_secrets()
        else:
            self.status_label.config(text="Not logged in")
            self.notebook.tab(0, state="disabled")
            # Switch to journal tab
            self.notebook.select(1)
    
    def generate_password_tool(self):
        """Generate password tool"""
        self.secrets_tab.generate_password()
    
    def export_data(self):
        """Export user data"""
        if not self.current_user:
            messagebox.showerror("Error", "Please login first")
            return
        
        messagebox.showinfo("Info", "Export functionality would be implemented here")
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About", 
                           "Secret Journal Manager v1.0\n\n"
                           "A secure desktop application for managing secrets and journal entries.\n\n"
                           "Features:\n"
                           "• Encrypted secret storage\n"
                           "• Personal journal with mood tracking\n"
                           "• Password generation\n"
                           "• Secure local database")
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = SecretJournalApp()
    app.run()