import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import sqlite3
import base64
import os
import logging
import hashlib
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging for SDLC observability
logging.basicConfig(
    filename='vault.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Application Theme Settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class CryptographicVaultSystem(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Cryptographic Vault System")
        self.geometry("650x700")
        self.resizable(False, False)
        
        self.key = None
        self.fernet = None
        self.failed_attempts = 0
        self.timeout_id = None

        self.init_db()
        
        # Bind user activity to reset the 3-minute inactivity timer
        self.bind("<Any-KeyPress>", self.reset_inactivity_timer)
        self.bind("<Any-Button>", self.reset_inactivity_timer)
        self.bind("<Motion>", self.reset_inactivity_timer)

        self.current_frame = None

        if self.is_first_run():
            self.show_setup_screen()
        else:
            self.show_login_screen()

    # ==========================================
    # Database Initialization
    # ==========================================
    def init_db(self):
        try:
            conn = sqlite3.connect("vault_data.db")
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sys_config (
                    key_name TEXT PRIMARY KEY,
                    key_value TEXT NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")

    def is_first_run(self):
        conn = sqlite3.connect("vault_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT key_value FROM sys_config WHERE key_name='master_hash'")
        result = cursor.fetchone()
        conn.close()
        return result is None

    # ==========================================
    # Cryptography Operations
    # ==========================================
    def hash_password(self, password, salt):
        return hashlib.sha256(password.encode() + salt).hexdigest()

    def generate_encryption_key(self, master_password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=150000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    # ==========================================
    # Session Management
    # ==========================================
    def reset_inactivity_timer(self, event=None):
        if self.timeout_id:
            self.after_cancel(self.timeout_id)
        
        # 3 minutes = 180,000 milliseconds
        if self.fernet is not None:
            self.timeout_id = self.after(180000, self.session_timeout_logout)

    def session_timeout_logout(self):
        logging.info("Session expired due to 3 minutes of inactivity. System locked.")
        self.key = None
        self.fernet = None
        
        messagebox.showwarning("Session Timeout", "Session expired due to 3 minutes of inactivity. Please log in again.")
        self.show_login_screen()

    # ==========================================
    # Navigation Helper
    # ==========================================
    def switch_frame(self, new_frame_func):
        if self.current_frame is not None:
            self.current_frame.destroy()
        new_frame_func()

    # ==========================================
    # UI Screens
    # ==========================================
    def show_setup_screen(self):
        self.current_frame = ctk.CTkFrame(self, corner_radius=15)
        self.current_frame.pack(pady=60, padx=40, fill="both", expand=True)

        ctk.CTkLabel(self.current_frame, text="System Setup", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(30, 10))
        ctk.CTkLabel(self.current_frame, text="Create your Master Password.\nKeep it safe, it cannot be recovered!", text_color="gray").pack(pady=(0, 20))

        self.new_pwd_entry = ctk.CTkEntry(self.current_frame, placeholder_text="New Master Password", show="*", width=250, height=40)
        self.new_pwd_entry.pack(pady=10)

        ctk.CTkButton(self.current_frame, text="Initialize System", command=self.process_setup, width=250, height=40).pack(pady=20)

    def process_setup(self):
        master_pwd = self.new_pwd_entry.get()
        if len(master_pwd) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters.")
            return

        salt = os.urandom(16)
        master_hash = self.hash_password(master_pwd, salt)

        conn = sqlite3.connect("vault_data.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO sys_config (key_name, key_value) VALUES (?, ?)", ('salt', salt.hex()))
        cursor.execute("INSERT INTO sys_config (key_name, key_value) VALUES (?, ?)", ('master_hash', master_hash))
        conn.commit()
        conn.close()

        logging.info("System initialized and Master Password set successfully.")
        messagebox.showinfo("Success", "System initialized successfully! Please log in.")
        self.switch_frame(self.show_login_screen)

    def show_login_screen(self):
        self.current_frame = ctk.CTkFrame(self, corner_radius=15)
        self.current_frame.pack(pady=100, padx=40, fill="both", expand=True)

        ctk.CTkLabel(self.current_frame, text="System Login", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(40, 20))

        self.login_pwd_entry = ctk.CTkEntry(self.current_frame, placeholder_text="Master Password", show="*", width=250, height=40)
        self.login_pwd_entry.pack(pady=20)

        self.login_btn = ctk.CTkButton(self.current_frame, text="Unlock Vault", command=self.process_login, width=250, height=40)
        self.login_btn.pack(pady=10)

    def process_login(self):
        master_pwd = self.login_pwd_entry.get()
        
        conn = sqlite3.connect("vault_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT key_value FROM sys_config WHERE key_name='salt'")
        salt_row = cursor.fetchone()
        cursor.execute("SELECT key_value FROM sys_config WHERE key_name='master_hash'")
        hash_row = cursor.fetchone()
        conn.close()

        if not salt_row or not hash_row:
            messagebox.showerror("Critical Error", "System configuration missing.")
            return

        salt = bytes.fromhex(salt_row[0])
        stored_hash = hash_row[0]

        input_hash = self.hash_password(master_pwd, salt)

        if input_hash == stored_hash:
            logging.info("Successful login attempt.")
            self.failed_attempts = 0
            self.key = self.generate_encryption_key(master_pwd, salt)
            self.fernet = Fernet(self.key)
            self.reset_inactivity_timer()
            self.switch_frame(self.show_vault_screen)
        else:
            self.failed_attempts += 1
            logging.warning(f"Failed login attempt {self.failed_attempts}/3.")
            
            if self.failed_attempts >= 3:
                logging.error("Maximum login attempts reached. System shutting down.")
                messagebox.showerror("Security Alert", "Maximum attempts reached. Application will exit.")
                self.destroy()
            else:
                attempts_left = 3 - self.failed_attempts
                messagebox.showerror("Authentication Failed", f"Incorrect password. {attempts_left} attempts remaining.")

    def show_vault_screen(self):
        self.current_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.current_frame.pack(fill="both", expand=True)

        # Top Section: Add New Credentials
        add_section = ctk.CTkFrame(self.current_frame, corner_radius=15)
        add_section.pack(pady=20, padx=20, fill="x")

        ctk.CTkLabel(add_section, text="Add New Credential", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

        input_grid = ctk.CTkFrame(add_section, fg_color="transparent")
        input_grid.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(input_grid, text="Website / Platform").grid(row=0, column=0, padx=5, sticky="w")
        self.entry_site = ctk.CTkEntry(input_grid, placeholder_text="e.g., github.com")
        self.entry_site.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ctk.CTkLabel(input_grid, text="Username / Email").grid(row=1, column=0, padx=5, sticky="w")
        self.entry_user = ctk.CTkEntry(input_grid, placeholder_text="Username or Email")
        self.entry_user.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ctk.CTkLabel(input_grid, text="Password").grid(row=2, column=0, padx=5, sticky="w")
        self.entry_pass = ctk.CTkEntry(input_grid, placeholder_text="Secure Password", show="*")
        self.entry_pass.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        btn_gen_pass = ctk.CTkButton(input_grid, text="Generate Strong Password ✨", command=self.generate_secure_password)
        btn_gen_pass.grid(row=2, column=2, padx=10, pady=5)

        input_grid.columnconfigure(1, weight=1)

        btn_save = ctk.CTkButton(add_section, text="Save & Encrypt Data 🔒", command=self.save_credential, height=45, corner_radius=10)
        btn_save.pack(pady=15, fill="x", padx=10)

        # Bottom Section: Stored Credentials
        stored_section = ctk.CTkFrame(self.current_frame, corner_radius=15)
        stored_section.pack(pady=10, padx=20, fill="both", expand=True)

        ctk.CTkLabel(stored_section, text="Stored Credentials", font=ctk.CTkFont(size=16)).pack(pady=10)

        self.scroll_frame = ctk.CTkScrollableFrame(stored_section)
        self.scroll_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.load_vault_data()

    def generate_secure_password(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        secure_password = ''.join(secrets.choice(alphabet) for i in range(16))
        self.entry_pass.delete(0, tk.END)
        self.entry_pass.insert(0, secure_password)
        self.entry_pass.configure(show="") 
        self.after(3000, lambda: self.entry_pass.configure(show="*"))

    def save_credential(self):
        site = self.entry_site.get().strip()
        user = self.entry_user.get().strip()
        password = self.entry_pass.get().strip()

        if not site or not user or not password:
            messagebox.showwarning("Warning", "All fields are required.")
            return

        try:
            encrypted_password = self.fernet.encrypt(password.encode()).decode()
            
            conn = sqlite3.connect("vault_data.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO vault_items (website, username, encrypted_password) VALUES (?, ?, ?)", 
                           (site, user, encrypted_password))
            conn.commit()
            conn.close()

            logging.info(f"New credential added for: {site}")
            messagebox.showinfo("Success", f"Credential for '{site}' saved successfully!")
            
            self.entry_site.delete(0, tk.END)
            self.entry_user.delete(0, tk.END)
            self.entry_pass.delete(0, tk.END)
            self.entry_pass.configure(show="*")
            
            self.load_vault_data()
        except Exception as e:
            logging.error(f"Failed to save credential: {e}")
            messagebox.showerror("Error", "An error occurred while saving data.")

    def load_vault_data(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        conn = sqlite3.connect("vault_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, website, username, encrypted_password FROM vault_items")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            ctk.CTkLabel(self.scroll_frame, text="Your vault is empty.\nAdd a new credential above.", 
                         text_color="gray", font=ctk.CTkFont(slant="italic")).pack(pady=40)
            return

        for row in rows:
            item_id, site, user, enc_pass = row
            
            card = ctk.CTkFrame(self.scroll_frame)
            card.pack(fill="x", pady=5, padx=5)
            
            ctk.CTkLabel(card, text=site, font=ctk.CTkFont(size=14, weight="bold"), width=120, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(card, text=f"({user})", text_color="gray", width=150, anchor="w").pack(side="left", padx=5)
            
            decrypt_btn = ctk.CTkButton(card, text="Copy Password 📋", width=120, 
                                        command=lambda ep=enc_pass: self.copy_to_clipboard(ep))
            decrypt_btn.pack(side="right", padx=10, pady=10)

    def copy_to_clipboard(self, encrypted_password):
        try:
            decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()
            self.clipboard_clear()
            self.clipboard_append(decrypted_password)
            self.update() 
            logging.info("Password decrypted and copied to clipboard.")
            messagebox.showinfo("Success", "Password decrypted and copied to your clipboard safely!")
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            messagebox.showerror("Security Error", "Data decryption failed. Data might be corrupted.")

if __name__ == "__main__":
    app = CryptographicVaultSystem()
    app.mainloop()