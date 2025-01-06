import tkinter as tk
from tkinter import ttk, messagebox
import cryptography
from cryptography.fernet import Fernet
import json
import secrets
import string
import base64
import os
import re


class PasswordManager:
    def __init__(self):
        self.key_file = "key.key"
        self.password_file = "passwords.enc"
        self.cipher_suite = None
        self.passwords = {}

        # Initialize or load encryption key
        if os.path.exists(self.key_file):
            self.load_key()
        else:
            self.generate_key()

        # Load existing passwords
        self.load_passwords()

    def generate_key(self):
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(key)
        self.cipher_suite = Fernet(key)

    def load_key(self):
        with open(self.key_file, "rb") as key_file:
            key = key_file.read()
            self.cipher_suite = Fernet(key)

    def load_passwords(self, master_password=None):
        try:
            if os.path.exists(self.password_file):
                with open(self.password_file, "rb") as file:
                    encrypted_data = file.read()
                    if encrypted_data:
                        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                        self.passwords = json.loads(decrypted_data)
        except Exception as e:
            self.passwords = {}

    def save_passwords(self):
        try:
            encrypted_data = self.cipher_suite.encrypt(json.dumps(self.passwords).encode())
            with open(self.password_file, "wb") as file:
                file.write(encrypted_data)
            return True
        except Exception as e:
            return False

    def validate_password(self, password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        if not re.search(r'[a-z]', password):
            return False, "Password must contain lowercase letters"

        if not re.search(r'[A-Z]', password):
            return False, "Password must contain uppercase letters"

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain special characters"

        return True, "Password meets all requirements"

    def generate_password(self, length=16):
        if length < 8:
            length = 8

        lowercase = secrets.choice(string.ascii_lowercase)
        uppercase = secrets.choice(string.ascii_uppercase)
        special = secrets.choice('!@#$%^&*(),.?":{}|<>')
        digit = secrets.choice(string.digits)

        remaining_length = length - 4
        characters = string.ascii_letters + string.digits + '!@#$%^&*(),.?":{}|<>'
        rest = ''.join(secrets.choice(characters) for _ in range(remaining_length))

        password_list = list(lowercase + uppercase + special + digit + rest)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)

    def get_password(self, service):
        """Retrieve password details for a service"""
        return self.passwords.get(service)

    def add_password(self, service, username, password):
        is_valid, message = self.validate_password(password)
        if not is_valid:
            return False

        self.passwords[service] = {
            "username": username,
            "password": password
        }
        return self.save_passwords()


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("600x400")
        self.root.resizable(True, True)

        # Initialize the password manager backend
        self.pm = PasswordManager()

        # Create main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Create tabs
        self.passwords_tab = ttk.Frame(self.notebook, padding="10")
        self.generate_tab = ttk.Frame(self.notebook, padding="10")

        self.notebook.add(self.passwords_tab, text="Passwords")
        self.notebook.add(self.generate_tab, text="Generate Password")

        # Setup the passwords tab
        self.setup_passwords_tab()

        # Setup the generate password tab
        self.setup_generate_tab()

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_container.columnconfigure(0, weight=1)
        self.main_container.rowconfigure(0, weight=1)

    def setup_passwords_tab(self):
        # Create treeview for password list
        self.tree = ttk.Treeview(self.passwords_tab, columns=('Service', 'Username'), show='headings')
        self.tree.heading('Service', text='Service')
        self.tree.heading('Username', text='Username')
        self.tree.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.passwords_tab, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=2, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Buttons frame
        btn_frame = ttk.Frame(self.passwords_tab)
        btn_frame.grid(row=1, column=0, columnspan=3, pady=10)

        ttk.Button(btn_frame, text="Add Password", command=self.show_add_password_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="View Password", command=self.show_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Password", command=self.delete_password).pack(side=tk.LEFT, padx=5)

        # Configure grid weights
        self.passwords_tab.columnconfigure(0, weight=1)
        self.passwords_tab.rowconfigure(0, weight=1)

        # Load existing passwords
        self.refresh_password_list()

    def setup_generate_tab(self):
        # Password length frame
        length_frame = ttk.Frame(self.generate_tab)
        length_frame.grid(row=0, column=0, pady=10, sticky=tk.W)

        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT)
        self.length_var = tk.StringVar(value="16")
        length_entry = ttk.Entry(length_frame, textvariable=self.length_var, width=5)
        length_entry.pack(side=tk.LEFT, padx=5)

        # Generated password frame
        password_frame = ttk.Frame(self.generate_tab)
        password_frame.grid(row=1, column=0, pady=10, sticky=tk.W)

        self.generated_password_var = tk.StringVar()
        ttk.Entry(password_frame, textvariable=self.generated_password_var, width=40).pack(side=tk.LEFT, padx=5)

        # Buttons
        btn_frame = ttk.Frame(self.generate_tab)
        btn_frame.grid(row=2, column=0, pady=10, sticky=tk.W)

        ttk.Button(btn_frame, text="Generate", command=self.generate_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Password", command=self.save_generated_password).pack(side=tk.LEFT, padx=5)

    def save_generated_password(self):
        generated_password = self.generated_password_var.get()
        if not generated_password:
            messagebox.showwarning("No Password", "Please generate a password first.")
            return

        # Create save password dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Save Generated Password")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()

        # Service
        ttk.Label(dialog, text="Service:").grid(row=0, column=0, pady=5, padx=5, sticky=tk.W)
        service_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=service_var).grid(row=0, column=1, pady=5, padx=5, sticky=(tk.W, tk.E))

        # Username
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, pady=5, padx=5, sticky=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=username_var).grid(row=1, column=1, pady=5, padx=5, sticky=(tk.W, tk.E))

        # Password (pre-filled and read-only)
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, pady=5, padx=5, sticky=tk.W)
        password_var = tk.StringVar(value=generated_password)
        ttk.Entry(dialog, textvariable=password_var, state='readonly').grid(row=2, column=1, pady=5, padx=5,
                                                                            sticky=(tk.W, tk.E))

        def save():
            service = service_var.get()
            username = username_var.get()
            password = password_var.get()

            if not all([service, username]):
                messagebox.showerror("Error", "Service and username are required!")
                return

            if self.pm.add_password(service, username, password):
                self.refresh_password_list()
                dialog.destroy()
                messagebox.showinfo("Success", "Password saved successfully!")
                # Switch to passwords tab
                self.notebook.select(0)
            else:
                messagebox.showerror("Error", "Failed to save password!")

        # Save button
        ttk.Button(dialog, text="Save", command=save).grid(row=3, column=0, columnspan=2, pady=20)

        # Configure grid weights
        dialog.columnconfigure(1, weight=1)

    def show_add_password_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()

        # Service
        ttk.Label(dialog, text="Service:").grid(row=0, column=0, pady=5, padx=5, sticky=tk.W)
        service_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=service_var).grid(row=0, column=1, columnspan=2, pady=5, padx=5,
                                                         sticky=(tk.W, tk.E))

        # Username
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, pady=5, padx=5, sticky=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=username_var).grid(row=1, column=1, columnspan=2, pady=5, padx=5,
                                                          sticky=(tk.W, tk.E))

        # Password with Generate button
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, pady=5, padx=5, sticky=tk.W)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, textvariable=password_var, show="*")
        password_entry.grid(row=2, column=1, pady=5, padx=5, sticky=(tk.W, tk.E))

        def toggle_password():
            current = password_entry.cget('show')
            password_entry.config(show='' if current == '*' else '*')

        def generate_and_set():
            password = self.pm.generate_password(16)
            password_var.set(password)
            password_entry.config(show='')
            dialog.after(2000, lambda: password_entry.config(show='*'))

        # Add Generate button
        ttk.Button(dialog, text="Generate", command=generate_and_set).grid(row=2, column=2, pady=5, padx=5, sticky=tk.W)

        # Add Show/Hide toggle
        ttk.Button(dialog, text="Show/Hide", command=toggle_password).grid(row=2, column=3, pady=5, padx=5, sticky=tk.W)

        def save():
            service = service_var.get()
            username = username_var.get()
            password = password_var.get()

            if not all([service, username, password]):
                messagebox.showerror("Error", "All fields are required!")
                return

            is_valid, message = self.pm.validate_password(password)
            if not is_valid:
                messagebox.showerror("Invalid Password", message)
                return

            if self.pm.add_password(service, username, password):
                self.refresh_password_list()
                dialog.destroy()
                messagebox.showinfo("Success", "Password saved successfully!")
            else:
                messagebox.showerror("Error", "Failed to save password!")

        ttk.Button(dialog, text="Save", command=save).grid(row=3, column=0, columnspan=4, pady=20)

        dialog.columnconfigure(1, weight=1)

    def show_password(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a password to view.")
            return

        item = self.tree.item(selection[0])
        service = item['values'][0]
        entry = self.pm.get_password(service)

        if entry:
            # Create a custom dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("Password Details")
            dialog.geometry("400x200")
            dialog.transient(self.root)
            dialog.grab_set()

            # Service label
            ttk.Label(dialog, text="Service:").grid(row=0, column=0, pady=5, padx=5, sticky=tk.W)
            ttk.Label(dialog, text=service).grid(row=0, column=1, pady=5, padx=5, sticky=tk.W)

            # Username row
            ttk.Label(dialog, text="Username:").grid(row=1, column=0, pady=5, padx=5, sticky=tk.W)
            ttk.Label(dialog, text=entry['username']).grid(row=1, column=1, pady=5, padx=5, sticky=tk.W)

            def copy_username():
                self.root.clipboard_clear()
                self.root.clipboard_append(entry['username'])
                messagebox.showinfo("Success", "Username copied to clipboard!")

            ttk.Button(dialog, text="Copy", command=copy_username).grid(row=1, column=2, pady=5, padx=5)

            # Password row
            ttk.Label(dialog, text="Password:").grid(row=2, column=0, pady=5, padx=5, sticky=tk.W)
            ttk.Label(dialog, text=entry['password']).grid(row=2, column=1, pady=5, padx=5, sticky=tk.W)

            def copy_password():
                self.root.clipboard_clear()
                self.root.clipboard_append(entry['password'])
                messagebox.showinfo("Success", "Password copied to clipboard!")

            ttk.Button(dialog, text="Copy", command=copy_password).grid(row=2, column=2, pady=5, padx=5)

            # Close button
            ttk.Button(dialog, text="Close", command=dialog.destroy).grid(row=3, column=0, columnspan=3, pady=20)

            # Configure grid weights
            dialog.columnconfigure(1, weight=1)


    def delete_password(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a password to delete.")
            return

        item = self.tree.item(selection[0])
        service = item['values'][0]

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for {service}?"):
            if service in self.pm.passwords:
                del self.pm.passwords[service]
                self.pm.save_passwords()
                self.refresh_password_list()
                messagebox.showinfo("Success", "Password deleted successfully!")

    def refresh_password_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for service, details in self.pm.passwords.items():
            self.tree.insert('', 'end', values=(service, details['username']))

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 8:
                messagebox.showwarning("Invalid Length", "Password length must be at least 8 characters.")
                return

            password = self.pm.generate_password(length)
            self.generated_password_var.set(password)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for password length.")

    def copy_to_clipboard(self):
        password = self.generated_password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Please generate a password first.")


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()