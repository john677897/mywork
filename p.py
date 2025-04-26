import os
import sqlite3
import base64
import re
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox, Canvas, simpledialog, StringVar, Toplevel
from tkinter.ttk import Progressbar  # Import Progressbar from ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import hashlib

# SQLite setup
conn = sqlite3.connect("file_logs.db")
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file TEXT,
        operation TEXT,
        time TEXT
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT
    )
''')
conn.commit()

# Key derivation from password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def log_operation(file, operation):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO logs (file, operation, time) VALUES (?, ?, ?)", (file, operation, time))
    conn.commit()

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user():
    username = simpledialog.askstring("Register", "Enter a username:")
    if not username:
        return
    password = simpledialog.askstring("Register", "Enter a password:", show='*')
    if not password or not is_strong_password(password):
        messagebox.showerror("Weak Password", "Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.")
        return

    try:
        password_hash = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        messagebox.showinfo("Success", "User registered successfully!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists.")

def login_user():
    username = simpledialog.askstring("Login", "Enter your username:")
    if not username:
        return
    password = simpledialog.askstring("Login", "Enter your password:", show='*')
    if not password:
        return

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result and result[0] == hash_password(password):
        messagebox.showinfo("Success", "Login successful!")
        app.deiconify()  # Show the main application window
    else:
        messagebox.showerror("Error", "Invalid username or password.")

def encrypt_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    password = simpledialog.askstring("Password", "Enter a password to encrypt:", show='*')
    if not password or not is_strong_password(password):
        messagebox.showerror("Weak Password", "Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.")
        return

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        with open(filepath, "rb") as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(filepath, "wb") as file:
                        file.write(salt + encrypted)  # prepend salt to encrypted content
        log_operation(filepath, "Encrypted")
        messagebox.showinfo("Success", f"File encrypted: {os.path.basename(filepath)}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    password = simpledialog.askstring("Password", "Enter the password to decrypt:", show='*')
    if not password:
        return
    try:
        with open(filepath, "rb") as file:
            content = file.read()
        salt = content[:16]
        encrypted = content[16:]
        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        with open(filepath, "wb") as file:
            file.write(decrypted)
        log_operation(filepath, "Decrypted")
        messagebox.showinfo("Success", f"File decrypted: {os.path.basename(filepath)}")
    except Exception as e:
        messagebox.showerror("Decryption Failed", str(e))

def show_logs():
    cursor.execute("SELECT * FROM logs")
    rows = cursor.fetchall()
    log_text = "\n".join([f"{id}. {file} - {operation} - {time}" for id, file, operation, time in rows])
    messagebox.showinfo("Logs", log_text if log_text else "No logs found.")

# Tkinter UI Setup
app = Tk()
app.title("🛡️ Password File Encryptor")
app.geometry("500x400")
app.resizable(False, False)

# Hide the main application window initially
app.withdraw()

canvas = Canvas(app, width=500, height=400)
canvas.pack(fill="both", expand=True)

def draw_gradient():
    for i in range(400):
        r = 255 - i // 2
        g = 100 + i // 5
        b = 200 + i // 10
        hex_color = f"#{r:02x}{g:02x}{b:02x}"
        canvas.create_line(0, i, 500, i, fill=hex_color)

draw_gradient()

def colorful_button(text, command, y):
    return Button(app, text=text, font=("Arial", 12, "bold"), fg="white", bg="#4B0082", activebackground="#9370DB", command=command).place(x=150, y=y, width=200, height=40)

Label(app, text="🔐 Password Encryptor", font=("Helvetica", 20, "bold"), bg="#9370DB", fg="white").place(x=110, y=30)

colorful_button("🗂️ Encrypt File", encrypt_file, 100)
colorful_button("🔓 Decrypt File", decrypt_file, 160)
colorful_button("📋 Show Logs", show_logs, 220)

# User Authentication Buttons
Button(app, text="Register", command=register_user, font=("Arial", 12)).place(x=50, y=300, width=100, height=40)
Button(app, text="Login", command=login_user, font=("Arial", 12)).place(x=350, y=300, width=100, height=40)

# Start the application with the login window
app.deiconify()
app.mainloop()


