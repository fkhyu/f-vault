from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import argon2
import os
import json
import time
from termcolor import colored, cprint
from getpass import getpass

session_started = False
session_start_time = None
session_password = None

ASCII_logo = r"""
▄▖  ▖▖    ▜ ▗ 
▙▖▄▖▌▌▀▌▌▌▐ ▜▘
▌   ▚▘█▌▙▌▐▖▐▖
"""


def cntr(text: str, h: bool, v: bool, text_rows: int, bottomPadding: bool) -> str:
    lines = text.split('\n')
    terminal_size = os.get_terminal_size()
    terminal_width = terminal_size[0]
    if v:
        empty_lines = terminal_size[1] - len(lines)
        top_padding = (empty_lines // 2) - (text_rows // 2)
        if bottomPadding:
            bottom_padding = empty_lines - top_padding
        else:
            bottom_padding = 0
        lines = [''] * top_padding + lines + [''] * bottom_padding
        text = '\n'.join(lines)
    if h:
        lines = text.split('\n')
        for i in range(len(lines)):
            line_length = len(lines[i])
            if line_length < terminal_width:
                padding = (terminal_width - line_length) // 2
                lines[i] = ' ' * padding + lines[i]
        text = '\n'.join(lines)
    return text

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def register():
    print(cntr(f"Welcome to {colored('F-Vault', 'blue')}!", True, False, 2, False))
    first = getpass(cntr(f"{colored('Enter your master password to start:', 'white')}\n", True, False, 2, True))
    clear()
    confirmation = getpass(cntr(f"{colored('Confirm master password:', 'white')}\n", True, True, 1, True))

    if first != confirmation:
        print("Passwords do not match. Please try again.")
        return
    
    ph = argon2.PasswordHasher()
    hashed_password = ph.hash(first)
    with open("master.key", "wb") as f:
        f.write(hashed_password.encode())
    print("Master password set successfully.")

    login()


def login():
    print(cntr(f"           Welcome back to {colored('F-Vault', 'blue')}!", True, True, 2, False))
    print(cntr(f"{colored('         Enter your master password:', 'white')}\n", True, False, 2, True))
    entered_password = getpass(cntr("", True, False, 0, True))

    with open("master.key", "rb") as f:
        stored_hashed_password = f.read().decode()

    ph = argon2.PasswordHasher()
    try: 
        ph.verify(stored_hashed_password, entered_password)
        global session_started, session_start_time, session_password
        session_started = True
        session_start_time = os.times()
        session_password = entered_password
        print("Login successful!")
        clear()
        home()
    except argon2.exceptions.VerifyMismatchError:
        print("Incorrect password. Access denied.")

def derive_key(password: str, salt: bytes) -> bytes:
    return argon2.low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64*1024,
        parallelism=2,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )

def encrypt_vault(vault_data: dict, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(vault_data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext

def decrypt_vault(blob: bytes, password: str) -> bytes: 
    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())


def home():
    menu_text = """
==--==--== Home ==--==--==

  1. Add New Password     
  2. My Passwords         
  3. Logout               
          
==--==--==--==--==--==--==
          """ 
    if not session_started:
        print("Please log in first.")
        return
    print(cntr(ASCII_logo, True, True, 10, False))
    print(cntr(menu_text, True, False, 0, True))
    
    handle_home_choice()


def handle_home_choice():
    choice = input("").strip()
    
    if choice == "1":
        add_new_password()
    elif choice == "2":
        my_passwords()
    elif choice == "3":
        logout()

def logout():
    clear()
    global session_started
    session_started = False
    session_start_time = None
    print("You have been logged out.")
    exit()

def add_new_password():
    clear()
    if not session_started:
        print("Please log in first.")
        return
    
    title = input("Enter the title for the password (e.g. Gmail):\n")
    username = input(f"Enter the username/email associated with {title}:\n")
    password = getpass(f"Enter the password for {title}:\n")

    vault = {}
    if os.path.exists("vault.bin"):
        with open("vault.bin", "rb") as f:
            blob = f.read()
            try:
                vault = decrypt_vault(blob, session_password)
            except Exception as e:
                print("Failed to decrypt vault. Cannot add new password.")
                return
            
        vault["entries"].append({
            'title': title,
            'username': username,
            'password': password
        })
    else:
        vault = {
            "entries": [{
                'title': title,
                'username': username,
                'password': password
            }]
        }

    encrypted_blob = encrypt_vault(vault, session_password)
    with open("vault.bin", "wb") as f:
        f.write(encrypted_blob)

    clear()
    print(f"Password for {title} added successfully.")
    time.sleep(1)
    clear()
    home()


def my_passwords():
    clear()
    if not session_started:
        print("Please log in first.")
        return
    
    if not os.path.exists("vault.bin"):
        print("No passwords stored yet.")
        return
    
    with open("vault.bin", "rb") as f:
        blob = f.read()

        try:
            vault = decrypt_vault(blob, session_password)
        except Exception as e:
            print("Failed to decrypt vault. Cannot display passwords.")
            return
        
        print("Your stored passwords:")

        for entry in vault["entries"]:
            print(f"Title: {entry['title']}")
            print(f"Username/Email: {entry['username']}")
            print(f"Password: {entry['password']}")
            print("-"*20)

        input("Press Enter to return to home...")
        clear()
        home()




if __name__ == "__main__":
    clear()
    cprint(cntr(ASCII_logo, True, True, 3, True), 'blue')
    time.sleep(2)
    clear()
    if not os.path.exists("master.key"):
        register()
    else:
        login()