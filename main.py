#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import argon2
import os
import json
import time
from termcolor import colored, cprint
from getpass import getpass
from bullet import Bullet, colors
import pyperclip
import base64

session_started = False
session_start_time = None
session_password = None

ASCII_logo = r"""
▄▖  ▖▖    ▜ ▗ 
▙▖▄▖▌▌▀▌▌▌▐ ▜▘
▌   ▚▘█▌▙▌▐▖▐▖
"""

large_ascii_logo = r"""
`7MM^^^YMM `7MMF'   `7MF'                `7MM   mm    
  MM    `7   `MA     ,V                    MM   MM    
  MM   d      VM:   ,V ,6"Yb.`7MM  `7MM    MM mmMMmm  
  MM""MM       MM.  M'8)   MM  MM    MM    MM   MM    
  MM   Y mmmmm `MM A'  ,pm9MM  MM    MM    MM   MM    
  MM            :MM;  8M   MM  MM    MM    MM   MM    
.JMML.           VF   `Moo9^Yo.`Mbod"YML..JMML. `Mbmo 
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
    print(cntr(f"          Welcome to {colored('F-Vault', 'cyan')}!", True, True, 2, False))
    print(cntr("         Enter your master password to start:\n", True, False, 2, True))
    first = getpass(cntr("", True, False, 0, True))
    clear()
    confirmation = getpass(cntr("        Confirm master password:\n", True, True, 0, False))

    if first != confirmation:
        print("Passwords do not match. Please try again.")
        return
    
    ph = argon2.PasswordHasher()
    hashed_password = ph.hash(first)
    with open("master.key", "wb") as f:
        f.write(hashed_password.encode())
    clear()
    print(cntr("Master password set successfully.", True, True, 0, True))
    time.sleep(1)
    clear()
    login()


def login():
    print(cntr("           Welcome back to F-Vault!", True, True, 2, False))
    print(cntr("         Enter your master password:\n", True, False, 2, True))
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
-==--==--== Home ==--==--==-

1. Add New Password         
2. My Passwords             
3. Update Password          
4. Remove Password          
9. Change Master Password   
0. Logout                   

-==--==--==--==--==--==--==-
          """ 
    if not session_started:
        print("Please log in first.")
        return
    print(cntr(ASCII_logo, True, True, 15, False))
    print(cntr(menu_text, True, False, 0, True))
    
    handle_home_choice()


def handle_home_choice():    
    choice = input(cntr("", True, False, 0, False)).strip()
    
    if choice == "1":
        add_new_password()
    elif choice == "2":
        my_passwords()
    elif choice == "3":
        update_password()
    elif choice == "4":
        remove_password()
    elif choice == "9":
        change_master_password()
    elif choice == "0":
        logout()
    elif choice == "67":
        secret_function()

def logout():
    clear()
    global session_started
    session_started = False
    session_start_time = None
    session_password = None
    print("You have been logged out.")
    exit()

def update_password():
    if not session_started:
        login()
        return
    
    if not os.path.exists("vault.bin"):
        print(cntr("No passwords stored yet.", True, True, 0, True))
        time.sleep(1)
        clear()
        home()
        return
    
    clear()

    with open("vault.bin", "rb") as f:
        blob = f.read()

        try:
            vault = decrypt_vault(blob, session_password)
        except Exception as e:
            cprint(cntr("Failed to decrypt vault. Cannot update passwords.", True, True, 0, True), "red")
            time.sleep(1)
            clear()
            home()
            return
        
    passwords = []

    for entry in vault["entries"]:
        passwords.append(json.dumps(entry))

    choices = ["Back to Home"] + [json.loads(p)['title'] + " (" + json.loads(p)['username'] + ")" for p in passwords]

    cli = Bullet(
        prompt = "Select a password to update:",
        choices = choices,
        margin = 1,
        shift = 1,
        bullet = "➤"
    )

    selected_password = cli.launch()

    if selected_password == "Back to Home":
        clear()
        home()
        return
    
    selected_index = choices.index(selected_password)

    new_password = getpass(cntr("Enter the new password:\n", True, True, 0, True))
    vault["entries"][selected_index - 1]['password'] = new_password

    encrypted_blob = encrypt_vault(vault, session_password)

    with open("vault.bin", "wb") as f:
        f.write(encrypted_blob)

    clear()
    cprint(cntr("Password updated successfully!", True, True, 0, True), 'green')
    time.sleep(1)
    clear()
    home()

def remove_password():
    clear()
    if not session_started:
        login()
        return
    
    if not os.path.exists("vault.bin"):
        print(cntr("No passwords stored yet.", True, True, 0, True))
        time.sleep(1)
        clear()
        home()
        return
    
    with open("vault.bin", "rb") as f:
        blob = f.read()

        try: 
            vault = decrypt_vault(blob, session_password)
        except Exception as e:
            cprint(cntr("Failed to decrypt vault. Cannot remove passwords.", True, True, 0, True), "red")
            time.sleep(1)
            clear()
            home()
            return
        
        passwords = []

        for entry in vault["entries"]:
            passwords.append(json.dumps(entry))

        choices = ["Back to Home"] + [json.loads(p)['title'] + " (" + json.loads(p)['username'] + ")" for p in passwords]

        cli = Bullet(
            prompt = "Select a password to remove:",
            choices = choices,
            margin = 1,
            shift = 1,
            bullet = "➤",
            background_on_switch = colors.background['red'],
            word_on_switch = colors.foreground['white']
        )

        selected_password = cli.launch()
        if selected_password == "Back to Home":
            clear()
            home()
            return
        selected_index = choices.index(selected_password)

        confirmation = input(cntr(f"Are you sure you want to remove the password entry '{selected_password}'? (y/n): ", True, False, 0, True)).strip().lower()
        if confirmation != 'y':
            clear()
            print(cntr("Cancelled.", True, True, 0, True))
            time.sleep(1)
            clear()
            home()
            return

        del vault['entries'][selected_index - 1]

        encrypted_blob = encrypt_vault(vault, session_password)
        with open("vault.bin", "wb") as f:
            f.write(encrypted_blob)

        clear()
        print(cntr(f"The password entry '{selected_password}' has been removed.", True, True, 0, True))
        time.sleep(1)
        clear()
        home()

def add_new_password():
    clear()
    if not session_started:
        login()
        return
    
    # ask as long as values are empty

    while True:
        print(cntr("Enter the title (e.g. Gmail):\n", True, True, 0, False))
        title = input(cntr("", True, False, 0, False))
        if title.strip() == "":
            print("Title cannot be empty.")
            continue
        break
    
    clear()

    while True:
        print(cntr("Enter the username/email:\n", True, True, 0, False))
        username = input(cntr("", True, False, 0, False))
        if username.strip() == "":
            print("Username/Email cannot be empty.")
            continue
        break

    clear()

    while True:
        password = getpass(cntr("Enter the password:\n", True, True, 0, True))
        if password.strip() == "":
            print("Password cannot be empty.")
            continue
        break

    clear()

    vault = {}
    if os.path.exists("vault.bin"):
        with open("vault.bin", "rb") as f:
            blob = f.read()
            try:
                vault = decrypt_vault(blob, session_password)
            except Exception as e:
                print("Failed to decrypt vault. Cannot add new password.")
                time.sleep(1)
                clear()
                home()
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
    cprint(cntr(f"Password added successfully!", True, True, 0, True), 'green')
    time.sleep(1)
    clear()
    home()


def my_passwords():
    clear()
    if not session_started:
        print("Please log in first.")
        return
    
    if not os.path.exists("vault.bin"):
        print(cntr("No passwords stored yet.", True, True, 0, True))
        time.sleep(1)
        clear()
        home()
        return
    
    with open("vault.bin", "rb") as f:
        blob = f.read()

        try:
            vault = decrypt_vault(blob, session_password)
        except Exception as e:
            print("Failed to decrypt vault. Cannot display passwords.")
            time.sleep(1)
            clear()
            home()
            return
        
        # TODO: implement bullet menu for better nav + hide pass and copy on selection

        passwords = []

        for entry in vault["entries"]:
            passwords.append(json.dumps(entry))

        choices = ["Back to Home"] + [json.loads(p)['title'] + " (" + json.loads(p)['username'] + ")" for p in passwords]

        cli = Bullet(
            prompt = "Select a password to copy:\n",
            choices = choices,
            margin = 1,
            shift = 1,
            bullet = "➤"
        )

        selected_password = cli.launch()
        if selected_password == "Back to Home":
            clear()
            home()
            return
        selected_index = choices.index(selected_password)
        password = vault["entries"][selected_index - 1]['password']

        pyperclip.copy(password)

        clear()
        cprint(cntr("Copied!", True, True, 0, True), 'green')
        time.sleep(1)
        clear()
        home()

def change_master_password():
    global session_password
    clear()
    if not session_started:
        login()
        return
    
    if not os.path.exists("master.key"):
        register()

    print(cntr("Enter your current master password:", True, True, 0, True))
    current_password = getpass(cntr("", True, False, 0, True))

    if current_password != session_password:
        cprint(cntr("Incorrect current master password.", True, True, 0, True), "red")
        time.sleep(1)
        clear()
        home()
        return
    
    new_password = getpass(cntr("Enter your new master password:\n", True, True, 0, True))
    confirm_password = getpass(cntr("Confirm your new master password:\n", True, True, 0, True))

    while True:
        if new_password != confirm_password:
            cprint(cntr("Passwords do not match. Please try again.", True, True, 0, True), "red")
            time.sleep(1)
            clear()
            new_password = getpass(cntr("Enter your new master password:\n", True, True, 0, True))
            confirm_password = getpass(cntr("Confirm your new master password:\n", True, True, 0, True))
        else:
            break

    vault = decrypt_vault(open("vault.bin", "rb").read(), session_password)
    encrypted_blob = encrypt_vault(vault, new_password)
    with open("vault.bin", "wb") as f:
        f.write(encrypted_blob)

    ph = argon2.PasswordHasher()
    hashed_password = ph.hash(new_password)
    with open("master.key", "wb") as f:
        f.write(hashed_password.encode())

    session_password = new_password
    clear()
    cprint(cntr("Master password changed successfully.", True, True, 0, True), "green")
    time.sleep(1)
    clear()
    home()


def secret_function():
    the_message = "IOKWiOKWiOKWiOKWiOKWiOKWiOKVl+KWiOKWiOKWiOKWiOKWiOKWiOKWiOKVlwrilojilojilZTilZDilZDilZDilZDilZ3ilZrilZDilZDilZDilZDilojilojilZEK4paI4paI4paI4paI4paI4paI4paI4pWXICAgIOKWiOKWiOKVlOKVnQrilojilojilZTilZDilZDilZDilojilojilZcgIOKWiOKWiOKVlOKVnSAK4pWa4paI4paI4paI4paI4paI4paI4pWU4pWdICDilojilojilZEgIAog4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWdICAg4pWa4pWQ4pWdICA="
    the_message = base64.b64decode(the_message).decode()
    clear()
    print(cntr(the_message, True, True, 0, True))
    time.sleep(3)
    clear()
    home()


if __name__ == "__main__":
    clear()
    cprint(cntr(large_ascii_logo, True, True, 0, True), 'cyan')
    time.sleep(1)
    clear()
    if not os.path.exists("master.key"):
        register()
    else:
        login()