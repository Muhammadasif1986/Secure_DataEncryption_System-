import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import time
import os
from datetime import datetime

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
DATA_FILE = "encrypted_data.json"
MASTER_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()  # For demo purposes only

# Generate or load encryption key
def get_encryption_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return open("secret.key", "rb").read()

KEY = get_encryption_key()
cipher = Fernet(KEY)

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = False
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Load or initialize stored data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# Security functions
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"

def verify_passkey(passkey, stored_hash):
    salt, stored_hashed = stored_hash.split('$')
    new_hash = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()
    return new_hash == stored_hashed

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit UI
st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")

# Navigation
def main_page():
    st.title("🔒 Secure Data Encryption System")
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("""
    Use this app to **securely store and retrieve data** using unique passkeys.
    
    ### Features:
    - Military-grade encryption (AES-128)
    - Secure passkey storage with PBKDF2 hashing
    - Brute-force protection with account lockout
    - Persistent data storage
    """)

def store_data_page():
    st.title("🔒 Secure Data Encryption System")
    st.subheader("📂 Store Data Securely")
    
    user_id = st.text_input("Enter a unique identifier for your data:")
    user_data = st.text_area("Enter sensitive data to store:")
    passkey = st.text_input("Enter a strong passkey:", type="password")
    passkey_confirm = st.text_input("Confirm passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if not all([user_id, user_data, passkey, passkey_confirm]):
            st.error("⚠️ All fields are required!")
        elif passkey != passkey_confirm:
            st.error("⚠️ Passkeys do not match!")
        elif len(passkey) < 8:
            st.error("⚠️ Passkey must be at least 8 characters long!")
        elif user_id in stored_data:
            st.error("⚠️ This identifier is already in use!")
        else:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            
            stored_data[user_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
                "timestamp": str(datetime.now())
            }
            
            save_data(stored_data)
            st.success("✅ Data stored securely!")
            st.balloons()

def retrieve_data_page():
    st.title("🔒 Secure Data Encryption System")
    
    if st.session_state.locked_out:
        remaining_time = LOCKOUT_TIME - (time.time() - st.session_state.lockout_time)
        if remaining_time > 0:
            st.error(f"🔒 Account locked! Please try again in {int(remaining_time/60)} minutes and {int(remaining_time%60)} seconds.")
            return
        else:
            st.session_state.locked_out = False
            st.session_state.failed_attempts = 0
    
    st.subheader("🔍 Retrieve Your Data")
    
    user_id = st.selectbox("Select your data identifier:", [""] + list(stored_data.keys()))
    passkey = st.text_input("Enter your passkey:", type="password")
    
    if st.button("Decrypt"):
        if not user_id or not passkey:
            st.error("⚠️ Both fields are required!")
        elif user_id not in stored_data:
            st.error("⚠️ Identifier not found!")
        else:
            data = stored_data[user_id]
            
            if verify_passkey(passkey, data["passkey"]):
                decrypted_text = decrypt_data(data["encrypted_text"])
                st.success("✅ Data decrypted successfully!")
                st.text_area("Decrypted Data:", value=decrypted_text, height=200)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                remaining_attempts = MAX_ATTEMPTS - st.session_state.failed_attempts
                
                if remaining_attempts > 0:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")
                else:
                    st.session_state.locked_out = True
                    st.session_state.lockout_time = time.time()
                    st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")

def login_page():
    st.title("🔒 Secure Data Encryption System")
    st.subheader("🔑 Reauthorization Required")
    
    if st.session_state.locked_out:
        remaining_time = LOCKOUT_TIME - (time.time() - st.session_state.lockout_time)
        if remaining_time > 0:
            st.error(f"🔒 Account locked! Please try again in {int(remaining_time/60)} minutes and {int(remaining_time%60)} seconds.")
            return
    
    login_pass = st.text_input("Enter Master Password:", type="password")
    
    if st.button("Login"):
        if hashlib.sha256(login_pass.encode()).hexdigest() == MASTER_PASSWORD_HASH:
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.session_state.locked_out = False
            st.success("✅ Reauthorized successfully!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Incorrect password!")

# App routing
if st.session_state.locked_out and st.session_state.failed_attempts >= MAX_ATTEMPTS:
    login_page()
else:
    pages = {
        "Home": main_page,
        "Store Data": store_data_page,
        "Retrieve Data": retrieve_data_page,
        "Login": login_page
    }
    
    st.sidebar.title("Navigation")
    selection = st.sidebar.radio("Go to", list(pages.keys()))
    
    if selection == "Retrieve Data" and st.session_state.failed_attempts >= MAX_ATTEMPTS:
        login_page()
    else:
        pages[selection]()
    
    st.sidebar.markdown("---")
    st.sidebar.info("""
    **Security Tips:**
    - Use a strong, unique passkey
    - Never share your passkey
    - Remember your data identifier
    """)