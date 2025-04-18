import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64

# --- Utility Functions ---

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_fernet_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_data(text, passkey):
    key = generate_fernet_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(text.encode())

def decrypt_data(encrypted_text, passkey):
    try:
        key = generate_fernet_key(passkey)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_text).decode()
    except:
        return None

# --- Session State Initialization ---

if 'users' not in st.session_state:
    st.session_state.users = {}  # {username: hashed_password}

if 'user_data' not in st.session_state:
    st.session_state.user_data = {}  # {username: {data_name: {"encrypted_text": ..., "passkey_hash": ...}}}

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if 'current_page' not in st.session_state:
    st.session_state.current_page = "auth"

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Pages ---

def show_auth_page():
    st.title("🔐 Secure Data System")

    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        with st.form("Login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            if st.form_submit_button("Login"):
                if username in st.session_state.users:
                    if st.session_state.users[username] == hash_password(password):
                        st.session_state.current_user = username
                        st.session_state.failed_attempts = 0
                        if username not in st.session_state.user_data:
                            st.session_state.user_data[username] = {}
                        st.session_state.current_page = "home"
                        st.rerun()
                    else:
                        st.error("Incorrect password")
                else:
                    st.error("Username not found. Please register!")

    with tab2:
        with st.form("Register"):
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            confirm_pass = st.text_input("Confirm Password", type="password")

            if st.form_submit_button("Register"):
                if not new_user or not new_pass or not confirm_pass:
                    st.error("All fields are required")
                elif new_pass != confirm_pass:
                    st.error("Passwords don't match")
                elif new_user in st.session_state.users:
                    st.error("Username already exists")
                else:
                    st.session_state.users[new_user] = hash_password(new_pass)
                    st.session_state.user_data[new_user] = {}
                    st.session_state.current_user = new_user
                    st.session_state.current_page = "home"
                    st.success("Registration successful!")
                    st.rerun()

def show_home():
    st.title(f"Welcome, {st.session_state.current_user}!")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data"):
            st.session_state.current_page = "store"
    with col2:
        if st.button("Retrieve Data"):
            st.session_state.current_page = "retrieve"

    if st.button("Logout"):
        st.session_state.current_user = None
        st.session_state.current_page = "auth"
        st.rerun()

def show_store_page():
    st.title("🔒 Store Encrypted Data")

    data_name = st.text_input("Data Identifier (Unique Name)")
    secret_data = st.text_area("Data to Encrypt")
    passkey = st.text_input("Passkey (used to encrypt & decrypt)", type="password")

    if st.button("Encrypt & Store"):
        if data_name and secret_data and passkey:
            if data_name in st.session_state.user_data[st.session_state.current_user]:
                st.error("Data identifier already exists")
            else:
                encrypted = encrypt_data(secret_data, passkey)
                passkey_hash = hash_password(passkey)
                st.session_state.user_data[st.session_state.current_user][data_name] = {
                    "encrypted_text": encrypted,
                    "passkey_hash": passkey_hash
                }
                st.success(f"Data '{data_name}' stored securely!")
        else:
            st.error("All fields are required")

    if st.button("Back to Home"):
        st.session_state.current_page = "home"

def show_retrieve_page():
    st.title("🔓 Retrieve Encrypted Data")

    user_data = st.session_state.user_data[st.session_state.current_user]

    if not user_data:
        st.warning("No data stored yet")
        if st.button("Back to Home"):
            st.session_state.current_page = "home"
    else:
        data_name = st.selectbox("Select data to decrypt", list(user_data.keys()))
        passkey = st.text_input("Enter passkey to decrypt", type="password")

        if st.button("Decrypt Data"):
            record = user_data[data_name]
            if hash_password(passkey) == record["passkey_hash"]:
                decrypted = decrypt_data(record["encrypted_text"], passkey)
                if decrypted:
                    st.success("Decryption successful!")
                    st.text_area("Decrypted Data", decrypted, height=300)
                    st.session_state.failed_attempts = 0
                else:
                    st.error("Decryption failed")
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey! Attempts: {st.session_state.failed_attempts}/3")
                if st.session_state.failed_attempts >= 3:
                    st.warning("Too many failed attempts! Logging out...")
                    st.session_state.current_user = None
                    st.session_state.current_page = "auth"
                    st.session_state.failed_attempts = 0
                    st.rerun()

        if st.button("Back to Home"):
            st.session_state.current_page = "home"

# --- Main ---

def main():
    if st.session_state.current_page == "auth":
        show_auth_page()
    elif st.session_state.current_page == "home":
        show_home()
    elif st.session_state.current_page == "store":
        show_store_page()
    elif st.session_state.current_page == "retrieve":
        show_retrieve_page()

if __name__ == "__main__":
    main()