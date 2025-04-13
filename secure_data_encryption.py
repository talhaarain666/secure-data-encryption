import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
import base64
import uuid


# Use a consistent encryption key (e.g., from a secret)
@st.cache_resource
def get_cipher():
    master_key = hashlib.sha256(b"my-super-secret-key").digest()  # Change to your own strong secret
    key = base64.urlsafe_b64encode(master_key)
    return Fernet(key)

cipher = get_cipher()
DATA_FILE = "secure_store.json"

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "navigation" not in st.session_state:
    st.session_state.navigation = "Home"
if "username" not in st.session_state:
    st.session_state.username = None

# Load stored data from file
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        try:
            st.session_state.stored_data = json.load(f)
        except:
            st.session_state.stored_data = {}

# Ensure "users" key exists
if "users" not in st.session_state.stored_data:
    st.session_state.stored_data["users"] = {}


# Password hashing with salt
def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100_000)
    return {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(hashed).decode()
    }


# Encrypt / Decrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    user_data = st.session_state.stored_data["users"][st.session_state.username]["data"]

    # Find entry with matching encrypted_text
    found_entry = None
    for entry_id, entry in user_data.items():
        if entry["encrypted_text"] == encrypted_text:
            found_entry = entry
            break

    if not found_entry:
        st.session_state.failed_attempts += 1
        return None

    salt = base64.b64decode(found_entry["salt"])
    expected_hash = found_entry["passkey_hash"]
    user_hash_obj = hash_passkey(passkey, salt)

    if user_hash_obj["hash"] == expected_hash:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None


def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f, indent=4)


# Auth Functions
def is_logged_in():
    return st.session_state.username is not None

def register_user(username, password):
    users = st.session_state.stored_data["users"]
    if username in users:
        return False, "Username already exists."

    hashed = hash_passkey(password)
    users[username] = {
        "password_hash": hashed["hash"],
        "salt": hashed["salt"],
        "data": {}
    }
    save_data()
    return True, "User registered successfully."

def login_user(username, password):
    users = st.session_state.stored_data["users"]
    user = users.get(username)
    if not user:
        return False, "User not found."

    salt = base64.b64decode(user["salt"])
    hashed = hash_passkey(password, salt)
    if hashed["hash"] == user["password_hash"]:
        st.session_state.username = username
        return True, "Logged in successfully."
    return False, "Invalid password."


# Streamlit UI
st.title("🔐 Secure Data Encryption System")

# Sidebar
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.navigation))
st.session_state.navigation = choice

if st.session_state.username:
    st.sidebar.markdown(f"👤 Logged in as: `{st.session_state.username}`")
    if st.sidebar.button("Logout"):
        st.session_state.username = None
        st.session_state.navigation = "Login"
        st.success("👋 Logged out successfully.")
        st.rerun()

# Pages
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("This app allows you to securely store and retrieve sensitive data using encryption and passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    if not is_logged_in():
        st.warning("Please login to access this page.")
        st.stop()

    text = st.text_area("Enter Data to Encrypt")
    passkey = st.text_input("Create a Passkey", type="password")

    if st.button("Encrypt & Store"):
        if text and passkey:
            hashed_obj = hash_passkey(passkey)
            encrypted = encrypt_data(text)
            entry_id = str(uuid.uuid4())
            user_data = st.session_state.stored_data["users"][st.session_state.username]["data"]
            user_data[entry_id] = {
                "encrypted_text": encrypted,
                "passkey_hash": hashed_obj["hash"],
                "salt": hashed_obj["salt"]
            }
            save_data()
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please fill out both fields.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    if not st.session_state.authorized:
        st.warning("🔒 Reauthorization required. Redirecting to Login...")
        st.session_state.navigation = "Login"
        st.rerun()

    if not is_logged_in():
        st.warning("Please login to access this page.")
        st.stop()

    st.markdown("### 🔐 Stored Encrypted Entries")
    user_data = st.session_state.stored_data["users"][st.session_state.username]["data"]
    if user_data:
        for entry_id, entry in user_data.items():
            st.code(entry["encrypted_text"], language="text")
    else:
        st.info("No encrypted data found.")

    encrypted_text = st.text_area("Paste Encrypted Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.session_state.navigation = "Login"
                    st.warning("🚫 Too many failed attempts! Reauthorization required.")
                    st.rerun()
        else:
            st.error("⚠️ Fill both fields!")

elif choice == "Login":
    st.subheader("🔑 User Login or Registration")
    login_tab, register_tab = st.tabs(["Login", "Register"])

    with login_tab:
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")

        if st.button("Login"):
            success, message = login_user(username, password)
            if success:
                st.success(message)
                st.session_state.navigation = "Home"
                st.rerun()
            else:
                st.error(message)

    with register_tab:
        new_user = st.text_input("New Username", key="new_user")
        new_pass = st.text_input("New Password", type="password", key="new_pass")

        if st.button("Register"):
            success, message = register_user(new_user, new_pass)
            if success:
                st.success(message)
            else:
                st.error(message)
