import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key (use fixed key for consistent encryption/decryption)
@st.cache_resource
def get_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

cipher = get_cipher()

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "navigation" not in st.session_state:
    st.session_state.navigation = "Home"

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    data_entry = st.session_state.stored_data.get(encrypted_text)

    if data_entry and data_entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.navigation))
st.session_state.navigation = choice  # Keep current page synced

# HOME
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Store and retrieve sensitive data using passkeys and encryption.")

# STORE DATA
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    text = st.text_area("Enter Data to Encrypt")
    passkey = st.text_input("Create a Passkey", type="password")

    if st.button("Encrypt & Store"):
        if text and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(text)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please fill out both fields.")

# RETRIEVE DATA
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Reauthorization required. Redirecting to Login...")
        st.session_state.navigation = "Login"
        st.experimental_rerun()

    st.subheader("🔍 Retrieve Data")
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
                    st.experimental_rerun()
        else:
            st.error("⚠️ Fill both fields!")

# LOGIN
elif choice == "Login":
    st.subheader("🔑 Reauthorize Access")
    login_pass = st.text_input("Enter Master Password", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure method in production
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.session_state.navigation = "Retrieve Data"
            st.success("✅ Access restored! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Invalid master password.")
