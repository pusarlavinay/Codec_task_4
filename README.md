# 🔐 Advanced Encryption Tool

A robust encryption application with a **user-friendly Tkinter GUI** built in Python.  
Supports both **Symmetric (AES/Fernet)** and **Asymmetric (RSA)** encryption for text and files.

---

## 🚀 Features
- Symmetric (Fernet/AES):
  - Generate random keys
  - Derive keys from password (PBKDF2-HMAC-SHA256)
  - Encrypt & Decrypt **text** and **files**
- Asymmetric (RSA):
  - Generate RSA key pairs
  - Save/load private & public keys
  - Encrypt & Decrypt text
- GUI with **Tkinter + ttk Notebook Tabs**
- Secure key storage (`secret.key`)

---

## 📂 Project Structure
advanced_encryption_tool/
│── main.py # GUI Entry point
│── encryption.py # Symmetric encryption functions
│── rsa_utils.py # Asymmetric (RSA) functions
│── secret.key # Auto-generated Fernet key


---

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/advanced_encryption_tool.git
   cd advanced_encryption_tool


Install dependencies:
pip install cryptography
sudo apt install python3-tk   # For GUI

▶️ Usage

Run the tool:
python3 main.py
Symmetric Tab
Generate Fernet Key OR derive from password.
Encrypt/Decrypt text or files.
RSA Tab
Generate RSA key pair.
Save keys for future use.
Encrypt/Decrypt text securely.



Author :

Pusarla Vinay
