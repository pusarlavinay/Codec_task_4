import tkinter as tk
from tkinter import filedialog, messagebox
from encryption import *
from rsa_utils import *
from tkinter  import ttk

# --- Symmetric UI ---
def symmetric_ui(tab):
    tk.Button(tab, text="Generate Fernet Key", command=lambda: [generate_key(), messagebox.showinfo("OK", "Key generated!")]).pack(pady=2)

    pw_frame = tk.Frame(tab); pw_frame.pack(pady=2)
    tk.Label(pw_frame, text="Password:").pack(side="left")
    pw_entry = tk.Entry(pw_frame, show="*"); pw_entry.pack(side="left")
    tk.Button(pw_frame, text="Derive Key", command=lambda: [derive_key_from_password(pw_entry.get()), messagebox.showinfo("OK", "Key derived!")]).pack(side="left")

    txt = tk.Text(tab, height=5, width=50); txt.pack()
    out = tk.Text(tab, height=5, width=50); out.pack()

    def enc_text():
        try:
            key = load_key()
            token = encrypt_text(txt.get("1.0", "end-1c"), key)
            out.delete("1.0", "end"); out.insert("end", token.decode())
        except Exception as e: messagebox.showerror("Error", str(e))

    def dec_text():
        try:
            key = load_key()
            msg = decrypt_text(out.get("1.0", "end-1c").encode(), key)
            txt.delete("1.0", "end"); txt.insert("end", msg)
        except Exception as e: messagebox.showerror("Error", str(e))

    tk.Button(tab, text="Encrypt Text", command=enc_text).pack(pady=2)
    tk.Button(tab, text="Decrypt Text", command=dec_text).pack(pady=2)

    def enc_file():
        fn = filedialog.askopenfilename()
        if fn: 
            encrypt_file(fn, load_key()); messagebox.showinfo("OK", "File encrypted!")

    def dec_file():
        fn = filedialog.askopenfilename()
        if fn: 
            decrypt_file(fn, load_key()); messagebox.showinfo("OK", "File decrypted!")

    tk.Button(tab, text="Encrypt File", command=enc_file).pack(pady=2)
    tk.Button(tab, text="Decrypt File", command=dec_file).pack(pady=2)

# --- RSA UI ---
def rsa_ui(tab):
    tk.Button(tab, text="Generate RSA Keys", command=lambda: [generate_rsa_keypair(), messagebox.showinfo("OK", "RSA Keys generated!")]).pack(pady=2)

    txt = tk.Text(tab, height=5, width=50); txt.pack()
    out = tk.Text(tab, height=5, width=50); out.pack()

    def enc_text():
        try:
            _, pub = load_keys()
            cipher = rsa_encrypt_text(txt.get("1.0", "end-1c"), pub)
            out.delete("1.0", "end"); out.insert("end", cipher)
        except Exception as e: messagebox.showerror("Error", str(e))

    def dec_text():
        try:
            priv, _ = load_keys()
            msg = rsa_decrypt_text(out.get("1.0", "end-1c"), priv)
            txt.delete("1.0", "end"); txt.insert("end", msg)
        except Exception as e: messagebox.showerror("Error", str(e))

    tk.Button(tab, text="Encrypt Text", command=enc_text).pack(pady=2)
    tk.Button(tab, text="Decrypt Text", command=dec_text).pack(pady=2)

# --- Main window ---
root = tk.Tk()
root.title("Advanced Encryption Tool")

nb = ttk.Notebook(root)
sym_tab = tk.Frame(nb); rsa_tab = tk.Frame(nb)
nb.add(sym_tab, text="Symmetric (Fernet)")
nb.add(rsa_tab, text="RSA")
nb.pack(expand=1, fill="both")

symmetric_ui(sym_tab)
rsa_ui(rsa_tab)

root.mainloop()
