from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk

os.system("title DCrypt Console @V1")

class DCrypt(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DCrypt@V1 By Asterfion")
        self.geometry("600x600")
        self.resizable(False, False)

        ctk.set_appearance_mode("green")
        ctk.set_default_color_theme("green")
        self.iconbitmap("DCrypt.ico")  

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(pady=20, fill="both", expand=True)

        self.main_tab = self.tabview.add("DCrypt@V1")
        self.ads_tab = self.tabview.add("Copyright")

        self._init_ui()

    def _init_ui(self):
        self.action_label = ctk.CTkLabel(self.main_tab, text="Do you want to (e)ncrypt or (d)ecrypt a file?", font=("Arial", 12, "bold"))
        self.action_label.pack(pady=20)

        self.action_entry = ctk.CTkEntry(self.main_tab, placeholder_text="e/d", font=("Arial", 12, "bold"))
        self.action_entry.pack(pady=10)

        self.file_label = ctk.CTkLabel(self.main_tab, text="Select a file", font=("Arial", 12, "bold"))
        self.file_label.pack(pady=10)

        self.file_entry = ctk.CTkEntry(self.main_tab, placeholder_text="", font=("Arial", 12, "bold"))
        self.file_entry.pack(pady=10)

        self.select_button = ctk.CTkButton(self.main_tab, text="Select a file", command=self.select_file, font=("Arial", 12, "bold"))
        self.select_button.pack(pady=10)

        self.password_label = ctk.CTkLabel(self.main_tab, text="Enter a password", font=("Arial", 12, "bold"))
        self.password_label.pack(pady=10)

        self.password_entry = ctk.CTkEntry(self.main_tab, placeholder_text="password", show="*", font=("Arial", 12, "bold"))
        self.password_entry.pack(pady=10)

        self.button = ctk.CTkButton(self.main_tab, text="Execute", command=self.execute, font=("Arial", 12, "bold"))
        self.button.pack(pady=10)

        self.result_label = ctk.CTkLabel(self.main_tab, text="", font=("Arial", 12, "bold"))
        self.result_label.pack(pady=10)

        self.reset_button = ctk.CTkButton(self.main_tab, text="Reset", command=self.reset, font=("Arial", 12, "bold"))
        self.reset_button.pack(pady=10)

        self.ads_label = ctk.CTkLabel(self.ads_tab, text="Copyright (C) 2024 Asterfion", font=("Arial", 12, "bold"))
        self.ads_label.pack(pady=20)

        self.ads_text = ctk.CTkLabel(self.ads_tab, text='''--> Asterfion informations <--
https://guns.lol/asterfion
https://github.com/Asterfion

Made by Asterfion in 29/11/2024 DCrypt is an advanced crypter and decrypter of files folders and more...
Thanks for using DCrypt !
Love u guys !











Asterfion is here.
''', font=("Arial", 12, "bold"))
        self.ads_text.pack(pady=10)

    def reset(self):
        for widget in self.main_tab.winfo_children():
            widget.destroy()
        self._init_ui()

    def select_file(self):
        file_name = filedialog.askopenfilename(title="DCrypt@V1 - Select a file", filetypes=[("DCrypt-Selection", "*.*")])
        if file_name:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_name)

    def generate_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_file(self, file_name, password):
        try:
            salt = os.urandom(16)
            key = self.generate_key(password, salt)

            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            with open(file_name, 'rb') as file:
                original = file.read()

            encrypted_message = encryptor.update(original) + encryptor.finalize()
            tag = encryptor.tag

            encrypted = iv + salt + tag + encrypted_message

            encrypted_file_name = os.path.join(os.path.dirname(__file__), f"{os.path.basename(file_name)}.DCrypt")
            with open(encrypted_file_name, 'wb') as file:
                file.write(encrypted)

            messagebox.showinfo("DCrypt@V1", f"Your file has been successfully encrypted: {encrypted_file_name}")
        except Exception as e:
            messagebox.showerror("DCrypt@V1", f"An error occurred during encryption: {str(e)}")

    def decrypt_file(self, encrypted_file_name, password):
        try:
            with open(encrypted_file_name, 'rb') as file:
                encrypted_data = file.read()

            iv = encrypted_data[:12]
            salt = encrypted_data[12:28]
            tag = encrypted_data[28:44]
            encrypted_message = encrypted_data[44:]

            key = self.generate_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted = decryptor.update(encrypted_message) + decryptor.finalize()

            original_file_name = os.path.join(os.path.dirname(__file__), os.path.basename(encrypted_file_name).replace('.DCrypt', ''))
            with open(original_file_name, 'wb') as file:
                file.write(decrypted)
            messagebox.showinfo("DCrypt@V1", f"Your file has been successfully decrypted: {original_file_name}")
        except Exception as e:
            messagebox.showerror("DCrypt@V1", '''Decryption failed.
Incorrect password or corrupted file.''')

    def execute(self):
        action = self.action_entry.get().strip().lower()
        password = self.password_entry.get().strip()
        file_name = self.file_entry.get().strip()

        if not os.path.exists(file_name):
            self.result_label.configure(text="Error: The file does not exist.")
            return

        if action == 'e':
            self.encrypt_file(file_name, password)
            self.reset()
        elif action == 'd':
            self.decrypt_file(file_name, password)
            self.reset()
        else:
            self.result_label.configure(text="Error: Invalid action. Please enter 'e' to encrypt or 'd' to decrypt.")
            self.reset()

    def run(self):
        self.mainloop()

if __name__ == "__main__":
    try:
        py_crypt = DCrypt()
        py_crypt.run()
    except Exception as e:
        print(f'''
              
DCrypt Error: {str(e)}

''')
