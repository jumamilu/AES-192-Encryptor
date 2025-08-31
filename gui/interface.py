import os
import sys
import threading
import itertools

import customtkinter as ctk
from tkinter import filedialog, messagebox

# --------- Project imports ----------
CURRENT_DIR = os.path.dirname(__file__)
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
sys.path.append(PARENT_DIR)

from aes_encryption.ENC_YALERO import encrypt_file 
from aes_encryption.decryptor import decrypt_file
from key_derivation.derive_key import is_valid_password  # pre-check only

# --------- CTk theme ----------
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

BROWSE_W, BROWSE_H = 140, 36
ACTION_H = BROWSE_H
ACTION_W = 200   # slightly longer than Browse


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AES-192 Secure File Tool")
        self.geometry("900x620")
        self.minsize(760, 520)
        self.resizable(True, True)

        # State vars
        self.selected_path = ctk.StringVar(value="")
        self.selected_filename = ctk.StringVar(value="")
        self.password = ctk.StringVar(value="")
        self.show_password = ctk.BooleanVar(value=False)

        # For animation
        self.secure_label = None
        self.color_cycle = itertools.cycle(["#FFD700", "#FFB84D", "#FFA500", "#FFC107"])
        self._animate_running = False

        # Flow
        self._show_welcome()

    # ------------------ Welcome ------------------
    def _show_welcome(self):
        self.welcome_frame = ctk.CTkFrame(self, fg_color="#4B0082")
        self.welcome_frame.pack(fill='both', expand=True)

        ctk.CTkLabel(
            self.welcome_frame,
            text="Welcome to AES-192 File Security Tool",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color="#FFD700",
            wraplength=780
        ).pack(pady=(60, 18))

        ctk.CTkLabel(
            self.welcome_frame,
            text=("Keep your personal files safe and private with modern AES-192 encryption.\n"
                  "Encrypt and decrypt confidently while ensuring your files remain untampered."),
            font=ctk.CTkFont(size=16, slant="italic"),
            text_color="#FFFFFF",
            wraplength=740,
            justify="center"
        ).pack(pady=(0, 20))

        ctk.CTkButton(
            self.welcome_frame,
            text="Get Started",
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#FF69B4", hover_color="#FF1493",
            width=220, height=48,
            command=self._show_guidance
        ).pack(pady=24)

    # ------------------ Guidance ------------------
    def _show_guidance(self):
        self.welcome_frame.destroy()

        self.guidance_frame = ctk.CTkFrame(self, fg_color="#0D3B66")
        self.guidance_frame.pack(fill='both', expand=True, padx=18, pady=18)

        ctk.CTkLabel(
            self.guidance_frame,
            text="How to Secure Your Files",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="#FAF0CA"
        ).pack(pady=(30, 10))

        guidance_text = (
            "AES-192 encryption ensures your files remain private and untampered.\n\n"
            "Note: AES is symmetric, which means the SAME password used for encryption must be used for decryption.\n\n"
            "Losing or forgetting this password means losing access to your files permanently.\n\n"
            "Choose strong, memorable passwords and store them safely.\n"
            "Only with your correct password can your files be decrypted and restored."
        )

        ctk.CTkLabel(
            self.guidance_frame,
            text=guidance_text,
            font=ctk.CTkFont(size=16),
            text_color="#E1F5FE",
            justify="left",
            wraplength=820
        ).pack(padx=24, pady=(6, 20))

        # Animated secure message
        self.secure_label = ctk.CTkLabel(
            self.guidance_frame,
            text="🔒 Secure your files, secure your life",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#FFD700"
        )
        self.secure_label.pack(pady=(0, 34))
        self._animate_secure_label()

        ctk.CTkButton(
            self.guidance_frame,
            text="Continue",
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#EE964B", hover_color="#F4A261",
            width=220, height=48,
            command=self._show_main_ui
        ).pack(pady=10)

    def _animate_secure_label(self):
        if not self._animate_running:
            self._animate_running = True
        next_color = next(self.color_cycle)
        self.secure_label.configure(text_color=next_color)
        self.after(500, self._animate_secure_label)

    # ------------------ Main UI ------------------
    def _show_main_ui(self):
        self.guidance_frame.destroy()
        self._animate_running = False

        self.main_frame = ctk.CTkFrame(self, fg_color="#121212")
        self.main_frame.pack(fill='both', expand=True, padx=14, pady=14)

        self.main_frame.grid_rowconfigure(0, weight=0)
        self.main_frame.grid_rowconfigure(1, weight=0)
        self.main_frame.grid_rowconfigure(2, weight=0)
        self.main_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.main_frame,
            text="🔒 AES-192 Tool",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="#FFD700"
        ).grid(row=0, column=0, pady=(10, 6))

        # File selection
        file_row = ctk.CTkFrame(self.main_frame, fg_color="#121212")
        file_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(8, 4))
        file_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(file_row, text="Select File:", font=ctk.CTkFont(size=16)).grid(row=0, column=0, sticky="w")
        file_bar = ctk.CTkFrame(file_row, fg_color="#121212")
        file_bar.grid(row=1, column=0, sticky="ew")
        file_bar.grid_columnconfigure(0, weight=1)

        self.file_entry = ctk.CTkEntry(file_bar, textvariable=self.selected_filename)
        self.file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(
            file_bar, text="Browse", command=self._browse_file,
            fg_color="#1E90FF", hover_color="#4682B4",
            width=BROWSE_W, height=BROWSE_H
        ).grid(row=0, column=1, sticky="e")

        # Password entry
        pass_row = ctk.CTkFrame(self.main_frame, fg_color="#121212")
        pass_row.grid(row=2, column=0, sticky="ew", padx=8, pady=(8, 4))
        pass_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(pass_row, text="Password:", font=ctk.CTkFont(size=16)).grid(row=0, column=0, sticky="w")
        pw_bar = ctk.CTkFrame(pass_row, fg_color="#121212")
        pw_bar.grid(row=1, column=0, sticky="ew")
        pw_bar.grid_columnconfigure(0, weight=1)

        self.pass_entry = ctk.CTkEntry(pw_bar, show='*', textvariable=self.password)
        self.pass_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.show_password_switch = ctk.CTkSwitch(
            pw_bar, text="Show", command=self._toggle_password, variable=self.show_password
        )
        self.show_password_switch.grid(row=0, column=1, sticky="e")

        # Encrypt/Decrypt buttons right below password
        actions = ctk.CTkFrame(self.main_frame, fg_color="#121212")
        actions.grid(row=3, column=0, sticky="ew", padx=8, pady=(16, 10))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            actions, text="🔒 Encrypt", command=self._on_encrypt,
            fg_color="#28A745", hover_color="#3CC155",
            width=ACTION_W, height=ACTION_H
        ).grid(row=0, column=0, padx=10)

        ctk.CTkButton(
            actions, text="🔓 Decrypt", command=self._on_decrypt,
            fg_color="#FF4136", hover_color="#FF6650",
            width=ACTION_W, height=ACTION_H
        ).grid(row=0, column=1, padx=10)

    # ------------------ Helpers ------------------
    def _browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_path.set(path)
            self.selected_filename.set(os.path.basename(path))

    def _toggle_password(self):
        self.pass_entry.configure(show='' if self.show_password.get() else '*')

    # ------------------ Actions ------------------
    def _on_encrypt(self):
        path = self.selected_path.get().strip()
        pw = self.password.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid file to encrypt.")
            return
        if not is_valid_password(pw):
            messagebox.showerror(
                "Invalid Password",
                "Password must be at least 8 characters and include letters, digits, and punctuation."
            )
            return
        threading.Thread(target=self._encrypt_worker, args=(path, pw), daemon=True).start()
        self.password.set(""); self.selected_path.set(""); self.selected_filename.set("")

    def _on_decrypt(self):
        path = self.selected_path.get().strip()
        pw = self.password.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid file to decrypt.")
            return
        if not is_valid_password(pw):
            messagebox.showerror(
                "Invalid Password",
                "Password must be at least 8 characters and include letters, digits, and punctuation."
            )
            return
        threading.Thread(target=self._decrypt_worker, args=(path, pw), daemon=True).start()
        self.password.set(""); self.selected_path.set(""); self.selected_filename.set("")

    # ------------------ Workers ------------------
    def _encrypt_worker(self, path, pw):
        try:
            result = encrypt_file(path, pw)
            messagebox.showinfo("Success", f"File encrypted as: {os.path.basename(result)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _decrypt_worker(self, path, pw):
        try:
            decrypt_file(path, pw)
            messagebox.showinfo("Success", "Decryption successful!")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# ------------------ Run ------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
