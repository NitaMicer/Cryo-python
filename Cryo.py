import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import base64
import secrets
import hashlib
import base58 # type: ignore
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import CMAC


# Base58 encoding function
def base58_encode(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    encode = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encode = alphabet[rem] + encode
    return encode


# TBC Padding implementation
def tbc_pad(data, block_size):
    if not data:
        raise ValueError("Data cannot be empty when applying TBC padding.")
    
    last_byte = data[-1]
    last_bit = last_byte & 1
    padding_byte = 0x00 if last_bit == 1 else 0xFF
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    padding = bytes([padding_byte] * padding_len)
    return data + padding


def tbc_unpad(data, block_size):
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid data length for TBC unpadding.")
    last_byte = data[-1]
    padding_byte = last_byte
    padding_len = 1
    for i in range(2, block_size + 1):
        if data[-i] != padding_byte:
            break
        padding_len += 1
    if padding_len > block_size or data[-padding_len:] != bytes([padding_byte] * padding_len):
        raise ValueError("Invalid padding.")
    return data[:-padding_len]


# Zero Byte Padding implementation
def zero_pad(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([0x00] * padding_len)


def zero_unpad(data, block_size):
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid data length for Zero Byte unpadding.")
    unpadded_data = data.rstrip(b'\x00')
    return unpadded_data


def process_iv(user_iv_string, key):
    iv_bytes = user_iv_string.encode("utf-8")
    
    if len(iv_bytes) == 12:
        final_nonce = iv_bytes
    else:
        # Generate GHASH subkey by encrypting 16 zero bytes in ECB with your AES key
        ecb_cipher = AES.new(key, AES.MODE_ECB)
        H_subkey = ecb_cipher.encrypt(b"\x00" * 16)
        
        # Pad iv_bytes to multiple of 16 and append 64-bit length (bits), plus another 64 bits of zero
        iv_bit_len = len(iv_bytes) * 8
        remainder = len(iv_bytes) % 16
        pad_len = (16 - remainder) if remainder else 0
        iv_padded = iv_bytes + (b"\x00" * pad_len) + iv_bit_len.to_bytes(8, "big") + (b"\x00" * 8)
        
        # Use AES.new(H_subkey, AES.MODE_GCM) trick to GHASH
        ghash_cipher = AES.new(H_subkey, AES.MODE_GCM)
        ghash_cipher.update(iv_padded)
        ghash_output = ghash_cipher.digest()  # 16 bytes
        
        # Truncate GHASH output to 12 bytes
        final_nonce = ghash_output[:12]
    
    return final_nonce


class CryoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption")
        self.root.geometry("800x800")
        self.root.configure(bg="#1e1e1e")
        self.current_frame = None
        self.aes_values = {}
        self.random_key_length = 16
        self.switch_to_aes()

    def switch_to_aes(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.current_frame.pack(fill="both", expand=True)

        ttk.Label(self.current_frame, text="AES Encryption", font=("Arial", 20), foreground="white", background="#1e1e1e").pack(pady=20)

        ttk.Label(self.current_frame, text="Encryption Mode:", foreground="white", background="#1e1e1e").pack()
        self.encryption_mode = ttk.Combobox(self.current_frame, values=["ECB", "GCM"], state="readonly")
        self.encryption_mode.set("ECB")
        self.encryption_mode.pack()
        self.encryption_mode.bind("<<ComboboxSelected>>", self.update_iv_availability)

        ttk.Label(self.current_frame, text="Key Mode:", foreground="white", background="#1e1e1e").pack()
        self.key_mode = ttk.Combobox(self.current_frame, values=["SHA-256", "SHA-3 (256)", "Raw", "Derived"], state="readonly")
        self.key_mode.set("SHA-256")
        self.key_mode.pack()
        self.key_mode.bind("<<ComboboxSelected>>", self.toggle_key_length_availability)

        ttk.Label(self.current_frame, text="Key Length:", foreground="white", background="#1e1e1e").pack()
        self.key_length = ttk.Combobox(self.current_frame, values=["128", "192", "256"], state="readonly")
        self.key_length.set("256")
        self.key_length.pack()

        ttk.Label(self.current_frame, text="Padding:", foreground="white", background="#1e1e1e").pack()
        self.padding = ttk.Combobox(self.current_frame, values=["None", "PKCS7", "TBC", "Zero Byte"])
        self.padding.set("None")  # Set default padding to "None"
        self.padding.pack()

        # Add Character Set Dropdown
        ttk.Label(self.current_frame, text="Character Set:", foreground="white", background="#1e1e1e").pack()
        self.encoding = ttk.Combobox(self.current_frame, values=["ASCII", "UTF-8", "UTF-16", "UTF-32", "ISO-8859-1"], state="readonly")
        self.encoding.set("UTF-8")  # Set default set to "UTF-8"
        self.encoding.pack()

        key_frame = tk.Frame(self.current_frame, bg="#1e1e1e")
        key_frame.pack(pady=5)
        ttk.Label(key_frame, text="Key (Password):", foreground="white", background="#1e1e1e").pack(side="left")
        self.key_entry = tk.Entry(key_frame, bg="#2e2e2e", fg="white", show="*")
        self.key_entry.pack(side="left", padx=5)
        self.show_key_var = tk.BooleanVar()
        self.show_key_checkbox = ttk.Checkbutton(key_frame, text="Show", variable=self.show_key_var, command=self.toggle_key_visibility)
        self.show_key_checkbox.pack(side="left")

        random_key_frame = tk.Frame(self.current_frame, bg="#1e1e1e")
        random_key_frame.pack(pady=5)
        self.random_key_button = ttk.Button(random_key_frame, text="Random Key", command=self.generate_random_key)
        self.random_key_button.pack(side="left")
        self.random_key_var = tk.BooleanVar()
        self.random_key_checkbox = ttk.Checkbutton(random_key_frame, text="24-Byte Key", variable=self.random_key_var, command=self.toggle_random_key_length)
        self.random_key_checkbox.pack(side="left", padx=5)

        ttk.Label(self.current_frame, text="Initialization Vector (IV):", foreground="white", background="#1e1e1e").pack()
        iv_frame = tk.Frame(self.current_frame, bg="#1e1e1e")
        iv_frame.pack(pady=5)
        self.iv_entry = tk.Entry(iv_frame, bg="#2e2e2e", fg="white", state="disabled")
        self.iv_entry.pack(side="left", padx=5)
        self.iv_button = ttk.Button(iv_frame, text="Random IV", command=self.generate_random_iv, state="disabled")
        self.iv_button.pack(side="left")

        ttk.Label(self.current_frame, text="Plaintext / Ciphertext (Base64):", foreground="white", background="#1e1e1e").pack()
        self.text_entry = tk.Text(self.current_frame, height=10, bg="#2e2e2e", fg="white")
        self.text_entry.pack()

        ttk.Button(self.current_frame, text="Encrypt", command=self.encrypt_aes).pack(pady=10)
        ttk.Button(self.current_frame, text="Decrypt", command=self.decrypt_aes).pack(pady=10)

        help_button = ttk.Button(self.current_frame, text="?", command=self.switch_to_aes_info)
        help_button.place(relx=0.95, rely=0.02, anchor="ne")

        self.restore_aes_values()

    def toggle_key_length_availability(self, event=None):
        selected_mode = self.key_mode.get()
        if selected_mode in ["Raw", "Derived"]:
            self.key_length.config(state="disabled")
        else:
            self.key_length.config(state="readonly")

    def toggle_key_visibility(self):
        if self.show_key_var.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")

    def toggle_random_key_length(self):
        self.random_key_length = 24 if self.random_key_var.get() else 16

    def update_iv_availability(self, event=None):
        mode = self.encryption_mode.get()
        if mode == "ECB":
            self.iv_entry.delete(0, tk.END)
            self.iv_entry.config(state="disabled")
            self.iv_button.config(state="disabled")
            self.padding.config(state="readonly")
        elif mode == "GCM":
            self.iv_entry.config(state="normal")
            self.iv_button.config(state="normal")
            self.padding.set("None")
            self.padding.config(state="disabled")
        else:
            self.iv_entry.config(state="normal")
            self.iv_button.config(state="normal")
            self.padding.config(state="readonly")

    def generate_random_key(self):
        random_key = secrets.token_bytes(self.random_key_length)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, base58_encode(random_key))

    def generate_random_iv(self):
        block_size = 16  # AES block size is 16 bytes
        random_iv = secrets.token_bytes(block_size)
        self.iv_entry.delete(0, tk.END)
        self.iv_entry.insert(0, base58_encode(random_iv))

    def save_aes_values(self):
        self.aes_values["padding"] = self.padding.get()
        self.aes_values["key"] = self.key_entry.get()
        self.aes_values["iv"] = self.iv_entry.get()
        self.aes_values["text"] = self.text_entry.get("1.0", tk.END)

    def restore_aes_values(self):
        if "padding" in self.aes_values:
            self.padding.set(self.aes_values["padding"])
        if "key" in self.aes_values:
            self.key_entry.insert(0, self.aes_values["key"])
        if "iv" in self.aes_values:
            self.iv_entry.insert(0, self.aes_values["iv"])
        if "text" in self.aes_values:
            self.text_entry.insert("1.0", self.aes_values["text"])

    def process_aes_key(self, key_password, key_mode, key_length):
        if key_mode == "SHA-256":
            return hashlib.sha256(key_password.encode()).digest()[:key_length // 8]
        elif key_mode == "SHA-3 (256)":
            return hashlib.sha3_256(key_password.encode()).digest()[:key_length // 8]
        elif key_mode == "Raw":
            key = key_password.encode()
            if len(key) % 16 != 0:
                raise ValueError("Raw key length must be a multiple of 16 bytes.")
            return key
        elif key_mode == "Derived":
            try:
                key = bytes.fromhex(key_password)
                if len(key) != key_length // 8:
                    raise ValueError(f"Derived key must be a valid {key_length // 8}-byte hash.")
                return key
            except ValueError:
                raise ValueError(f"Derived key must be a valid {key_length // 8}-byte hash.")
        else:
            raise ValueError("Unsupported key mode.")

    def process_aes_iv(self, iv, mode):
        if mode == "GCM":
            if iv:
                iv = process_iv(iv, self.process_aes_key(self.key_entry.get(), self.key_mode.get(), int(self.key_length.get())))
            else:
                iv = secrets.token_bytes(12)  # Generate a 12-byte random nonce if IV is not provided
            return iv
        else:
            return None

    def encode_text(self, text, encoding):
        return text.encode(encoding)

    def decode_text(self, data, encoding):
        return data.decode(encoding)

    def encrypt_aes(self):
        try:
            key_password = self.key_entry.get()
            plaintext = self.text_entry.get("1.0", tk.END).strip()
            padding = self.padding.get()
            key_mode = self.key_mode.get()
            key_length = int(self.key_length.get())
            mode = self.encryption_mode.get()
            encoding = self.encoding.get()
            iv = self.iv_entry.get()

            if not key_password:
                raise ValueError("Key (Password) is required.")
            if not plaintext:
                raise ValueError("Plaintext is required.")
            if padding not in ["None", "PKCS7", "TBC", "Zero Byte"] and mode != "GCM":
                raise ValueError("Padding must be selected (None, PKCS7, TBC, or Zero Byte).")
            if mode == "GCM" and not iv:
                raise ValueError("Initialization Vector (IV) is required for GCM mode.")

            key = self.process_aes_key(key_password, key_mode, key_length)
            iv = self.process_aes_iv(iv, mode)

            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
            elif mode == "GCM":
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            else:
                raise ValueError("Unsupported encryption mode.")

            plaintext_bytes = self.encode_text(plaintext, encoding)

            if mode != "GCM":
                if padding == "PKCS7":
                    plaintext_bytes = pad(plaintext_bytes, AES.block_size)
                elif padding == "TBC":
                    plaintext_bytes = tbc_pad(plaintext_bytes, AES.block_size)
                elif padding == "Zero Byte":
                    plaintext_bytes = zero_pad(plaintext_bytes, AES.block_size)
                elif len(plaintext_bytes) % AES.block_size != 0:
                    raise ValueError("Plaintext length must be a multiple of 16 bytes for no padding.")

            if mode == "GCM":
                ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
                combined = iv + ciphertext + tag
                encoded_ciphertext = base64.b64encode(combined).decode().rstrip("=")
            else:
                ciphertext = cipher.encrypt(plaintext_bytes)
                encoded_ciphertext = base64.b64encode(ciphertext).decode().rstrip("=")

            self.text_entry.delete("1.0", tk.END)
            self.text_entry.insert("1.0", encoded_ciphertext)

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_aes(self):
        try:
            key_password = self.key_entry.get()
            ciphertext = self.text_entry.get("1.0", tk.END).strip()
            padding = self.padding.get()
            key_mode = self.key_mode.get()
            key_length = int(self.key_length.get())
            mode = self.encryption_mode.get()
            encoding = self.encoding.get()
            iv = self.iv_entry.get()

            if not key_password:
                raise ValueError("Key (Password) is required.")
            if not ciphertext:
                raise ValueError("Ciphertext is required.")
            if padding not in ["None", "PKCS7", "TBC", "Zero Byte"] and mode != "GCM":
                raise ValueError("Padding must be selected (None, PKCS7, TBC, or Zero Byte).")
            if mode == "GCM" and not iv:
                raise ValueError("Initialization Vector (IV) is required for GCM mode.")

            combined = base64.b64decode(ciphertext + '==')  # Decode Base64 encoded ciphertext
            key = self.process_aes_key(key_password, key_mode, key_length)

            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
                ciphertext_bytes = combined  # In ECB mode, the entire combined is the ciphertext
            elif mode == "GCM":
                nonce = combined[:12]
                ciphertext_bytes = combined[12:-16]
                tag = combined[-16:]
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            else:
                raise ValueError("Unsupported encryption mode.")

            if mode == "GCM":
                plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag)
            else:
                plaintext_bytes = cipher.decrypt(ciphertext_bytes)

                if padding == "PKCS7":
                    plaintext_bytes = unpad(plaintext_bytes, AES.block_size)
                elif padding == "TBC":
                    plaintext_bytes = tbc_unpad(plaintext_bytes, AES.block_size)
                elif padding == "Zero Byte":
                    plaintext_bytes = zero_unpad(plaintext_bytes, AES.block_size)

            plaintext = self.decode_text(plaintext_bytes, encoding)

            self.text_entry.delete("1.0", tk.END)
            self.text_entry.insert("1.0", plaintext)

        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def switch_to_aes_info(self):
        if self.current_frame:
            self.save_aes_values()
            self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.current_frame.pack(fill="both", expand=True)

        ttk.Button(self.current_frame, text="Back", command=self.switch_to_aes).pack(anchor="nw", pady=10, padx=10)

        ttk.Label(self.current_frame, text="AES Information", font=("Arial", 20), foreground="white", background="#1e1e1e").pack(pady=20)

        info_text = (
            "Random Keys: \n"
            "- Are Base58 encoded 16 bytes random values (24 bytes when enabled by adjacent checkbox).\n"
            "- For key mode 'Raw', those keys are cut down to match the cipher key length.\n"
            "- In key mode 'Derived', a HKDF-SHA3-256 hash is derived from 64 bytes random values.\n\n"
            "Key Modes: \n"
            "- SHA256/SHA3-256: Key input is treated as a password and hashed. If the key length is smaller \n"
            "  than the hash size, only the first bytes according to the key length are used.\n"
            "- Raw: Key input is used for cipher operation byte per byte where 1 character = 1 byte.\n"
            "- Derived: Key input must already be a hash, derived from a password or random value \n"
            "  by a key derivation or simple hash function.\n\n"
            "Initialization Vector (IV): \n"
            "- The IV input is used for cipher operation byte per byte, where 1 character = 1 byte.\n"
            "- Random IVs are Base58 encoded and have the same length as the cipher block size.\n"
            "- If the IV is not 12 bytes long, it is hashed to derive a 12-byte nonce.\n\n"
            "Padding: \n"
            "- Without padding, the plaintext must be the same length as the cipher block size.\n"
            "- PKCS7: Adds padding bytes to ensure plaintext is a multiple of block size.\n"
            "- TBC: Pads plaintext with the last byte of plaintext until it reaches the block size.\n"
            "- Zero Byte: Pads plaintext with 0x00 bytes until it reaches the block size.\n\n"
            "Ciphertext: \n"
            "- Is Base64 encoded with NO_WRAP and NO_PADDING flags."
        )
        info_label = tk.Label(self.current_frame, text=info_text, justify="left", fg="white", bg="#1e1e1e", wraplength=750)
        info_label.pack(pady=10)

    def encrypt(self, plaintext, key, iv=None):
        if iv is None:
            iv = get_random_bytes(12)  # GCM mode typically uses a 12-byte IV
        else:
            iv = process_iv(iv, key)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return base64.b64encode(iv + ciphertext + tag).decode('utf-8')  # Store IV and tag with the ciphertext

    def decrypt(self, encrypted_data, key):
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:12]  # Extract the IV
        tag = encrypted_data[-16:]  # Extract the tag
        ciphertext = encrypted_data[12:-16]  # Extract the ciphertext
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()


if __name__ == "__main__":
    root = tk.Tk()
    app = CryoApp(root)
    root.mainloop()
