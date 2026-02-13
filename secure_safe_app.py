

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import cv2
import face_recognition
import numpy as np
import hashlib

# --- Constants ---
SENDER_LOG_FILE = "destruction_log.txt"
RECEIVED_LOG_FILE = "received_secrets_log.txt"
FACE_ENCODING_FILE = "face_encoding.dat"

# ==============================================================================
#  1. CRYPTOGRAPHIC CORE (No changes needed)
# ==============================================================================
class CryptoEngine:
    def derive_key(self, password: str, salt: bytes) -> bytes:
        return scrypt.hash(password.encode(), salt, N=16384, r=8, p=1, buflen=32)

    def encrypt_data(self, password: str, data: bytes) -> bytes:
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return salt + nonce + ciphertext

    def decrypt_data(self, password: str, encrypted_data: bytes) -> bytes:
        try:
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return None

# ==============================================================================
#  2. GUI AND APPLICATION LOGIC
# ==============================================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.crypto_engine = CryptoEngine()
        self.filepath = None
        self.DESTRUCTION_TIME = 120
        self.destruction_timer = None
        self.temp_file_path = None
        
        self.setup_logs()
        
        # (GUI setup code is unchanged)
        self.title("Secure Messenger (Sender MFA Enabled)")
        self.geometry("600x350")
        self.configure(bg="#2E2E2E")
        self.resizable(False, False)
        self.status_label = tk.Label(self, text="Status: Ready", bg="#2E2E2E", fg="#FFFFFF", font=("Helvetica", 16, "bold"))
        self.status_label.pack(pady=20)
        self.file_label = tk.Label(self, text="Select a file to encrypt or decrypt", bg="#2E2E2E", fg="#CCCCCC", font=("Helvetica", 10), wraplength=580)
        self.file_label.pack(pady=5)
        self.timer_label = tk.Label(self, text="", bg="#2E2E2E", fg="#FFD700", font=("Courier", 24, "bold"))
        self.timer_label.pack(pady=10)
        button_frame = tk.Frame(self, bg="#2E2E2E")
        button_frame.pack(pady=20)
        self.select_button = tk.Button(button_frame, text="Select File", command=self.select_file, font=("Helvetica", 12), bg="#4A4A4A", fg="white")
        self.select_button.grid(row=0, column=0, padx=10, ipady=5)
        self.encrypt_button = tk.Button(button_frame, text="Encrypt Secret", command=self.encrypt_file, state=tk.DISABLED, font=("Helvetica", 12), bg="#006400", fg="white")
        self.encrypt_button.grid(row=0, column=1, padx=10, ipady=5)
        self.decrypt_button = tk.Button(button_frame, text="Read Secret", command=self.decrypt_and_view, state=tk.DISABLED, font=("Helvetica", 12), bg="#8B0000", fg="white")
        self.decrypt_button.grid(row=0, column=2, padx=10, ipady=5)
        self.enroll_button = tk.Button(self, text="Enroll Face ID (Sender Only)", command=self.enroll_face, font=("Helvetica", 12, "bold"), bg="#005A9C", fg="white")
        self.enroll_button.pack(pady=15, ipady=5, ipadx=10)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_logs(self):
        if not os.path.exists(SENDER_LOG_FILE):
            with open(SENDER_LOG_FILE, 'w') as f: f.write("# Sender's log of destroyed secrets.\n")
        if not os.path.exists(RECEIVED_LOG_FILE):
            with open(RECEIVED_LOG_FILE, 'w') as f: f.write("# Receiver's log of viewed secrets.\n")
            
    def get_file_hash(self, filepath: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def is_file_received(self, file_hash: str) -> bool:
        with open(RECEIVED_LOG_FILE, 'r') as f:
            return file_hash in f.read()

    def log_received_file(self, file_hash: str):
        with open(RECEIVED_LOG_FILE, 'a') as f:
            f.write(f"{file_hash}\n")

    def is_file_destroyed(self, filepath: str) -> bool:
        with open(SENDER_LOG_FILE, 'r') as f:
            return os.path.abspath(filepath) in f.read()

    def log_destruction(self, filepath: str):
        with open(SENDER_LOG_FILE, 'a') as f:
            f.write(f"{os.path.abspath(filepath)}\n")

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            filename = os.path.basename(self.filepath)
            self.file_label.config(text=f"Selected: {filename}")
            if self.filepath.endswith(".sdd"):
                self.decrypt_button.config(state=tk.NORMAL); self.encrypt_button.config(state=tk.DISABLED)
                self.set_status("Ready to Read Secret", "#FFA500")
            else:
                self.encrypt_button.config(state=tk.NORMAL); self.decrypt_button.config(state=tk.DISABLED)
                self.set_status("Ready to Encrypt Secret", "#00BFFF")
    
    def enroll_face(self):
        password = self.get_password("Create your MASTER password to protect your Face ID:")
        if not password: return
        messagebox.showinfo("Get Ready", "Camera will open. Look at the camera and press SPACE.")
        cap = cv2.VideoCapture(0)
        enrolled_encoding = None
        while True:
            ret, frame = cap.read()
            if not ret: break
            cv2.imshow("Enroll - Press SPACE to Capture", frame); key = cv2.waitKey(1) & 0xFF
            if key == 32:
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                face_locations = face_recognition.face_locations(rgb_frame)
                if face_locations: enrolled_encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]; break
        cap.release(); cv2.destroyAllWindows()
        if enrolled_encoding is not None:
            encrypted_encoding = self.crypto_engine.encrypt_data(password, enrolled_encoding.tobytes())
            with open(FACE_ENCODING_FILE, 'wb') as f: f.write(encrypted_encoding)
            messagebox.showinfo("Success", "Face ID enrolled and secured.")

    def verify_sender_face(self, password: str) -> bool:
        if not os.path.exists(FACE_ENCODING_FILE): return False
        with open(FACE_ENCODING_FILE, 'rb') as f: encrypted_encoding = f.read()
        decrypted_bytes = self.crypto_engine.decrypt_data(password, encrypted_encoding)
        if decrypted_bytes is None: return False
        known_encoding = np.frombuffer(decrypted_bytes)
        cap = cv2.VideoCapture(0); verified = False
        messagebox.showinfo("Verification", "Sender verification required. Look at the camera.")
        for _ in range(60):
            ret, frame = cap.read()
            if not ret: continue
            cv2.imshow("Verifying Sender...", frame); cv2.waitKey(1)
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            face_encodings = face_recognition.face_encodings(rgb_frame)
            if face_encodings:
                if True in face_recognition.compare_faces([known_encoding], face_encodings[0]): verified = True; break
        cap.release(); cv2.destroyAllWindows()
        return verified

    def encrypt_file(self):
        if self.is_file_destroyed(self.filepath):
            messagebox.showerror("Error", "This secret key has already been sent and is considered destroyed.")
            return
        if not os.path.exists(FACE_ENCODING_FILE):
            messagebox.showerror("Error", "Sender's Face ID is not enrolled. Cannot send secrets.")
            return
        password = self.get_password("SENDER: Enter your master password to authorize sending:")
        if not password: return
        if not self.verify_sender_face(password):
            messagebox.showerror("MFA Failed", "Sender verification failed. You are not authorized to send secrets.")
            return
        with open(self.filepath, 'rb') as f: plaintext = f.read()
        encrypted_data = self.crypto_engine.encrypt_data(password, plaintext)
        encrypted_filepath = self.filepath + ".sdd"
        with open(encrypted_filepath, 'wb') as f: f.write(encrypted_data)
        self.log_destruction(self.filepath)
        messagebox.showinfo("Success", "Sender authorized. Secret encrypted and marked as destroyed.")
        self.set_status("Secret Sent", "#FF4500")

    def decrypt_and_view(self):
        file_hash = self.get_file_hash(self.filepath)
        if self.is_file_received(file_hash):
            messagebox.showerror("Access Denied", "This secret has already been viewed and destroyed. It cannot be opened again.")
            return
            
        password = self.get_password("RECEIVER: Enter the shared password to read the secret:")
        if not password: return
        with open(self.filepath, 'rb') as f: encrypted_data = f.read()
        plaintext = self.crypto_engine.decrypt_data(password, encrypted_data)
        if plaintext is None:
            messagebox.showerror("Error", "Decryption failed. Incorrect password.")
            return

        self.log_received_file(file_hash)
        
        original_filename = self.filepath.replace(".sdd", "")
        _, file_extension = os.path.splitext(original_filename)
        self.temp_file_path = f"temp_decrypted_secret{file_extension}"

        with open(self.temp_file_path, 'wb') as f: f.write(plaintext)
        
        # --- THIS IS THE CHANGED PART ---
        os.startfile(self.temp_file_path)
        # Immediately start the timer after opening the file
        self.start_destruction_timer()
        # Update the status label to provide feedback, since the pop-up is gone
        self.set_status("SECRET VISIBLE - TIMER STARTED", "#00FF7F")
        # The messagebox.showinfo call has been removed.
        # --- END OF CHANGE ---


    def start_destruction_timer(self):
        self.time_left = self.DESTRUCTION_TIME
        self.update_timer()

    def update_timer(self):
        if self.time_left > 0:
            mins, secs = divmod(self.time_left, 60)
            self.timer_label.config(text=f"Secret destroys in: {mins:02d}:{secs:02d}")
            self.time_left -= 1
            self.destruction_timer = self.after(1000, self.update_timer)
        else: self.destroy_secret_file("Timer expired.")

    def destroy_secret_file(self, reason: str):
        if self.temp_file_path and os.path.exists(self.temp_file_path):
            os.remove(self.temp_file_path)
            self.temp_file_path = None
            messagebox.showinfo("Self-Destruct", f"The revealed secret has been permanently deleted.\nReason: {reason}")
        self.set_status("SECRET DESTROYED", "red")
        self.timer_label.config(text="")
        if self.destruction_timer: self.after_cancel(self.destruction_timer)
            
    def on_closing(self):
        self.destroy_secret_file("Application closed.")
        self.destroy()

    def get_password(self, prompt: str) -> str:
        return simpledialog.askstring("Password", prompt, show='*')
        
    def set_status(self, text, color):
        self.status_label.config(text=f"Status: {text}", fg=color)

if __name__ == "__main__":
    app = App()
    app.mainloop()