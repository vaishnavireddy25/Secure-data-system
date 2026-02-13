# SecureSafe – Self-Destructing Data System

SecureSafe is a lightweight cybersecurity application that provides time-limited and self-destructing access to sensitive files using authenticated encryption and multi-factor authentication.

The system ensures that plaintext data and encryption keys exist only in memory during an active session and are destroyed immediately after session expiry or security triggers.

## Key Features
- AES-GCM based authenticated encryption for secure file storage
- Multi-factor authentication with password and optional face recognition
- Volatile in-memory key handling with crypto-shredding on session termination
- Time-based and event-driven destruction mechanisms

## Runtime generated files
The following files are created automatically when the application is executed and are intentionally excluded from the repository:

- `destruction_log.txt`
- `received_secrets_log.txt`
- `face_encoding.dat`

These files are generated locally for logging and biometric authentication purposes.

## How to run
1. Create and activate a Python virtual environment.
2. Install the required dependencies.
3. Run:
   ```bash
   python secure_safe_app.py
