# SECURED-SAFE-CASE: Encrypted File Transfer & Secure File Storage

SECURED-SAFE-CASE is a cybersecurity project that implements encrypted file upload/download between a client and server.
Files are encrypted on the client using AES-256-GCM, split into chunks, integrity protected with HMAC-SHA256, uploaded over HTTP/HTTPS, and stored encrypted on the server disk.

## Security Design

- Client-side encryption using AES-256-GCM
- Unique 96-bit nonce per chunk
- HMAC-SHA256 per encrypted chunk
- Password-derived keys using PBKDF2-HMAC-SHA256
- Server stores only ciphertext chunks
- Resume support for missing chunks
- MVP user isolation using a generic `X-User` header

For production, replace the MVP `X-User` header with JWT authentication and run behind HTTPS/TLS.

## Setup

```bash
cd secured-safe-case_project
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

## Run Server

```bash
cd server
uvicorn app:app --reload
```

Open API docs:

```text
http://127.0.0.1:8000/docs
```

## Upload File

Open a second terminal:

```bash
cd secured-safe-case_project
python client/secured-safe-case_client.py --user demo_user upload sample.pdf
```

The client will ask for an encryption password.
Save the returned File ID.

## List Files

```bash
python client/secured-safe-case_client.py --user demo_user list
```

## Download File

```bash
python client/secured-safe-case_client.py --user demo_user download YOUR_FILE_ID --out downloads
```

Enter the same encryption password used during upload.

## Resume Failed Upload

```bash
python client/secured-safe-case_client.py --user demo_user resume YOUR_FILE_ID sample.pdf
```

## Threat Model

### Man-in-the-Middle
Mitigation: HTTPS/TLS plus client-side AES encryption.

### Server Compromise
Mitigation: server stores encrypted chunks only. Plaintext is not stored.

### File Tampering
Mitigation: AES-GCM authentication tag and HMAC-SHA256 verification.

### Replay Attack
Mitigation: HMAC covers file_id, chunk_number, nonce, and ciphertext.

### Key Management Risk
Mitigation: keys are derived from user password and salt. Encryption key is not stored on server.

## Limitations of MVP

- No real login system yet
- No HTTPS certificate setup yet
- No frontend dashboard yet
- PBKDF2 is used for simplicity; Argon2id is stronger for password-based key derivation


## Privacy Note

This repository intentionally contains no personal information, author name, email address, institution name, roll number, phone number, resume details, or machine-specific paths. Replace placeholders only if your submission format requires it.
