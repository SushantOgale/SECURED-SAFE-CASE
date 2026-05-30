import argparse
import base64
import getpass
import hashlib
import hmac
import math
import os
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=600_000,
    )
    key_material = kdf.derive(password.encode())
    return key_material[:32], key_material[32:]


def aad(file_id: str, chunk_number: int) -> bytes:
    return f"SecureVault|{file_id}|{chunk_number}".encode()


def chunk_hmac(hmac_key: bytes, file_id: str, chunk_number: int, nonce: bytes, ciphertext: bytes) -> str:
    msg = aad(file_id, chunk_number) + nonce + ciphertext
    return hmac.new(hmac_key, msg, hashlib.sha256).hexdigest()


def upload(server: str, user: str, file_path: str, chunk_size: int):
    path = Path(file_path)
    if not path.exists():
        raise SystemExit("File does not exist")

    password = getpass.getpass("Encryption password: ")
    salt = os.urandom(16)
    aes_key, hmac_key = derive_keys(password, salt)
    aesgcm = AESGCM(aes_key)

    file_size = path.stat().st_size
    total_chunks = math.ceil(file_size / chunk_size)
    headers = {"X-User": user}

    init_resp = requests.post(
        f"{server}/upload/init",
        headers=headers,
        data={
            "original_filename": path.name,
            "file_size": file_size,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "salt": base64.b64encode(salt).decode(),
        },
        timeout=30,
    )
    init_resp.raise_for_status()
    file_id = init_resp.json()["file_id"]
    print(f"File ID: {file_id}")

    with path.open("rb") as f:
        for chunk_number in range(total_chunks):
            plaintext = f.read(chunk_size)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext, aad(file_id, chunk_number))
            hmac_hex = chunk_hmac(hmac_key, file_id, chunk_number, nonce, ciphertext)

            files = {"encrypted_chunk": (f"chunk_{chunk_number:06d}.enc", ciphertext, "application/octet-stream")}
            data = {
                "file_id": file_id,
                "chunk_number": chunk_number,
                "nonce": base64.b64encode(nonce).decode(),
                "hmac_hex": hmac_hex,
            }
            r = requests.post(f"{server}/upload/chunk", headers=headers, data=data, files=files, timeout=60)
            r.raise_for_status()
            print(f"Uploaded chunk {chunk_number + 1}/{total_chunks}")

    print("Upload complete.")
    print("Save this File ID for download:", file_id)


def resume_upload(server: str, user: str, file_id: str, file_path: str):
    # For resume, the original salt is fetched from metadata and the same password must be used.
    path = Path(file_path)
    headers = {"X-User": user}
    meta = requests.get(f"{server}/download/metadata/{file_id}", headers=headers, timeout=30)
    meta.raise_for_status()
    metadata = meta.json()["file"]
    status = requests.get(f"{server}/upload/status/{file_id}", headers=headers, timeout=30)
    status.raise_for_status()
    missing = status.json()["missing_chunks"]
    if not missing:
        print("No missing chunks. Upload already complete.")
        return

    password = getpass.getpass("Encryption password: ")
    salt = base64.b64decode(metadata["salt"])
    aes_key, hmac_key = derive_keys(password, salt)
    aesgcm = AESGCM(aes_key)
    chunk_size = metadata["chunk_size"]

    with path.open("rb") as f:
        for chunk_number in missing:
            f.seek(chunk_number * chunk_size)
            plaintext = f.read(chunk_size)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext, aad(file_id, chunk_number))
            hmac_hex = chunk_hmac(hmac_key, file_id, chunk_number, nonce, ciphertext)
            files = {"encrypted_chunk": (f"chunk_{chunk_number:06d}.enc", ciphertext, "application/octet-stream")}
            data = {"file_id": file_id, "chunk_number": chunk_number, "nonce": base64.b64encode(nonce).decode(), "hmac_hex": hmac_hex}
            r = requests.post(f"{server}/upload/chunk", headers=headers, data=data, files=files, timeout=60)
            r.raise_for_status()
            print(f"Resumed chunk {chunk_number}")


def download(server: str, user: str, file_id: str, output_dir: str):
    headers = {"X-User": user}
    meta_resp = requests.get(f"{server}/download/metadata/{file_id}", headers=headers, timeout=30)
    meta_resp.raise_for_status()
    meta = meta_resp.json()
    file_info = meta["file"]
    chunks = meta["chunks"]

    password = getpass.getpass("Encryption password: ")
    salt = base64.b64decode(file_info["salt"])
    aes_key, hmac_key = derive_keys(password, salt)
    aesgcm = AESGCM(aes_key)

    out_path = Path(output_dir) / file_info["original_filename"]
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("wb") as out:
        for c in chunks:
            chunk_number = c["chunk_number"]
            nonce = base64.b64decode(c["nonce"])
            r = requests.get(f"{server}/download/chunk/{file_id}/{chunk_number}", headers=headers, timeout=60)
            r.raise_for_status()
            ciphertext = r.content
            expected_hmac = c["hmac_hex"]
            actual_hmac = chunk_hmac(hmac_key, file_id, chunk_number, nonce, ciphertext)
            if not hmac.compare_digest(expected_hmac, actual_hmac):
                raise SystemExit(f"HMAC verification failed on chunk {chunk_number}")
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad(file_id, chunk_number))
            out.write(plaintext)
            print(f"Downloaded and decrypted chunk {chunk_number + 1}/{len(chunks)}")

    print("Download complete:", out_path)


def list_files(server: str, user: str):
    r = requests.get(f"{server}/files", headers={"X-User": user}, timeout=30)
    r.raise_for_status()
    for item in r.json():
        print(f"{item['file_id']} | {item['original_filename']} | {item['status']} | {item['file_size']} bytes")


def main():
    parser = argparse.ArgumentParser(description="SecureVault client")
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--user", required=True)
    sub = parser.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("upload")
    up.add_argument("file")
    up.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)

    res = sub.add_parser("resume")
    res.add_argument("file_id")
    res.add_argument("file")

    down = sub.add_parser("download")
    down.add_argument("file_id")
    down.add_argument("--out", default="downloads")

    sub.add_parser("list")

    args = parser.parse_args()
    if args.cmd == "upload":
        upload(args.server, args.user, args.file, args.chunk_size)
    elif args.cmd == "resume":
        resume_upload(args.server, args.user, args.file_id, args.file)
    elif args.cmd == "download":
        download(args.server, args.user, args.file_id, args.out)
    elif args.cmd == "list":
        list_files(args.server, args.user)


if __name__ == "__main__":
    main()
