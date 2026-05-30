from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header
from fastapi.responses import FileResponse
from pathlib import Path
from uuid import uuid4
import base64
import os
import shutil

from database import init_db, get_conn

app = FastAPI(title="SecureVault - Encrypted File Transfer & Storage")
BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "encrypted_storage"
STORAGE_DIR.mkdir(exist_ok=True)


def require_user(x_user: str | None = Header(default=None)) -> str:
    # MVP authentication: pass X-User header. Later replace with JWT login.
    if not x_user or not x_user.strip():
        raise HTTPException(status_code=401, detail="Missing X-User header")
    return x_user.strip()


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def health():
    return {"status": "ok", "project": "SecureVault"}


@app.post("/upload/init")
def init_upload(
    original_filename: str = Form(...),
    file_size: int = Form(...),
    chunk_size: int = Form(...),
    total_chunks: int = Form(...),
    salt: str = Form(...),
    x_user: str | None = Header(default=None),
):
    owner = require_user(x_user)
    file_id = uuid4().hex
    file_dir = STORAGE_DIR / owner / file_id
    file_dir.mkdir(parents=True, exist_ok=True)

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO files(file_id, owner, original_filename, file_size, chunk_size, total_chunks, salt)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (file_id, owner, original_filename, file_size, chunk_size, total_chunks, salt),
    )
    conn.commit()
    conn.close()
    return {"file_id": file_id, "uploaded_chunks": []}


@app.post("/upload/chunk")
async def upload_chunk(
    file_id: str = Form(...),
    chunk_number: int = Form(...),
    nonce: str = Form(...),
    hmac_hex: str = Form(...),
    encrypted_chunk: UploadFile = File(...),
    x_user: str | None = Header(default=None),
):
    owner = require_user(x_user)
    conn = get_conn()
    file_row = conn.execute("SELECT * FROM files WHERE file_id=? AND owner=?", (file_id, owner)).fetchone()
    if not file_row:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")
    if chunk_number < 0 or chunk_number >= file_row["total_chunks"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid chunk number")

    file_dir = STORAGE_DIR / owner / file_id
    file_dir.mkdir(parents=True, exist_ok=True)
    chunk_path = file_dir / f"chunk_{chunk_number:06d}.enc"

    with chunk_path.open("wb") as out:
        shutil.copyfileobj(encrypted_chunk.file, out)

    size = chunk_path.stat().st_size
    conn.execute(
        """
        INSERT OR REPLACE INTO chunks(file_id, chunk_number, nonce, hmac_hex, chunk_path, size)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (file_id, chunk_number, nonce, hmac_hex, str(chunk_path), size),
    )

    uploaded_count = conn.execute("SELECT COUNT(*) AS c FROM chunks WHERE file_id=?", (file_id,)).fetchone()["c"]
    if uploaded_count == file_row["total_chunks"]:
        conn.execute("UPDATE files SET status='complete' WHERE file_id=?", (file_id,))
    conn.commit()
    conn.close()

    return {"message": "chunk stored", "file_id": file_id, "chunk_number": chunk_number}


@app.get("/upload/status/{file_id}")
def upload_status(file_id: str, x_user: str | None = Header(default=None)):
    owner = require_user(x_user)
    conn = get_conn()
    file_row = conn.execute("SELECT * FROM files WHERE file_id=? AND owner=?", (file_id, owner)).fetchone()
    if not file_row:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")
    uploaded = [r["chunk_number"] for r in conn.execute("SELECT chunk_number FROM chunks WHERE file_id=? ORDER BY chunk_number", (file_id,)).fetchall()]
    missing = [i for i in range(file_row["total_chunks"]) if i not in set(uploaded)]
    conn.close()
    return {"file_id": file_id, "status": file_row["status"], "uploaded_chunks": uploaded, "missing_chunks": missing}


@app.get("/files")
def list_files(x_user: str | None = Header(default=None)):
    owner = require_user(x_user)
    conn = get_conn()
    rows = conn.execute("SELECT file_id, original_filename, file_size, total_chunks, status, created_at FROM files WHERE owner=? ORDER BY created_at DESC", (owner,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/download/metadata/{file_id}")
def download_metadata(file_id: str, x_user: str | None = Header(default=None)):
    owner = require_user(x_user)
    conn = get_conn()
    file_row = conn.execute("SELECT * FROM files WHERE file_id=? AND owner=?", (file_id, owner)).fetchone()
    if not file_row:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")
    chunks = conn.execute("SELECT chunk_number, nonce, hmac_hex, size FROM chunks WHERE file_id=? ORDER BY chunk_number", (file_id,)).fetchall()
    conn.close()
    return {"file": dict(file_row), "chunks": [dict(c) for c in chunks]}


@app.get("/download/chunk/{file_id}/{chunk_number}")
def download_chunk(file_id: str, chunk_number: int, x_user: str | None = Header(default=None)):
    owner = require_user(x_user)
    conn = get_conn()
    file_row = conn.execute("SELECT * FROM files WHERE file_id=? AND owner=?", (file_id, owner)).fetchone()
    if not file_row:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")
    chunk = conn.execute("SELECT * FROM chunks WHERE file_id=? AND chunk_number=?", (file_id, chunk_number)).fetchone()
    conn.close()
    if not chunk:
        raise HTTPException(status_code=404, detail="Chunk not found")
    path = Path(chunk["chunk_path"])
    if not path.exists():
        raise HTTPException(status_code=500, detail="Chunk missing on disk")
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)
