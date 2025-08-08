# server.py
import os
import sqlite3
import base64
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify, Response, stream_with_context
from crypto_utils import hash_password

DB_FILE = os.environ.get("DB_FILE", "users.db")
PORT = int(os.environ.get("PORT", 8080))

app = Flask(__name__)

# in-memory messages queue (each entry: {"id": int, "data": base64str, "timestamp": iso})
# persisted in sqlite as well
NEW_MSG_COND = threading.Condition()
NEXT_MSG_ID = 1

# --- DB helpers ---
def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    data TEXT NOT NULL,
                    ts TEXT NOT NULL
                )""")
    conn.commit()
    conn.close()

def create_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    return row[0] == hash_password(password)

def store_message_base64(b64data):
    ts = datetime.utcnow().isoformat() + "Z"
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO messages (data, ts) VALUES (?, ?)", (b64data, ts))
    mid = c.lastrowid
    conn.commit()
    conn.close()
    # notify SSE listeners
    with NEW_MSG_COND:
        NEW_MSG_COND.notify_all()
    return {"id": mid, "data": b64data, "ts": ts}

def load_messages(since_id=0, limit=100):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if since_id:
        c.execute("SELECT id,data,ts FROM messages WHERE id > ? ORDER BY id ASC LIMIT ?", (since_id, limit))
    else:
        c.execute("SELECT id,data,ts FROM messages ORDER BY id ASC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "data": r[1], "ts": r[2]} for r in rows]

# --- Flask routes ---
@app.route("/")
def home():
    return "✅ Secure Chat Server (E2EE relay) - HTTP API"

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"status":"error","message":"Missing username or password"}), 400
    if create_user(username, password):
        return jsonify({"status":"success","message":"Signup successful"})
    else:
        return jsonify({"status":"error","message":"Username already exists"}), 409

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"status":"error","message":"Missing username or password"}), 400
    if verify_user(username, password):
        return jsonify({"status":"success","message":"Login successful"})
    else:
        return jsonify({"status":"error","message":"Invalid credentials"}), 401

@app.route("/send", methods=["POST"])
def send_message():
    """
    Accepts JSON:
    {
      "username": "...",
      "message": "<base64-encoded encrypted bytes>"
    }
    Server stores the base64 blob and not attempt to decrypt it.
    """
    data = request.json or {}
    username = data.get("username", "").strip()
    b64msg = data.get("message", "")
    if not username or not b64msg:
        return jsonify({"status":"error","message":"Missing fields"}), 400
    # optional: authenticate user by password token — here we assume caller is authenticated
    # Validate base64
    try:
        _ = base64.b64decode(b64msg)
    except Exception:
        return jsonify({"status":"error","message":"message must be base64"}), 400
    rec = store_message_base64(b64msg)
    return jsonify({"status":"success","message":"Stored", "id": rec["id"]})

@app.route("/messages", methods=["GET"])
def get_messages():
    """
    Query parameters:
      since_id=<int>  -> return messages with id > since_id
      limit=<int>
    """
    try:
        since_id = int(request.args.get("since_id") or 0)
    except:
        since_id = 0
    try:
        limit = int(request.args.get("limit") or 100)
    except:
        limit = 100
    msgs = load_messages(since_id=since_id, limit=limit)
    return jsonify({"messages": msgs})

@app.route("/stream")
def stream():
    """
    SSE stream: yields new messages as they arrive in server (base64 payloads).
    Clients can connect and listen for `message` events.
    Optionally ?since_id=<int> to start from an ID.
    """
    try:
        last_id = int(request.args.get("since_id") or 0)
    except:
        last_id = 0

    def event_stream():
        nonlocal last_id
        # First send any pending messages
        while True:
            pending = load_messages(since_id=last_id, limit=100)
            if pending:
                for m in pending:
                    last_id = max(last_id, m["id"])
                    payload = m["data"]
                    ts = m["ts"]
                    # SSE event
                    yield f"event: message\ndata: {payload}\ndata: {ts}\n\n"
                # continue to wait for new notifications
            # wait until new message notification
            with NEW_MSG_COND:
                NEW_MSG_COND.wait(timeout=30.0)  # wake periodically to keep connection alive
            # loop and check pending again

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

# --- start ---
def main():
    init_db()
    # When deployed on Render, Render sets PORT env and expects the web process only
    # We run Flask app directly and let clients use HTTP endpoints /stream or /messages
    app.run(host="0.0.0.0", port=PORT)

if __name__ == "__main__":
    main()
