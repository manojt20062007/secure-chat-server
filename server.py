# server.py
import os
import sqlite3
import time
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from crypto_utils import hash_password, serialize_public_key

DB_FILE = os.environ.get("DB_FILE", "secure_chat.db")
app = Flask(__name__)
CORS(app)

# --- DB setup ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        public_key TEXT NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        ts INTEGER NOT NULL
    )""")
    conn.commit()
    conn.close()

# --- Helper DB funcs ---
def insert_user(username, pwd_hash, public_key_b64):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)",
                  (username, pwd_hash, public_key_b64))
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
    return row and row[0] == hash_password(password)

def get_public_key(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def store_message(sender, recipient, nonce_b64, ciphertext_b64):
    ts = int(time.time())
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, recipient, nonce, ciphertext, ts) VALUES (?, ?, ?, ?, ?)",
              (sender, recipient, nonce_b64, ciphertext_b64, ts))
    conn.commit()
    conn.close()

def fetch_messages_for(recipient):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, sender, nonce, ciphertext, ts FROM messages WHERE recipient = ? ORDER BY id ASC", (recipient,))
    rows = c.fetchall()
    conn.close()
    return rows

# --- Simple auth token (not a production JWT) ---
TOKENS = {}  # token -> username

def make_token(username):
    import uuid
    t = str(uuid.uuid4())
    TOKENS[t] = username
    return t

def get_username_from_token(token):
    return TOKENS.get(token)

# --- Routes ---
@app.route("/")
def home():
    return "✅ Secure Chat Server (E2EE) running"

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")  # base64 public key bytes

    if not username or not password or not public_key:
        return jsonify({"status": "error", "message": "username/password/public_key required"}), 400

    ok = insert_user(username, hash_password(password), public_key)
    if not ok:
        return jsonify({"status": "error", "message": "username exists"}), 409

    return jsonify({"status": "success", "message": "signup ok"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    if verify_user(username, password):
        token = make_token(username)
        return jsonify({"status": "success", "token": token})
    return jsonify({"status": "error", "message": "invalid credentials"}), 401

@app.route("/public_key/<username>", methods=["GET"])
def public_key(username):
    pk = get_public_key(username)
    if not pk:
        return jsonify({"status": "error", "message": "user not found"}), 404
    return jsonify({"status": "success", "username": username, "public_key": pk})

@app.route("/send", methods=["POST"])
def send_message():
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    username = get_username_from_token(token)
    if not username:
        return jsonify({"status": "error", "message": "unauthenticated"}), 401

    data = request.json or {}
    recipient = data.get("recipient")
    nonce_b64 = data.get("nonce")
    ciphertext_b64 = data.get("ciphertext")

    if not recipient or not nonce_b64 or not ciphertext_b64:
        return jsonify({"status": "error", "message": "missing fields"}), 400

    # store without attempting to decrypt
    store_message(username, recipient, nonce_b64, ciphertext_b64)
    return jsonify({"status": "success", "message": "stored"})

@app.route("/messages", methods=["GET"])
def get_messages():
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    username = get_username_from_token(token)
    if not username:
        return jsonify({"status": "error", "message": "unauthenticated"}), 401

    rows = fetch_messages_for(username)
    results = []
    for _id, sender, nonce_b64, ciphertext_b64, ts in rows:
        results.append({
            "id": _id,
            "sender": sender,
            "nonce": nonce_b64,
            "ciphertext": ciphertext_b64,
            "ts": ts
        })
    return jsonify({"status": "success", "messages": results})

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
