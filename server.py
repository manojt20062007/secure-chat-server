from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import os

app = Flask(__name__)
CORS(app)

DB_FILE = "chat.db"

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# ---------- PASSWORD HASH ----------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------- SIGNUP ----------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")

    if not username or not password or not public_key:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "User already exists"}), 400

    c.execute("INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
              (username, hash_password(password), public_key))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "signup ok"})

# ---------- LOGIN ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "User not found"}), 400

    if row[0] != hash_password(password):
        return jsonify({"status": "error", "message": "Invalid password"}), 400

    return jsonify({"status": "success", "message": "login ok"})

# ---------- GET PUBLIC KEY ----------
@app.route("/get_pubkey/<username>", methods=["GET"])
def get_pubkey(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "User not found"}), 404

    return jsonify({"status": "success", "public_key": row[0]})

# ---------- SEND MESSAGE ----------
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    sender = data.get("sender")
    receiver = data.get("receiver")
    message = data.get("message")

    if not sender or not receiver or not message:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
              (sender, receiver, message))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Message sent"})

# ---------- FETCH MESSAGES ----------
@app.route("/fetch/<username>", methods=["GET"])
def fetch_messages(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT sender, message FROM messages WHERE receiver=?", (username,))
    rows = c.fetchall()
    conn.close()

    messages = [{"sender": r[0], "message": r[1]} for r in rows]
    return jsonify({"status": "success", "messages": messages})

# ---------- START ----------
if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        init_db()
    app.run(host="0.0.0.0", port=5000)
