from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets

app = Flask(__name__)
CORS(app)

# Store users in-memory: { username: { "password": ..., "token": ... } }
users = {}
messages = []

# ------------------ SIGNUP ------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users:
        return jsonify({"status": "error", "message": "Username already exists"}), 400

    users[username] = {"password": password, "token": None}
    return jsonify({"status": "success", "message": "Signup successful"})


# ------------------ LOGIN ------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users and users[username]["password"] == password:
        token = secrets.token_hex(16)  # Generate secure random token
        users[username]["token"] = token
        return jsonify({"status": "success", "token": token})
    else:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 401


# ------------------ SEND MESSAGE ------------------
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    token = data.get("token")
    message = data.get("message")

    # Find username by token
    username = None
    for user, info in users.items():
        if info["token"] == token:
            username = user
            break

    if username is None:
        return jsonify({"status": "error", "message": "Invalid token"}), 401

    messages.append({"username": username, "message": message})
    return jsonify({"status": "success", "message": "Message sent"})


# ------------------ GET MESSAGES ------------------
@app.route("/messages", methods=["GET"])
def get_messages():
    return jsonify({"status": "success", "messages": messages})


# ------------------ HOME PAGE ------------------
@app.route("/")
def home():
    return "<h1>Secure Chat Server is running!</h1>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
