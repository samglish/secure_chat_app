#!/usr/bin/env python3
import os
import secrets
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "chat.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    last_seen = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(64), index=True, nullable=False)
    sender = db.Column(db.String(64), nullable=False)
    algo = db.Column(db.String(16), nullable=False)  # 'AES-GCM' or 'CAESAR'
    ciphertext = db.Column(db.Text, nullable=False)  # base64
    iv = db.Column(db.String(64))  # base64 IV for AES-GCM; empty for CAESAR
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return dict(
            id=self.id,
            room=self.room,
            sender=self.sender,
            algo=self.algo,
            ciphertext=self.ciphertext,
            iv=self.iv or "",
            created_at=self.created_at.isoformat()
        )

# --- Helpers ---
def update_last_seen(user):
    user.last_seen = datetime.now(timezone.utc)
    db.session.commit()

def get_user_by_token(token: str):
    if not token:
        return None
    return User.query.filter_by(token=token).first()

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username already exists"}), 409
    token = secrets.token_hex(16)
    user = User(username=username, token=token)
    db.session.add(user)
    db.session.commit()
    return jsonify({"token": token, "username": username})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"token": user.token, "username": user.username})

@app.route("/api/message", methods=["POST"])
def post_message():
    data = request.get_json(force=True)
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_by_token(token)
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    room = (data.get("room") or "general").strip()[:64]
    algo = (data.get("algo") or "AES-GCM").strip().upper()
    ciphertext = data.get("ciphertext") or ""
    iv = data.get("iv") or ""

    if not ciphertext:
        return jsonify({"error": "ciphertext required"}), 400
    if algo not in ("AES-GCM", "CAESAR"):
        return jsonify({"error": "unsupported algo"}), 400

    msg = Message(room=room, sender=user.username, algo=algo, ciphertext=ciphertext, iv=iv)
    db.session.add(msg)
    db.session.commit()
    return jsonify({"ok": True, "id": msg.id, "created_at": msg.created_at.isoformat()})

@app.route("/api/messages")
def get_messages():
    room = (request.args.get("room") or "general").strip()[:64]
    after_id = request.args.get("after_id", type=int)
    q = Message.query.filter_by(room=room).order_by(Message.id.asc())
    if after_id:
        q = q.filter(Message.id > after_id)
    msgs = [m.to_dict() for m in q.limit(200).all()]
    return jsonify({"messages": msgs})


@app.route("/api/online-users")
def online_users():
    room = (request.args.get("room") or "general").strip()[:64]
    threshold = datetime.now(timezone.utc) - timedelta(seconds=30)
    active_users = (
        db.session.query(User.username)
        .join(Message, Message.sender == User.username)
        .filter(Message.room == room)
        .filter(User.last_seen > threshold)
        .distinct()
        .all()
    )
    return jsonify({"users": [u[0] for u in active_users]})

# --- CLI init ---
@app.cli.command("init-db")
def init_db():
    """Initialize the database."""
    db.create_all()
    print("Database initialized at:", app.config["SQLALCHEMY_DATABASE_URI"])

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
