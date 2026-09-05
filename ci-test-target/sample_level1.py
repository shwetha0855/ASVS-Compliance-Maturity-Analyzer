import os, bcrypt, secrets, logging
from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text

app = Flask(__name__)
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(b"password", salt)
bcrypt.checkpw(b"password", hashed)
saltRounds = 12
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["5 per minute"])
token = secrets.token_urlsafe(16)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["DEBUG"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
FLASK_DEBUG = "0"
rand = secrets.token_hex(32)
rand_bytes = os.urandom(32)

def get_user(db, uid):
    return db.execute(text("SELECT * FROM users WHERE id=:id"), {"id": uid})

@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e): return jsonify({"error": "Internal server error"}), 500

@app.after_request
def headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(debug=False)
