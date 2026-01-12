import json
import os
import secrets
import time
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from flask import Flask, jsonify, request, send_from_directory
import jwt

app = Flask(__name__)

PORT = int(os.getenv("PORT", "4001"))
JWT_SECRET = os.getenv("JWT_SECRET", "replace-this-in-production")
ACCESS_TTL_MS = int(os.getenv("ACCESS_TTL_MS", str(15 * 60 * 1000)))
REFRESH_TTL_MS = int(os.getenv("REFRESH_TTL_MS", str(7 * 24 * 60 * 60 * 1000)))
COOKIE_SAMESITE_RAW = os.getenv("COOKIE_SAMESITE", "lax").lower()
COOKIE_SAMESITE = {
    "lax": "Lax",
    "strict": "Strict",
    "none": "None",
}.get(COOKIE_SAMESITE_RAW, "Lax")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "").lower() in ("1", "true", "yes")

DEFAULT_ORIGINS = [
    f"http://localhost:{PORT}",
    f"http://127.0.0.1:{PORT}",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8001",
    "http://127.0.0.1:8001",
]
ALLOWED_ORIGINS = set(
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", ",".join(DEFAULT_ORIGINS)).split(",")
    if origin.strip()
)

challenges = {}
refresh_store = {}


def now_ms() -> int:
    return int(time.time() * 1000)


def ok(data):
    return {"code": 0, "message": "ok", "data": data, "timestamp": now_ms()}


def fail(code, message):
    return {"code": code, "message": message, "data": None, "timestamp": now_ms()}


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/api/v1/public/auth/challenge", methods=["POST", "OPTIONS"])
def challenge():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}
    address = data.get("address")
    if not address:
        return jsonify(fail(400, "Missing address")), 400

    nonce = secrets.token_hex(8)
    issued_at = now_ms()
    expires_at = issued_at + 5 * 60 * 1000
    challenge_text = f"Sign to login\n\nnonce: {nonce}\nissuedAt: {issued_at}"

    challenges[address.lower()] = {
        "challenge": challenge_text,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }

    return jsonify(
        ok(
            {
                "address": address,
                "challenge": challenge_text,
                "nonce": nonce,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
            }
        )
    )


@app.route("/api/v1/public/auth/verify", methods=["POST", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}
    address = data.get("address")
    signature = data.get("signature")
    if not address or not signature:
        return jsonify(fail(400, "Missing address or signature")), 400

    key = address.lower()
    record = challenges.get(key)
    if not record:
        return jsonify(fail(400, "Challenge expired")), 400

    if now_ms() > record["expiresAt"]:
        challenges.pop(key, None)
        return jsonify(fail(400, "Challenge expired")), 400

    try:
        message = encode_defunct(text=record["challenge"])
        recovered = Account.recover_message(message, signature=signature)
        if recovered.lower() != key:
            return jsonify(fail(401, "Invalid signature")), 401
    except Exception:
        return jsonify(fail(401, "Invalid signature")), 401

    challenges.pop(key, None)

    access_token, access_expires_at, refresh_expires_at, refresh_token = issue_tokens(key)
    response = jsonify(
        ok(
            {
                "address": key,
                "token": access_token,
                "expiresAt": access_expires_at,
                "refreshExpiresAt": refresh_expires_at,
            }
        )
    )
    set_refresh_cookie(response, refresh_token, int(REFRESH_TTL_MS / 1000))
    return response


@app.route("/api/v1/public/auth/refresh", methods=["POST", "OPTIONS"])
def refresh():
    if request.method == "OPTIONS":
        return ("", 204)

    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify(fail(401, "Missing refresh token")), 401

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        response = jsonify(fail(401, "Invalid refresh token"))
        clear_refresh_cookie(response)
        return response, 401

    if payload.get("typ") != "refresh" or not payload.get("jti"):
        response = jsonify(fail(401, "Invalid refresh token"))
        clear_refresh_cookie(response)
        return response, 401

    record = refresh_store.get(payload["jti"])
    if not record or record["address"] != payload.get("address") or now_ms() > record["expiresAt"]:
        refresh_store.pop(payload["jti"], None)
        response = jsonify(fail(401, "Refresh token expired"))
        clear_refresh_cookie(response)
        return response, 401

    refresh_store.pop(payload["jti"], None)

    access_token, access_expires_at, refresh_expires_at, refresh_token = issue_tokens(payload["address"])
    response = jsonify(
        ok(
            {
                "address": payload["address"],
                "token": access_token,
                "expiresAt": access_expires_at,
                "refreshExpiresAt": refresh_expires_at,
            }
        )
    )
    set_refresh_cookie(response, refresh_token, int(REFRESH_TTL_MS / 1000))
    return response


@app.route("/api/v1/public/auth/logout", methods=["POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        return ("", 204)

    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=["HS256"])
            jti = payload.get("jti")
            if jti:
                refresh_store.pop(jti, None)
        except Exception:
            pass

    response = jsonify(ok({"logout": True}))
    clear_refresh_cookie(response)
    return response


@app.route("/api/v1/private/profile", methods=["GET", "OPTIONS"])
def profile():
    if request.method == "OPTIONS":
        return ("", 204)

    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify(fail(401, "Missing access token")), 401

    token = parts[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return jsonify(fail(401, "Invalid or expired access token")), 401

    if payload.get("typ") != "access":
        return jsonify(fail(401, "Invalid access token")), 401

    return jsonify(ok({"address": payload.get("address"), "issuedAt": now_ms()}))


def issue_tokens(address: str):
    refresh_id = secrets.token_hex(16)
    refresh_expires_at = now_ms() + REFRESH_TTL_MS
    refresh_store[refresh_id] = {"address": address, "expiresAt": refresh_expires_at}

    refresh_token = jwt.encode(
        {
            "address": address,
            "typ": "refresh",
            "jti": refresh_id,
            "exp": int(time.time() + REFRESH_TTL_MS / 1000),
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    access_token = jwt.encode(
        {
            "address": address,
            "typ": "access",
            "sid": refresh_id,
            "exp": int(time.time() + ACCESS_TTL_MS / 1000),
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    return access_token, now_ms() + ACCESS_TTL_MS, refresh_expires_at, refresh_token


def set_refresh_cookie(response, token: str, max_age: int):
    response.set_cookie(
        "refresh_token",
        token,
        max_age=max_age,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/api/v1/public/auth",
    )


def clear_refresh_cookie(response):
    response.set_cookie(
        "refresh_token",
        "",
        max_age=0,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/api/v1/public/auth",
    )


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = (BASE_DIR / ".." / ".." / "frontend").resolve()
DIST_DIR = (BASE_DIR / ".." / ".." / ".." / "dist").resolve()


@app.route("/dist/<path:filename>")
def dist_files(filename):
    return send_from_directory(DIST_DIR, filename)


@app.route("/dapp.html")
def dapp_page():
    return send_from_directory(FRONTEND_DIR, "dapp.html")


@app.route("/")
def root_page():
    return send_from_directory(FRONTEND_DIR, "dapp.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
