import base64
import json
import logging
import os
import secrets
import time
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from flask import Flask, jsonify, request, send_from_directory
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("auth")

PORT = int(os.getenv("PORT", "3204"))
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
UCAN_AUD = os.getenv("UCAN_AUD", f"did:web:127.0.0.1:{PORT}")
# Recommended: UCAN_RESOURCE=app:<appId> and UCAN_ACTION=read,write; appId = frontend domain or IP:port.
UCAN_RESOURCE = os.getenv("UCAN_RESOURCE", "profile")
UCAN_ACTION = os.getenv("UCAN_ACTION", "read")
REQUIRED_UCAN_CAP = [{"resource": UCAN_RESOURCE, "action": UCAN_ACTION}]

DEFAULT_ORIGINS = [
    f"http://127.0.0.1:{PORT}",
    f"http://127.0.0.1:{PORT}",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8001",
    "http://127.0.0.1:8001",
]
for extra_port in (3201, 3202, 3203, 3204):
    DEFAULT_ORIGINS.append(f"http://127.0.0.1:{extra_port}")
    DEFAULT_ORIGINS.append(f"http://127.0.0.1:{extra_port}")
ALLOWED_ORIGINS = set(
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", ",".join(DEFAULT_ORIGINS)).split(",")
    if origin.strip()
)

challenges = {}
refresh_store = {}


def now_ms() -> int:
    return int(time.time() * 1000)


def preview(value: str, keep: int = 8) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2 + 3:
        return value
    return f"{value[:keep]}...{value[-keep:]}"


def ok(data):
    return {"code": 0, "message": "ok", "data": data, "timestamp": now_ms()}


def fail(code, message):
    return {"code": code, "message": message, "data": None, "timestamp": now_ms()}


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def base58_decode(value: str) -> bytes:
    num = 0
    for char in value:
        num *= 58
        index = BASE58_ALPHABET.find(char)
        if index == -1:
            raise ValueError("invalid base58 character")
        num += index
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    n_pad = len(value) - len(value.lstrip("1"))
    return b"\x00" * n_pad + combined


def did_key_to_public_key(did: str) -> bytes:
    if not did or not did.startswith("did:key:z"):
        raise ValueError("invalid did:key format")
    decoded = base58_decode(did[len("did:key:z") :])
    if len(decoded) < 2 or decoded[0] != 0xED or decoded[1] != 0x01:
        raise ValueError("unsupported did:key type")
    return decoded[2:]


def normalize_epoch_ms(value):
    if value is None:
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value * 1000 if value < 1_000_000_000_000 else value


def match_pattern(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def caps_allow(available, required) -> bool:
    if not isinstance(available, list) or not available:
        return False
    for req in required:
        matched = False
        for cap in available:
            if not isinstance(cap, dict):
                continue
            if match_pattern(cap.get("resource", ""), req.get("resource", "")) and match_pattern(
                cap.get("action", ""), req.get("action", "")
            ):
                matched = True
                break
        if not matched:
            return False
    return True


def extract_ucan_statement(message: str):
    for line in message.splitlines():
        trimmed = line.strip()
        if trimmed.upper().startswith("UCAN-AUTH"):
            payload = trimmed[len("UCAN-AUTH") :].lstrip(" :")
            return json.loads(payload)
    return None


def verify_root_proof(root: dict):
    if not isinstance(root, dict) or root.get("type") != "siwe":
        raise ValueError("invalid root proof")
    siwe = root.get("siwe") or {}
    message = siwe.get("message")
    signature = siwe.get("signature")
    if not message or not signature:
        raise ValueError("missing SIWE message")

    recovered = Account.recover_message(encode_defunct(text=message), signature=signature).lower()
    iss = f"did:pkh:eth:{recovered}"
    if root.get("iss") and root.get("iss") != iss:
        logger.warning("UCAN root issuer mismatch rootIss=%s recoveredIss=%s", root.get("iss"), iss)
        raise ValueError("root issuer mismatch")

    statement = extract_ucan_statement(message)
    if not statement:
        raise ValueError("missing UCAN statement")

    aud = statement.get("aud") or root.get("aud")
    cap = statement.get("cap") or root.get("cap")
    exp = normalize_epoch_ms(statement.get("exp") or root.get("exp"))
    nbf = normalize_epoch_ms(statement.get("nbf") or root.get("nbf"))

    if not aud or not isinstance(cap, list) or not exp:
        logger.warning("UCAN root claims invalid aud=%s exp=%s capCount=%s", aud, exp, len(cap) if isinstance(cap, list) else 0)
        raise ValueError("invalid root claims")

    if root.get("aud") and root.get("aud") != aud:
        logger.warning("UCAN root audience mismatch rootAud=%s aud=%s", root.get("aud"), aud)
        raise ValueError("root audience mismatch")
    if root.get("exp") and normalize_epoch_ms(root.get("exp")) != exp:
        logger.warning("UCAN root expiry mismatch rootExp=%s exp=%s", root.get("exp"), exp)
        raise ValueError("root expiry mismatch")

    now = now_ms()
    if nbf and now < nbf:
        raise ValueError("root not active")
    if now > exp:
        raise ValueError("root expired")

    logger.info("UCAN root verified iss=%s aud=%s exp=%s nbf=%s caps=%s", iss, aud, exp, nbf, cap)
    return {"iss": iss, "aud": aud, "cap": cap, "exp": exp, "nbf": nbf}


def decode_ucan_token(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid UCAN token")
    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))
    signature = base64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    return header, payload, signature, signing_input


def verify_ucan_jws(token: str):
    header, payload, signature, signing_input = decode_ucan_token(token)
    if header.get("alg") != "EdDSA":
        raise ValueError("unsupported UCAN alg")
    raw_key = did_key_to_public_key(payload.get("iss", ""))
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(signature, signing_input)
    except InvalidSignature as exc:
        raise ValueError("invalid UCAN signature") from exc

    exp = normalize_epoch_ms(payload.get("exp"))
    nbf = normalize_epoch_ms(payload.get("nbf"))
    now = now_ms()
    if nbf and now < nbf:
        raise ValueError("UCAN not active")
    if exp and now > exp:
        raise ValueError("UCAN expired")

    logger.info(
        "UCAN JWS verified iss=%s aud=%s exp=%s nbf=%s caps=%s",
        payload.get("iss"),
        payload.get("aud"),
        exp,
        nbf,
        payload.get("cap") or [],
    )
    return payload, exp


def verify_proof_chain(current_did: str, required_caps, required_exp, proofs):
    if not isinstance(proofs, list) or not proofs:
        raise ValueError("missing UCAN proof chain")
    logger.info(
        "UCAN proof chain currentDid=%s requiredExp=%s proofs=%s requiredCaps=%s",
        current_did,
        required_exp,
        len(proofs),
        required_caps,
    )
    first = proofs[0]
    if isinstance(first, str):
        payload, exp = verify_ucan_jws(first)
        if payload.get("aud") != current_did:
            raise ValueError(f"UCAN audience mismatch expected={current_did} got={payload.get('aud')}")
        if not caps_allow(payload.get("cap") or [], required_caps):
            raise ValueError("UCAN capability denied")
        if exp and required_exp and exp < required_exp:
            raise ValueError("UCAN proof expired")
        next_proofs = payload.get("prf") or proofs[1:]
        return verify_proof_chain(payload.get("iss"), payload.get("cap") or [], exp, next_proofs)

    root = verify_root_proof(first)
    if root["aud"] != current_did:
        raise ValueError("root audience mismatch")
    if not caps_allow(root["cap"], required_caps):
        raise ValueError("root capability denied")
    if required_exp and root["exp"] < required_exp:
        raise ValueError("root expired")
    return root


def is_ucan_token(token: str) -> bool:
    try:
        header, _, _, _ = decode_ucan_token(token)
        return header.get("typ") == "UCAN" or header.get("alg") == "EdDSA"
    except Exception:
        return False


def verify_ucan_invocation(token: str):
    payload, exp = verify_ucan_jws(token)
    logger.info(
        "UCAN invocation token=%s iss=%s aud=%s exp=%s caps=%s proofs=%s",
        preview(token),
        payload.get("iss"),
        payload.get("aud"),
        exp,
        payload.get("cap") or [],
        len(payload.get("prf") or []),
    )
    if payload.get("aud") != UCAN_AUD:
        raise ValueError(f"UCAN audience mismatch expected={UCAN_AUD} got={payload.get('aud')}")
    if not caps_allow(payload.get("cap") or [], REQUIRED_UCAN_CAP):
        raise ValueError("UCAN capability denied")
    root = verify_proof_chain(payload.get("iss"), payload.get("cap") or [], exp, payload.get("prf") or [])
    address = root["iss"].replace("did:pkh:eth:", "")
    return address


@app.before_request
def start_timer():
    request.environ["start_time"] = time.time()


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    start = request.environ.get("start_time")
    duration_ms = int((time.time() - start) * 1000) if start else -1
    logger.info(
        "HTTP method=%s path=%s status=%s durationMs=%s origin=%s",
        request.method,
        request.path,
        response.status_code,
        duration_ms,
        origin or "",
    )
    return response


@app.route("/api/v1/public/auth/challenge", methods=["POST", "OPTIONS"])
def challenge():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}
    address = data.get("address")
    if not address:
        return jsonify(fail(400, "Missing address")), 400
    logger.info("Auth challenge request address=%s", address)

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
    logger.info("Auth verify request address=%s signature=%s", address, preview(signature))

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
        logger.warning("Auth verify failed address=%s", key)
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
    logger.info("Auth refresh request token=%s", preview(refresh_token))

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
    logger.info("Auth refresh success address=%s", payload.get("address"))

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
    logger.info("Auth logout")
    return response


@app.route("/api/v1/public/profile", methods=["GET", "OPTIONS"])
def profile():
    if request.method == "OPTIONS":
        return ("", 204)

    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify(fail(401, "Missing access token")), 401

    token = parts[1]
    if is_ucan_token(token):
        try:
            address = verify_ucan_invocation(token)
        except Exception as exc:
            logger.warning("UCAN profile failed error=%s", exc)
            return jsonify(fail(401, str(exc))), 401
        logger.info("UCAN profile ok address=%s", address)
        return jsonify(ok({"address": address, "issuedAt": now_ms()}))

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        logger.warning("JWT profile failed")
        return jsonify(fail(401, "Invalid or expired access token")), 401

    if payload.get("typ") != "access":
        return jsonify(fail(401, "Invalid access token")), 401

    logger.info("JWT profile ok address=%s", payload.get("address"))
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
