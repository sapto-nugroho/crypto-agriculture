# server.py
# Jalankan: python server.py
# Menerima ciphertext dari gateway, menyimpan, dan mendekripsi untuk verifikasi.

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import json
import os
import time

app = Flask(__name__)

STORAGE_DIR = "server_storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

stats = {"received": 0, "failed": 0, "tampered_rejected": 0}


# ── Load Private Keys ─────────────────────────────────────────────────────────
def load_rsa_private_key():
    with open("keys/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_ecc_private_key():
    with open("keys/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ── Dekripsi RSA Mode ─────────────────────────────────────────────────────────
def decrypt_rsa_mode(packet):
    rsa_priv = load_rsa_private_key()

    # Step 1: Dekripsi session key dengan RSA-OAEP
    session_key = rsa_priv.decrypt(
        bytes.fromhex(packet["encrypted_session_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 2: Verifikasi tag dan dekripsi ciphertext dengan AES-GCM
    nonce      = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    tag        = bytes.fromhex(packet["tag"])

    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


# ── Dekripsi ECC Mode (X25519 / Curve25519) ───────────────────────────────────
def decrypt_ecc_mode(packet):
    ecc_priv = load_ecc_private_key()

    # Step 1: Load ephemeral public key dari gateway (format Raw 32 byte)
    epk_bytes     = bytes.fromhex(packet["ephemeral_public_key"])
    ephemeral_pub = X25519PublicKey.from_public_bytes(epk_bytes)

    # Step 2: Hitung shared secret dengan X25519
    shared_secret = ecc_priv.exchange(ephemeral_pub)

    # Step 3: Turunkan session key (HKDF parameter identik dengan gateway)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"smart-agriculture-v1"
    )
    session_key = hkdf.derive(shared_secret)

    # Step 4: Verifikasi tag dan dekripsi
    nonce      = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    tag        = bytes.fromhex(packet["tag"])

    aesgcm    = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)

    # Step 3: Turunkan session key (info harus identik dengan gateway)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"smart-agriculture-v1"
    )
    session_key = hkdf.derive(shared_secret)

    # Step 4: Verifikasi tag dan dekripsi
    nonce      = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    tag        = bytes.fromhex(packet["tag"])

    aesgcm    = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


# ── Endpoint Server ───────────────────────────────────────────────────────────
@app.route("/store", methods=["POST"])
def store():
    packet = request.get_json()
    seq    = packet.get("sequence_number", "?")
    mode   = packet.get("mode", "?")

    # Simpan ciphertext ke storage (BUKAN plaintext)
    filename = os.path.join(STORAGE_DIR, f"packet_{int(time.time()*1000)}.json")
    with open(filename, "w") as f:
        json.dump(packet, f)

    # Dekripsi untuk verifikasi (membuktikan sistem berjalan end-to-end)
    try:
        if mode == "RSA":
            plaintext = decrypt_rsa_mode(packet)
        elif mode == "ECC":
            plaintext = decrypt_ecc_mode(packet)
        else:
            return jsonify({"status": "error", "reason": f"Unknown mode: {mode}"}), 400

        stats["received"] += 1
        print(f"[OK] seq#{seq:05d} | mode={mode} | "
              f"temp={plaintext.get('temperature')}°C | "
              f"humidity={plaintext.get('air_humidity')}% | "
              f"total_received={stats['received']}")
        return jsonify({"status": "ok", "seq": seq})

    except InvalidTag:
        stats["tampered_rejected"] += 1
        print(f"[REJECTED] seq#{seq} | Tag tidak valid! Ciphertext mungkin dimodifikasi. "
              f"total_rejected={stats['tampered_rejected']}")
        return jsonify({"status": "rejected", "reason": "Invalid authentication tag"}), 400

    except Exception as e:
        stats["failed"] += 1
        print(f"[ERROR] seq#{seq} | {e}")
        return jsonify({"status": "error", "reason": str(e)}), 500


@app.route("/stats", methods=["GET"])
def get_stats():
    stored = len(os.listdir(STORAGE_DIR))
    return jsonify({**stats, "stored_ciphertexts": stored})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "up"})

# ── main ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Server started on port 5002")
    print(f"Storage directory: {STORAGE_DIR}/")
    app.run(port=5002)
