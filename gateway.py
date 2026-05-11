# edge_gateway.py
# Jalankan: python edge_gateway.py
# Menerima data dari sensor, mengenkripsi, mengirim ke server.
# Jika server mati, ciphertext disimpan ke buffer lokal.

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests
import json
import os
import time
import threading

app = Flask(__name__)

SERVER_URL  = "http://localhost:5002/store"
BUFFER_DIR  = "gateway_buffer"
os.makedirs(BUFFER_DIR, exist_ok=True)

# Statistik gateway
stats = {"sent": 0, "buffered": 0, "retry_sent": 0}


# ── Load Public Keys ──────────────────────────────────────────────────────────
def load_rsa_public_key():
    with open("keys/rsa_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_ecc_public_key():
    with open("keys/ecc_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ── Enkripsi RSA Mode ─────────────────────────────────────────────────────────
def encrypt_rsa_mode(plaintext_bytes):
    # Step 1: Generate session key AES-256 (32 byte random)
    session_key = os.urandom(32)

    # Step 2: Enkripsi session key dengan RSA-OAEP
    rsa_pub = load_rsa_public_key()
    encrypted_session_key = rsa_pub.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 3: Enkripsi data sensor dengan AES-256-GCM (nonce unik tiap enkripsi)
    nonce = os.urandom(12)   # 96-bit nonce
    aesgcm = AESGCM(session_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

    ciphertext = ct_with_tag[:-16]
    tag        = ct_with_tag[-16:]

    return {
        "mode":                  "RSA",
        "algorithm":             "RSA-OAEP-SHA256-AES-256-GCM",
        "encrypted_session_key": encrypted_session_key.hex(),
        "nonce":                 nonce.hex(),
        "ciphertext":            ciphertext.hex(),
        "tag":                   tag.hex()
    }


# ── Enkripsi ECC Mode (X25519 / Curve25519) ───────────────────────────────────
def encrypt_ecc_mode(plaintext_bytes):
    # Step 1: Generate ephemeral keypair X25519 di gateway (baru tiap enkripsi)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public  = ephemeral_private.public_key()

    # Step 2: Hitung shared secret dengan X25519
    server_ecc_pub = load_ecc_public_key()
    shared_secret  = ephemeral_private.exchange(server_ecc_pub)

    # Step 3: Turunkan session key dengan HKDF-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"smart-agriculture-v1"
    )
    session_key = hkdf.derive(shared_secret)

    # Step 4: Enkripsi data sensor dengan AES-256-GCM
    nonce  = os.urandom(12)
    aesgcm = AESGCM(session_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

    ciphertext = ct_with_tag[:-16]
    tag        = ct_with_tag[-16:]

    # X25519 public key diserialisasi dalam format Raw (32 byte)
    epk_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return {
        "mode":                 "ECC",
        "algorithm":            "X25519-HKDF-SHA256-AES-256-GCM",
        "ephemeral_public_key": epk_bytes.hex(),
        "nonce":                nonce.hex(),
        "ciphertext":           ciphertext.hex(),
        "tag":                  tag.hex()
    }


# ── Kirim ke Server / Buffer ──────────────────────────────────────────────────
def send_to_server(packet):
    """Coba kirim ke server. Return True jika berhasil."""
    try:
        resp = requests.post(SERVER_URL, json=packet, timeout=3)
        return resp.status_code == 200
    except Exception:
        return False


def save_to_buffer(packet):
    """Simpan ciphertext ke file lokal. TIDAK menyimpan plaintext."""
    filename = os.path.join(BUFFER_DIR, f"packet_{int(time.time()*1000)}.json")
    with open(filename, "w") as f:
        json.dump(packet, f)
    print(f"  [BUFFER] Disimpan lokal: {filename}")


def retry_buffer():
    """Background thread: coba kirim ulang buffer saat server aktif kembali."""
    while True:
        time.sleep(5)
        files = sorted(os.listdir(BUFFER_DIR))
        if not files:
            continue
        print(f"[RETRY] Mencoba kirim {len(files)} paket dari buffer...")
        for fname in files:
            fpath = os.path.join(BUFFER_DIR, fname)
            try:
                with open(fpath) as f:
                    packet = json.load(f)
                if send_to_server(packet):
                    os.remove(fpath)
                    stats["retry_sent"] += 1
                    print(f"  [RETRY OK] {fname} berhasil dikirim ulang")
                else:
                    print(f"  [RETRY FAIL] Server masih mati, berhenti sementara.")
                    break
            except Exception as e:
                print(f"  [RETRY ERROR] {fname}: {e}")


# ── Endpoint Gateway ──────────────────────────────────────────────────────────
@app.route("/receive", methods=["POST"])
def receive_from_sensor():
    body        = request.get_json()
    sensor_data = body["sensor_data"]
    mode        = body.get("mode", "ECC").upper()

    plaintext_bytes = json.dumps(sensor_data).encode("utf-8")

    # Enkripsi sesuai mode
    if mode == "RSA":
        packet = encrypt_rsa_mode(plaintext_bytes)
    else:
        packet = encrypt_ecc_mode(plaintext_bytes)  # ECC mode = X25519

    # Tambahkan metadata (tidak dienkripsi, di luar ciphertext)
    packet["sensor_id"]       = sensor_data["sensor_id"]
    packet["timestamp"]       = sensor_data["timestamp"]
    packet["sequence_number"] = sensor_data["sequence_number"]

    # Kirim ke server atau buffer
    if send_to_server(packet):
        stats["sent"] += 1
        print(f"[SENT] seq#{sensor_data['sequence_number']:05d} | mode={mode} | "
              f"total_sent={stats['sent']}")
    else:
        stats["buffered"] += 1
        print(f"[BUFFER] Server mati. seq#{sensor_data['sequence_number']:05d} | "
              f"total_buffered={stats['buffered']}")
        save_to_buffer(packet)

    return jsonify({"status": "ok"})


@app.route("/stats", methods=["GET"])
def get_stats():
    pending = len(os.listdir(BUFFER_DIR))
    return jsonify({**stats, "pending_in_buffer": pending})


# ── main ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Jalankan retry buffer di background thread
    t = threading.Thread(target=retry_buffer, daemon=True)
    t.start()
    print("Edge Gateway started on port 5001")
    print(f"Buffer directory: {BUFFER_DIR}/")
    app.run(port=5001)
