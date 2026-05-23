# edge_gateway.py
# Jalankan SETELAH server aktif.
# Gateway otomatis fetch public key dari server saat startup.
# Gateway enkripsi data sensor dan kirim ke server.
# Jika server mati, gateway buffer ciphertext lokal dan retry saat server hidup.
#
# Jalankan: python edge_gateway.py

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

SERVER_URL  = "http://localhost:5002"
BUFFER_DIR  = "gateway_buffer"
KEYS_DIR    = "gateway_keys"   # public key hasil fetch dari server

os.makedirs(BUFFER_DIR, exist_ok=True)
os.makedirs(KEYS_DIR,   exist_ok=True)

stats = {"sent": 0, "buffered": 0, "retry_sent": 0}


# ══════════════════════════════════════════════════════════════════
# FETCH PUBLIC KEY DARI SERVER
# Dijalankan saat gateway startup — mengambil public key dari server
# ══════════════════════════════════════════════════════════════════

def fetch_public_keys():
    """
    Ambil public key RSA dan ECC dari server.
    Simpan ke gateway_keys/ untuk digunakan saat enkripsi.
    Retry sampai berhasil karena server harus aktif dulu.
    """
    print("[KEY] Mengambil public key dari server...")

    while True:
        try:
            # Fetch RSA public key
            rsa_resp = requests.get(f"{SERVER_URL}/public-key/rsa", timeout=5)
            if rsa_resp.status_code == 200:
                with open(f"{KEYS_DIR}/rsa_public.pem", "wb") as f:
                    f.write(rsa_resp.content)
                print("[KEY] RSA public key berhasil diambil dari server.")
            else:
                raise Exception(f"RSA key fetch failed: {rsa_resp.status_code}")

            # Fetch ECC public key
            ecc_resp = requests.get(f"{SERVER_URL}/public-key/ecc", timeout=5)
            if ecc_resp.status_code == 200:
                with open(f"{KEYS_DIR}/ecc_public.pem", "wb") as f:
                    f.write(ecc_resp.content)
                print("[KEY] ECC public key berhasil diambil dari server.")
            else:
                raise Exception(f"ECC key fetch failed: {ecc_resp.status_code}")

            print("[KEY] Semua public key siap digunakan.\n")
            break

        except Exception as e:
            print(f"[KEY] Gagal ambil public key: {e}")
            print("[KEY] Pastikan server sudah jalan. Retry dalam 3 detik...")
            time.sleep(3)


# ══════════════════════════════════════════════════════════════════
# LOAD PUBLIC KEYS
# ══════════════════════════════════════════════════════════════════

def load_rsa_public_key():
    with open(f"{KEYS_DIR}/rsa_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_ecc_public_key():
    with open(f"{KEYS_DIR}/ecc_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ══════════════════════════════════════════════════════════════════
# ENKRIPSI
# ══════════════════════════════════════════════════════════════════

def encrypt_rsa_mode(plaintext_bytes):
    """
    RSA mode:
    1. Generate session key AES-256 secara acak
    2. Enkripsi session key dengan RSA-OAEP (public key server)
    3. Enkripsi data dengan AES-256-GCM menggunakan session key
    """
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

    # Step 3: Enkripsi data dengan AES-256-GCM (nonce unik tiap enkripsi)
    nonce       = os.urandom(12)   # 96-bit nonce
    aesgcm      = AESGCM(session_key)
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


def encrypt_ecc_mode(plaintext_bytes):
    """
    ECC mode (X25519):
    1. Generate ephemeral keypair X25519 (baru tiap sesi)
    2. Hitung shared secret dengan ECDH (X25519)
    3. Turunkan session key dengan HKDF-SHA256
    4. Enkripsi data dengan AES-256-GCM
    """
    # Step 1: Generate ephemeral keypair (baru tiap enkripsi = forward secrecy)
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

    # Step 4: Enkripsi data dengan AES-256-GCM
    nonce       = os.urandom(12)
    aesgcm      = AESGCM(session_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

    ciphertext = ct_with_tag[:-16]
    tag        = ct_with_tag[-16:]

    # X25519 public key dalam format Raw (32 byte)
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


# ══════════════════════════════════════════════════════════════════
# KIRIM KE SERVER / BUFFER
# ══════════════════════════════════════════════════════════════════

def send_to_server(packet):
    """Coba kirim ke server. Return True jika berhasil."""
    try:
        resp = requests.post(f"{SERVER_URL}/store", json=packet, timeout=3)
        return resp.status_code == 200
    except Exception:
        return False


def save_to_buffer(packet):
    """Simpan ciphertext ke file lokal. TIDAK menyimpan plaintext."""
    filename = os.path.join(BUFFER_DIR, f"packet_{int(time.time()*1000)}.json")
    with open(filename, "w") as f:
        json.dump(packet, f)
    print(f"  [BUFFER] Disimpan: {os.path.basename(filename)}")


def retry_buffer():
    """Background thread: kirim ulang buffer saat server aktif kembali."""
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
                    print(f"  [RETRY OK] {fname}")
                else:
                    print(f"  [RETRY FAIL] Server masih mati.")
                    break
            except Exception as e:
                print(f"  [RETRY ERROR] {fname}: {e}")


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.route("/receive", methods=["POST"])
def receive_from_sensor():
    """Terima data plaintext dari sensor, enkripsi, kirim ke server."""
    body        = request.get_json()
    sensor_data = body["sensor_data"]
    mode        = body.get("mode", "ECC").upper()

    plaintext_bytes = json.dumps(sensor_data).encode("utf-8")

    # Enkripsi sesuai mode
    if mode == "RSA":
        packet = encrypt_rsa_mode(plaintext_bytes)
    else:
        packet = encrypt_ecc_mode(plaintext_bytes)

    # Tambahkan metadata (di luar ciphertext)
    packet["sensor_id"]       = sensor_data["sensor_id"]
    packet["timestamp"]       = sensor_data["timestamp"]
    packet["sequence_number"] = sensor_data["sequence_number"]

    # Kirim ke server atau buffer
    if send_to_server(packet):
        stats["sent"] += 1
        print(f"[SENT] seq#{str(sensor_data['sequence_number']).zfill(5)} | "
              f"mode={mode} | total_sent={stats['sent']}")
    else:
        stats["buffered"] += 1
        print(f"[BUFFER] Server mati. seq#{str(sensor_data['sequence_number']).zfill(5)} | "
              f"total_buffered={stats['buffered']}")
        save_to_buffer(packet)

    return jsonify({"status": "ok"})


@app.route("/stats", methods=["GET"])
def get_stats():
    pending = len(os.listdir(BUFFER_DIR))
    return jsonify({**stats, "pending_in_buffer": pending})


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("  EDGE GATEWAY — Smart Agriculture Crypto System")
    print("=" * 55)

    # Fetch public key dari server sebelum gateway mulai
    fetch_public_keys()

    # Jalankan retry buffer di background
    t = threading.Thread(target=retry_buffer, daemon=True)
    t.start()

    print(f"[INFO] Buffer directory: {BUFFER_DIR}/")
    print(f"[INFO] Gateway started on port 5001\n")
    app.run(port=5001)
