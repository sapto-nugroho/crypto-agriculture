# server.py
# Jalankan PERTAMA sebelum gateway dan sensor.
# Server generate semua key saat pertama kali dijalankan.
# Server expose public key ke gateway via endpoint /public-key/rsa dan /public-key/ecc
# Server menyediakan Web Dashboard di http://localhost:5002/dashboard
#
# Jalankan: python server.py

from flask import Flask, request, jsonify, send_file, render_template
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import json
import os
import time
from collections import deque

app = Flask(__name__)

KEYS_DIR    = "keys"
STORAGE_DIR = "server_storage"
os.makedirs(KEYS_DIR,    exist_ok=True)
os.makedirs(STORAGE_DIR, exist_ok=True)

stats = {"received": 0, "failed": 0, "tampered_rejected": 0}

# Log aktivitas untuk dashboard (simpan 50 entri terakhir)
activity_log = deque(maxlen=50)
# Data sensor terbaru untuk dashboard
latest_packets = deque(maxlen=20)
start_time = time.time()

# Mode aktif sistem — bisa diubah dari dashboard
active_mode = "ECC"   # default ECC
mode_history = deque(maxlen=50)  # log riwayat pergantian mode


# ══════════════════════════════════════════════════════════════════
# GENERATE KEY — dijalankan otomatis saat server pertama kali start
# ══════════════════════════════════════════════════════════════════

def generate_rsa_keys():
    """Generate pasangan kunci RSA-2048 untuk server."""
    print("[KEY] Generating RSA-2048 keypair...")
    t_start = time.perf_counter()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    with open(f"{KEYS_DIR}/rsa_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"{KEYS_DIR}/rsa_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 4)
    print(f"[KEY] RSA-2048 keys generated.  ({elapsed_ms} ms)")
    return elapsed_ms


def generate_ecc_keys():
    """Generate pasangan kunci ECC X25519 (Curve25519) untuk server."""
    print("[KEY] Generating ECC X25519 keypair...")
    t_start = time.perf_counter()

    private_key = X25519PrivateKey.generate()
    with open(f"{KEYS_DIR}/ecc_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"{KEYS_DIR}/ecc_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 4)
    print(f"[KEY] ECC X25519 keys generated. ({elapsed_ms} ms)")
    return elapsed_ms


def verify_rsa_keypair():
    """
    Verifikasi pasangan kunci RSA: enkripsi test dengan public key,
    dekripsi dengan private key, cek hasilnya cocok.
    """
    test_data   = b"smart-agriculture-rsa-verify"
    private_key = load_rsa_private_key()
    public_key  = private_key.public_key()

    t_start = time.perf_counter()
    ciphertext = public_key.encrypt(
        test_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 4)
    return (decrypted == test_data), elapsed_ms


def verify_ecc_keypair():
    """
    Verifikasi pasangan kunci ECC X25519: simulasi ECDH penuh —
    ephemeral key + server key → derive session key → enkripsi → dekripsi.
    """
    test_data   = b"smart-agriculture-ecc-verify"
    private_key = load_ecc_private_key()
    public_key  = private_key.public_key()

    t_start = time.perf_counter()

    # Sisi gateway: generate ephemeral, hitung shared secret, enkripsi
    ephemeral_priv = X25519PrivateKey.generate()
    shared_a       = ephemeral_priv.exchange(public_key)
    key_a          = HKDF(algorithm=hashes.SHA256(), length=32,
                          salt=None, info=b"smart-agriculture-v1").derive(shared_a)
    nonce          = os.urandom(12)
    ciphertext     = AESGCM(key_a).encrypt(nonce, test_data, None)

    # Sisi server: hitung shared secret dengan ephemeral pub, dekripsi
    epk_bytes  = ephemeral_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    shared_b   = private_key.exchange(X25519PublicKey.from_public_bytes(epk_bytes))
    key_b      = HKDF(algorithm=hashes.SHA256(), length=32,
                      salt=None, info=b"smart-agriculture-v1").derive(shared_b)
    decrypted  = AESGCM(key_b).decrypt(nonce, ciphertext, None)

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 4)
    return (decrypted == test_data), elapsed_ms


def generate_keys_if_not_exist():
    """
    Generate semua key jika belum ada.
    Dipanggil otomatis saat server start.
    Jika key sudah ada, tidak di-generate ulang.
    Setelah generate/load, verifikasi pasangan kunci dan print laporan waktu.
    """
    print("─" * 55)

    rsa_exists = os.path.exists(f"{KEYS_DIR}/rsa_private.pem")
    ecc_exists = os.path.exists(f"{KEYS_DIR}/ecc_private.pem")

    # ── Generate (atau skip) ──────────────────────────────────────
    if not rsa_exists:
        rsa_keygen_ms = generate_rsa_keys()
    else:
        print("[KEY] RSA keys already exist, skipping generation.")
        rsa_keygen_ms = None

    if not ecc_exists:
        ecc_keygen_ms = generate_ecc_keys()
    else:
        print("[KEY] ECC keys already exist, skipping generation.")
        ecc_keygen_ms = None

    # ── Verifikasi pasangan kunci ─────────────────────────────────
    print("─" * 55)
    print("[KEY] Verifying keypairs...")

    rsa_ok, rsa_verify_ms = verify_rsa_keypair()
    ecc_ok, ecc_verify_ms = verify_ecc_keypair()

    rsa_status = "✓ VALID" if rsa_ok else "✗ TIDAK VALID"
    ecc_status = "✓ VALID" if ecc_ok else "✗ TIDAK VALID"

    print(f"  RSA-2048  : {rsa_status}  (verify: {rsa_verify_ms} ms)")
    print(f"  ECC X25519: {ecc_status}  (verify: {ecc_verify_ms} ms)")

    # ── Laporan ringkasan ─────────────────────────────────────────
    print("─" * 55)
    print("[KEY] ── Laporan Waktu Key ──────────────────────────")
    if rsa_keygen_ms is not None:
        print(f"  RSA-2048   generate : {rsa_keygen_ms} ms")
    else:
        print(f"  RSA-2048   generate : (key sudah ada, tidak di-generate ulang)")
    print(f"  RSA-2048   verify   : {rsa_verify_ms} ms  → {rsa_status}")

    if ecc_keygen_ms is not None:
        print(f"  ECC X25519 generate : {ecc_keygen_ms} ms")
    else:
        print(f"  ECC X25519 generate : (key sudah ada, tidak di-generate ulang)")
    print(f"  ECC X25519 verify   : {ecc_verify_ms} ms  → {ecc_status}")

    if not rsa_ok or not ecc_ok:
        print("\n  [PERINGATAN] Ada pasangan kunci yang tidak valid!")
        print("  Hapus folder keys/ dan restart server untuk generate ulang.")
    else:
        print("\n  Semua pasangan kunci valid. Server siap.")
    print("─" * 55)


# ══════════════════════════════════════════════════════════════════
# LOAD PRIVATE KEYS
# ══════════════════════════════════════════════════════════════════

def load_rsa_private_key():
    with open(f"{KEYS_DIR}/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_ecc_private_key():
    with open(f"{KEYS_DIR}/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ══════════════════════════════════════════════════════════════════
# DEKRIPSI
# ══════════════════════════════════════════════════════════════════

def decrypt_rsa_mode(packet):
    """Dekripsi paket RSA mode."""
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

    # Step 2: Verifikasi tag dan dekripsi data dengan AES-GCM
    nonce      = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    tag        = bytes.fromhex(packet["tag"])

    aesgcm    = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


def decrypt_ecc_mode(packet):
    """Dekripsi paket ECC mode (X25519)."""
    ecc_priv = load_ecc_private_key()

    # Step 1: Load ephemeral public key dari gateway (format Raw 32 byte)
    epk_bytes     = bytes.fromhex(packet["ephemeral_public_key"])
    ephemeral_pub = X25519PublicKey.from_public_bytes(epk_bytes)

    # Step 2: Hitung shared secret dengan X25519
    shared_secret = ecc_priv.exchange(ephemeral_pub)

    # Step 3: Turunkan session key dengan HKDF-SHA256
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


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS — PUBLIC KEY DISTRIBUTION
# Gateway mengambil public key dari sini saat startup
# ══════════════════════════════════════════════════════════════════

@app.route("/public-key/rsa", methods=["GET"])
def get_rsa_public_key():
    """
    Gateway fetch public key RSA dari endpoint ini.
    Public key boleh diketahui siapapun — tidak rahasia.
    """
    return send_file(f"{KEYS_DIR}/rsa_public.pem", mimetype="application/x-pem-file")


@app.route("/public-key/ecc", methods=["GET"])
def get_ecc_public_key():
    """
    Gateway fetch public key ECC dari endpoint ini.
    Public key boleh diketahui siapapun — tidak rahasia.
    """
    return send_file(f"{KEYS_DIR}/ecc_public.pem", mimetype="application/x-pem-file")


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS — TERIMA CIPHERTEXT
# ══════════════════════════════════════════════════════════════════

@app.route("/store", methods=["POST"])
def store():
    """Terima ciphertext dari gateway, simpan, dan dekripsi untuk verifikasi."""
    packet = request.get_json()
    seq    = packet.get("sequence_number", "?")
    mode   = packet.get("mode", "?").upper()

    # Simpan ciphertext ke storage (BUKAN plaintext)
    filename = os.path.join(STORAGE_DIR, f"packet_{int(time.time()*1000)}.json")
    with open(filename, "w") as f:
        json.dump(packet, f)

    # Catat waktu mulai dekripsi
    t_dec_start = time.perf_counter()

    # Dekripsi untuk verifikasi end-to-end
    try:
        if mode == "RSA":
            plaintext = decrypt_rsa_mode(packet)
        elif mode == "ECC":
            plaintext = decrypt_ecc_mode(packet)
        else:
            return jsonify({"status": "error", "reason": f"Unknown mode: {mode}"}), 400

        # Hitung waktu dekripsi sisi server
        dec_ms = round((time.perf_counter() - t_dec_start) * 1000, 4)

        stats["received"] += 1

        # Simpan ke log aktivitas dan data terbaru untuk dashboard
        log_entry = {
            "time":     time.strftime("%H:%M:%S"),
            "seq":      seq,
            "mode":     mode,
            "status":   "ok",
            "temp":     plaintext.get("temperature"),
            "humidity": plaintext.get("air_humidity"),
            "moisture": plaintext.get("soil_moisture"),
            "ph":       plaintext.get("soil_ph"),
            "sensor_id": plaintext.get("sensor_id"),
        }
        activity_log.appendleft(log_entry)
        latest_packets.appendleft(log_entry)

        print(f"[OK] seq#{str(seq).zfill(5)} | mode={mode} | "
              f"dec={dec_ms}ms | "
              f"temp={plaintext.get('temperature')}°C | "
              f"humidity={plaintext.get('air_humidity')}% | "
              f"total_received={stats['received']}")
        
        # Kembalikan dec_ms + payload_size_bytes ke gateway/experiment
        payload_size = len(request.data)   # ukuran ciphertext JSON yang diterima server (bytes)
        return jsonify({
            "status":             "ok",
            "seq":                seq,
            "dec_ms":             dec_ms,
            "payload_size_bytes": payload_size
        })

    except InvalidTag:
        stats["tampered_rejected"] += 1
        log_entry = {
            "time":   time.strftime("%H:%M:%S"),
            "seq":    seq,
            "mode":   mode,
            "status": "rejected",
        }
        activity_log.appendleft(log_entry)
        print(f"[REJECTED] seq#{seq} | Tag tidak valid! "
              f"total_rejected={stats['tampered_rejected']}")
        return jsonify({"status": "rejected",
                        "reason": "Invalid authentication tag"}), 400

    except Exception as e:
        stats["failed"] += 1
        log_entry = {
            "time":   time.strftime("%H:%M:%S"),
            "seq":    seq,
            "mode":   mode,
            "status": "error",
            "reason": str(e),
        }
        activity_log.appendleft(log_entry)
        print(f"[ERROR] seq#{seq} | {e}")
        return jsonify({"status": "error", "reason": str(e)}), 500


@app.route("/stats", methods=["GET"])
def get_stats():
    stored = len(os.listdir(STORAGE_DIR))
    return jsonify({**stats, "stored_ciphertexts": stored})


@app.route("/health", methods=["GET"])
def health():
    uptime = int(time.time() - start_time)
    return jsonify({"status": "up", "uptime_seconds": uptime})


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS — DASHBOARD
# ══════════════════════════════════════════════════════════════════

@app.route("/dashboard")
def dashboard():
    """Halaman utama Web Dashboard."""
    return render_template("dashboard.html")


@app.route("/api/dashboard-data", methods=["GET"])
def dashboard_data():
    """
    API endpoint untuk dashboard — dipanggil setiap 2 detik oleh browser.
    Mengembalikan semua data yang dibutuhkan dashboard dalam satu request.
    """
    stored  = len(os.listdir(STORAGE_DIR))
    uptime  = int(time.time() - start_time)
    hours   = uptime // 3600
    minutes = (uptime % 3600) // 60
    seconds = uptime % 60

    # Ambil data sensor terbaru untuk grafik (20 titik terakhir)
    recent = list(latest_packets)

    # Hitung rata-rata sensor dari data terbaru
    temps     = [p["temp"]     for p in recent if p.get("temp")     is not None]
    humids    = [p["humidity"] for p in recent if p.get("humidity") is not None]
    moistures = [p["moisture"] for p in recent if p.get("moisture") is not None]
    phs       = [p["ph"]       for p in recent if p.get("ph")       is not None]

    avg_temp     = round(sum(temps)     / len(temps),     1) if temps     else 0
    avg_humidity = round(sum(humids)    / len(humids),    1) if humids    else 0
    avg_moisture = round(sum(moistures) / len(moistures), 1) if moistures else 0
    avg_ph       = round(sum(phs)       / len(phs),       1) if phs       else 0

    # Mode yang digunakan
    modes_used = list(set(p["mode"] for p in recent if p.get("mode")))

    return jsonify({
        "stats": {
            **stats,
            "stored_ciphertexts": stored,
            "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        },
        "averages": {
            "temperature": avg_temp,
            "humidity":    avg_humidity,
            "moisture":    avg_moisture,
            "ph":          avg_ph,
        },
        "modes_used":    modes_used,
        "active_mode":   active_mode,
        "activity_log":  list(activity_log)[:15],
        "chart_data":    list(reversed(recent)),
    })


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS — MODE CONTROL
# ══════════════════════════════════════════════════════════════════

@app.route("/api/mode", methods=["GET"])
def get_mode():
    """
    Sensor simulator fetch mode aktif dari sini setiap kali hendak kirim data.
    Mengembalikan mode saat ini (RSA atau ECC).
    """
    return jsonify({
        "mode":    active_mode,
        "history": list(mode_history)[:10]
    })


@app.route("/api/mode", methods=["POST"])
def set_mode():
    """
    Dashboard mengirim mode baru ke sini.
    Body: { "mode": "RSA" } atau { "mode": "ECC" }
    """
    global active_mode

    body     = request.get_json()
    new_mode = body.get("mode", "").upper()

    if new_mode not in ("RSA", "ECC"):
        return jsonify({
            "status": "error",
            "reason": "Mode harus RSA atau ECC"
        }), 400

    old_mode    = active_mode
    active_mode = new_mode

    # Catat riwayat pergantian mode
    mode_history.appendleft({
        "time":     time.strftime("%H:%M:%S"),
        "from":     old_mode,
        "to":       new_mode,
        "changed":  old_mode != new_mode
    })

    print(f"[MODE] Diganti: {old_mode} → {new_mode} "
          f"pada {time.strftime('%H:%M:%S')}")

    return jsonify({
        "status":      "ok",
        "active_mode": active_mode,
        "previous":    old_mode
    })


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("  SERVER — Smart Agriculture Crypto System")
    print("=" * 55)

    # Generate key saat server pertama kali jalan
    generate_keys_if_not_exist()

    print(f"\n[INFO] Public key endpoints:")
    print(f"  RSA : http://localhost:5002/public-key/rsa")
    print(f"  ECC : http://localhost:5002/public-key/ecc")
    print(f"\n[INFO] Dashboard : http://localhost:5002/dashboard")
    print(f"[INFO] Storage   : {STORAGE_DIR}/")
    print(f"[INFO] Mode aktif: {active_mode}")
    print(f"[INFO] Server started on port 5002\n")

    app.run(port=5002, threaded=True)