import json
import os
import time
from flask import Flask, request, jsonify, render_template
from aes import decrypt
from rsa import decrypt_session_key, private_key
from ecc import derive_session_key, public_key_from_bytes, server_private_key
from cryptography.exceptions import InvalidTag

app = Flask(__name__, template_folder='templates')

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "server_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

stats = {"received": 0, "failed": 0, "tampered_rejected": 0}

# Bersihkan storage saat server start
import shutil
if os.path.exists(STORAGE_DIR):
    shutil.rmtree(STORAGE_DIR)
os.makedirs(STORAGE_DIR, exist_ok=True)

# Simpan history data sensor untuk grafik (max 50 data terakhir)
sensor_history = []
rsa_times      = []
ecc_times      = []

class Server:
    def __init__(self):
        self.storage   = []
        self.is_online = True
        print("Server aktif")

    def receive(self, packet):
        #Terima dan simpan ciphertext (bukan plaintext)
        self.storage.append(packet)
        #Simpan ke folder server_storage
        filename = os.path.join(STORAGE_DIR, f"packet_{int(time.time()*1000)}.json")
        with open(filename, "w") as f:
            json.dump(packet, f, indent=2)
        print(f"[{packet['mode']}] Ciphertext diterima, sequence_number: {packet['sequence_number']}")

    def decrypt_packet(self, packet):
        mode = packet["mode"]
        if mode == "RSA":
            session_key = decrypt_session_key(private_key, packet["encrypted_session_key"])
        elif mode == "ECC":
            ephem_pub_bytes = bytes.fromhex(packet["ephemeral_public_key"])
            ephem_pub       = public_key_from_bytes(ephem_pub_bytes)
            session_key     = derive_session_key(server_private_key, ephem_pub)
        try:
            plaintext = decrypt(
                session_key,
                packet["nonce"],
                packet["ciphertext"],
                packet["tag"]
            )
            return json.loads(plaintext.decode())
        except InvalidTag:
            print("Ciphertext ditolak! Tag tidak valid.")
            return None

    def status(self):
        status = "ONLINE" if self.is_online else "OFFLINE"
        stored = len(os.listdir(STORAGE_DIR))
        print(f"Server: {status} | Memori: {len(self.storage)} paket | File: {stored} paket")

#Buat instance server
server = Server()

@app.route("/store", methods=["POST"])
def store():
    packet = request.get_json()
    seq    = packet.get("sequence_number", "?")
    mode   = packet.get("mode", "?")

    server.receive(packet)

    try:
        t_start   = time.perf_counter()
        plaintext = server.decrypt_packet(packet)
        dec_time  = (time.perf_counter() - t_start) * 1000

        if plaintext:
            stats["received"] += 1

            sensor_history.append({
                "timestamp":    plaintext.get("timestamp", ""),
                "temperature":  plaintext.get("temperature", 0),
                "soil_ph":      plaintext.get("soil_ph", 0),
                "air_humidity": plaintext.get("air_humidity", 0),
                "mode":         mode,
                "seq":          seq
            })
            if len(sensor_history) > 50:
                sensor_history.pop(0)

            if mode == "RSA":
                rsa_times.append(round(dec_time, 3))
                if len(rsa_times) > 50:
                    rsa_times.pop(0)
            elif mode == "ECC":
                ecc_times.append(round(dec_time, 3))
                if len(ecc_times) > 50:
                    ecc_times.pop(0)

            print(f"[OK] seq#{seq} | mode={mode} | "
                  f"temp={plaintext.get('temperature')}°C | "
                  f"total_received={stats['received']}")
            return jsonify({"status": "ok", "seq": seq})
        else:
            stats["tampered_rejected"] += 1
            return jsonify({"status": "rejected", "reason": "Invalid tag"}), 400

    except Exception as e:
        stats["failed"] += 1
        print(f"[ERROR] seq#{seq} | {e}")
        return jsonify({"status": "error", "reason": str(e)}), 500

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "up"})

@app.route("/stats", methods=["GET"])
def get_stats():
    stored = len(os.listdir(STORAGE_DIR))
    return jsonify({**stats, "stored_ciphertexts": stored})

@app.route("/chart-data", methods=["GET"])
def chart_data():
    try:
        import requests as req
        gw_resp  = req.get("http://localhost:5001/stats", timeout=2)
        gw_stats = gw_resp.json()
    except Exception:
        gw_stats = {"sent": 0, "buffered": 0, "pending_in_buffer": 0, "retry_sent": 0}

    return jsonify({
        "sensor_history": sensor_history,
        "rsa_times":      rsa_times,
        "ecc_times":      ecc_times,
        "server_stats":   stats,
        "gateway_stats":  gw_stats,
        "stored":         len(os.listdir(STORAGE_DIR))
    })
	


@app.route("/", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    print("SERVER aktif di port 5002")
    print("Dashboard: http://localhost:5002")
    print(f"Storage: {STORAGE_DIR}/")
    app.run(port=5002, debug=False)