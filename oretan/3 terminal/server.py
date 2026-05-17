import json
import os
import time
from flask import Flask, request, jsonify
from aes import decrypt
from rsa import decrypt_session_key, private_key
from ecc import derive_session_key, public_key_from_bytes, server_private_key
from cryptography.exceptions import InvalidTag

app = Flask(__name__)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "server_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

stats = {"received": 0, "failed": 0, "tampered_rejected": 0}

class Server:
    def __init__(self):
        self.storage = []
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
            #Dekripsi session key pakai private key RSA
            session_key = decrypt_session_key(private_key, packet["encrypted_session_key"])

        elif mode == "ECC":
            #Derive session key dari ephemeral public key gateway
            ephem_pub_bytes = bytes.fromhex(packet["ephemeral_public_key"])
            ephem_pub = public_key_from_bytes(ephem_pub_bytes)
            session_key = derive_session_key(server_private_key, ephem_pub)

        #Dekripsi data sensor pakai AES-GCM
        #Tag diverifikasi otomatis, kalau invalid -> InvalidTag
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

#Endpoint: terima ciphertext dari gateway
@app.route("/store", methods=["POST"])
def store():
    packet = request.get_json()
    seq    = packet.get("sequence_number", "?")
    mode   = packet.get("mode", "?")

    #Simpan dan dekripsi via method server
    server.receive(packet)

    try:
        plaintext = server.decrypt_packet(packet)
        if plaintext:
            stats["received"] += 1
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

#Endpoint: cek status server
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "up"})

#Endpoint: statistik server
@app.route("/stats", methods=["GET"])
def get_stats():
    stored = len(os.listdir(STORAGE_DIR))
    return jsonify({**stats, "stored_ciphertexts": stored})

#Main
if __name__ == "__main__":
    print("SERVER aktif di port 5002")
    print(f"Storage: {STORAGE_DIR}/")
    app.run(port=5002)