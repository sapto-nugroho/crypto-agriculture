import json
import os
import time
import random
import requests
import threading
from pathlib import Path
from flask import Flask, request, jsonify
from aes import encrypt
from rsa import encrypt_session_key, private_key, public_key
from ecc import derive_session_key, public_key_to_bytes, public_key_from_bytes, server_private_key, server_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

app = Flask(__name__)

SERVER_URL = "http://localhost:5002/store"

#Kalau server mati, gateway nyimpan ciphertext ke file lokal sementara (buffer)
buffer_dir = "gateway_buffer"
os.makedirs(buffer_dir, exist_ok=True)

stats = {"sent": 0, "buffered": 0, "retry_sent": 0}

def save_to_buffer(packet):
    #Setiap buffer disimpan dalam file json masing2
    filename = os.path.join(buffer_dir, f"packet_{int(time.time()*1000)}.json")
    with open(filename, "w") as f:
        json.dump(packet, f, indent=2)
    total = len(os.listdir(buffer_dir))
    print(f"Server mati, data disimpan ke buffer lokal ({total} data)")

def flush_buffer():
    files = sorted(os.listdir(buffer_dir))
    if not files:
        return
    print(f"Mengirim ulang {len(files)} data dari buffer")
    for fname in files:
        fpath = os.path.join(buffer_dir, fname)
        with open(fpath, "r") as f:
            packet = json.load(f)
        if send_to_server(packet):
            #Hapus file setelah terkirim
            os.remove(fpath)
            stats["retry_sent"] += 1
            print(f"  Buffer {fname} berhasil dikirim ulang")
        else:
            print(f"  Server masih mati, berhenti sementara")
            break
    print("Buffer berhasil dikirim")

#Enkripsi RSA
def encrypt_rsa(data_json, rsa_public_key):
    #Generate session key AES
    session_key = os.urandom(32)
    #Lindungi session key dengan RSA-OAEP
    encrypted_sk = encrypt_session_key(rsa_public_key, session_key)
    #Enkripsi data sensor dengan AES-GCM
    aes_result = encrypt(session_key, data_json.encode())
    d = json.loads(data_json)
    return{
        "mode": "RSA",
        "algorithm": "RSA-OAEP-SHA256-AES-256-GCM",
        "sensor_id": d.get("sensor_id"),
        "timestamp": d.get("timestamp"),
        "sequence_number": d.get("sequence_number"),
        "encrypted_session_key": encrypted_sk,
        "nonce": aes_result["nonce"],
        "ciphertext": aes_result["ciphertext"],
        "tag": aes_result["tag"]
    }

#Enkripsi ECC
def encrypt_ecc(data_json, ecc_server_public):
    #Bentuk ephemeral key (kunci sekali pakai)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    #Derive session key via ECDH + HKDF
    session_key = derive_session_key(ephemeral_private, ecc_server_public)
    #Serialisasi ephemeral public key
    ephem_pub_bytes = public_key_to_bytes(ephemeral_public)
    ephem_pub_hex = ephem_pub_bytes.hex()
    #Enkripsi data sensor dengan AES-GCM
    aes_result = encrypt(session_key, data_json.encode())
    d = json.loads(data_json)
    return {
        "mode": "ECC",
        "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
        "sensor_id": d.get("sensor_id"),
        "timestamp": d.get("timestamp"),
        "sequence_number": d.get("sequence_number"),
        "ephemeral_public_key": ephem_pub_hex,
        "nonce": aes_result["nonce"],
        "ciphertext": aes_result["ciphertext"],
        "tag": aes_result["tag"]
    }

#Kirim ke server via HTTP
def send_to_server(packet):
    try:
        resp = requests.post(SERVER_URL, json=packet, timeout=3)
        return resp.status_code == 200
    except Exception:
        return False

#Retry buffer di background (tiap 5 detik cek buffer)
def retry_buffer():
    while True:
        time.sleep(5)
        files = sorted(os.listdir(buffer_dir))
        if files:
            flush_buffer()

#Endpoint: terima data dari sensor
@app.route("/receive", methods=["POST"])
def receive_from_sensor():
    body        = request.get_json()
    sensor_data = body["sensor_data"]
    mode        = body.get("mode", "ECC").upper()

    data_json = json.dumps(sensor_data)

    #Enkripsi sesuai mode
    if mode == "RSA":
        packet = encrypt_rsa(data_json, public_key)
    else:
        packet = encrypt_ecc(data_json, server_public_key)

    #Kirim ke server atau buffer
    if send_to_server(packet):
        stats["sent"] += 1
        print(f"[{mode}] Data terkirim ke server | seq#{sensor_data['sequence_number']}")
    else:
        stats["buffered"] += 1
        save_to_buffer(packet)

    return jsonify({"status": "ok"})

#Endpoint: statistik gateway
@app.route("/stats", methods=["GET"])
def get_stats():
    pending = len(os.listdir(buffer_dir))
    return jsonify({**stats, "pending_in_buffer": pending})

#Main
if __name__ == "__main__":
    #Jalankan retry buffer di background
    t = threading.Thread(target=retry_buffer, daemon=True)
    t.start()

    print("GATEWAY aktif di port 5001")
    print(f"Buffer: {buffer_dir}/")
    app.run(port=5001)