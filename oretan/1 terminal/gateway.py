import json
import os
import time
import random
from pathlib import Path
from old.sensor import data, data_json
from aes import encrypt
from rsa import encrypt_session_key, private_key, public_key
from ecc import derive_session_key, public_key_to_bytes, public_key_from_bytes, server_private_key, server_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

#Kalau server mati, gateway nyimpan ciphertext ke file lokal sementara (buffer)
buffer_dir = "gateway_buffer"
os.makedirs(buffer_dir, exist_ok=True)

def save_to_buffer(packet):
    #Setiap buffer disimpan dalam file json masing2
    filename = os.path.join(buffer_dir, f"packet_{int(time.time()*1000)}.json")
    with open(filename, "w") as f:
        json.dump(packet, f, indent=2)
    total = len(os.listdir(buffer_dir))
    print(f"Server mati, data disimpan ke buffer lokal ({total} data)")

def flush_buffer(server):
    files = sorted(os.listdir(buffer_dir))
    if not files:
        return
    print(f"Mengirim ulang {len(files)} data dari buffer")
    for fname in files:
        fpath = os.path.join(buffer_dir, fname)
        with open(fpath, "r") as f:
            packet = json.load(f)
        server.receive(packet)
        #Hapus file setelah terkirim
        os.remove(fpath)
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

#Kirim ke server
def send_to_server(server, packet, mode):
    if server.is_online:
        server.receive(packet)
        print(f"[{mode}] Data terkirim ke server")
        #Kalau ada buffer, kirim juga
        flush_buffer(server)
    else:
        save_to_buffer(packet)
#Pakai main supaya ini cuma untuk import fungsi2 rsa, ecc, sama aes tanpa memasukkan hasil testing
#Main
if __name__ == "__main__":
    # Import server
    from old.server import Server
    server = Server()
    print("GATEWAY — MODE RSA")
    packet_rsa = encrypt_rsa(data_json, public_key)
    print(f"Paket RSA:")
    print(f"sensor_id: {packet_rsa['sensor_id']}")
    print(f"mode: {packet_rsa['mode']}")
    print(f"algorithm: {packet_rsa['algorithm']}")
    send_to_server(server, packet_rsa, "RSA")

    print()
    print("GATEWAY — MODE ECC")
    packet_ecc = encrypt_ecc(data_json, server_public_key)
    print(f"Paket ECC:")
    print(f"sensor_id: {packet_ecc['sensor_id']}")
    print(f"mode: {packet_ecc['mode']}")
    print(f"algorithm: {packet_ecc['algorithm']}")
    send_to_server(server, packet_ecc, "ECC")