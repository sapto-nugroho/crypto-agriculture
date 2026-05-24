from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import os
import time
from datetime import datetime

KEYS_DIR = "gateway_keys" 
PRIV_DIR = "keys"

def generate_payload(target_size_kb, seq=1):
    base = {
        "sensor_id":       "FIELD-01-SENSOR-01",
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "temperature":     31.5,
        "air_humidity":    72.3,
        "soil_moisture":   41.8,
        "soil_ph":         6.4,
        "sequence_number": seq
    }
    target_bytes = target_size_kb * 1024
    dummy_size   = max(0, target_bytes - len(json.dumps(base).encode()))
    if dummy_size > 0:
        base["dummy"] = "x" * dummy_size
    return base

# ══════════════════════════════════════════════════════════════════
# ENKRIPSI RSA
# ══════════════════════════════════════════════════════════════════

def load_rsa_public_key():
    with open(f"{KEYS_DIR}/rsa_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_rsa_private_key():
    with open(f"{PRIV_DIR}/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
    
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



if __name__ == "__main__":
    kb = 100
    # 1. Generate payload dalam bentuk dictionary (sesuai fungsi Anda)
    data = generate_payload(kb, seq=1)
    
    # 2. SEBELUM ENKRIPSI: Konversi dictionary menjadi bytes agar sesuai dengan 'plaintext_bytes'
    plaintext_bytes = json.dumps(data).encode('utf-8')

    # Ukur waktu enkripsi
    t_enc_start = time.perf_counter()
    cptxt = encrypt_rsa_mode(plaintext_bytes)
    enc_ms = round((time.perf_counter() - t_enc_start) * 1000, 4)
    print("enc RSA :", enc_ms,"ms;",kb,"KB")

    # Ukur waktu dekripsi
    t_dec_start = time.perf_counter()
    pltxt = decrypt_rsa_mode(cptxt)
    dec_ms = round((time.perf_counter() - t_dec_start) * 1000, 4)
    print("dec RSA :", dec_ms,"ms;",kb,"KB")


