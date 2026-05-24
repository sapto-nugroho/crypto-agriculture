from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import os
import time
from datetime import datetime

KEYS_DIR  = "gateway_keys" 
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
# ENKRIPSI ECC X25519
# ══════════════════════════════════════════════════════════════════

def load_ecc_public_key():
    with open(f"{KEYS_DIR}/ecc_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())
    
def load_ecc_private_key():
    with open(f"{PRIV_DIR}/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

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


if __name__ == "__main__":
    kb = 100
    # 1. Generate payload dalam bentuk dictionary (sesuai fungsi Anda)
    data = generate_payload(kb, seq=1)
    
    # 2. SEBELUM ENKRIPSI: Konversi dictionary menjadi bytes agar sesuai dengan 'plaintext_bytes'
    plaintext_bytes = json.dumps(data).encode('utf-8')

    # Ukur waktu enkripsi
    t_enc_start = time.perf_counter()
    cptxt = encrypt_ecc_mode(plaintext_bytes)
    enc_ms = round((time.perf_counter() - t_enc_start) * 1000, 4)
    print("enc ECC :",enc_ms,"ms;",kb,"KB")
    # print("\neph pub:", cptxt["ephemeral_public_key"])

    # Ukur waktu dekripsi
    t_dec_start = time.perf_counter()
    pltxt = decrypt_ecc_mode(cptxt)
    dec_ms = round((time.perf_counter() - t_dec_start) * 1000, 4)
    print("dec ECC :", dec_ms,"ms;",kb,"KB")