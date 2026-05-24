# decrypt_storage.py
# Dekripsi manual file ciphertext dari server_storage/
# Jalankan: python decrypt_storage.py
# Atau file tertentu: python decrypt_storage.py server_storage/packet_xxx.json

import json
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

STORAGE_DIR     = "server_storage"
SERVER_KEYS_DIR = "keys"
OUTPUT_DIR      = "decrypted_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_rsa_private_key():
    with open(f"{SERVER_KEYS_DIR}/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_ecc_private_key():
    with open(f"{SERVER_KEYS_DIR}/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def decrypt_rsa(packet):
    rsa_priv    = load_rsa_private_key()
    session_key = rsa_priv.decrypt(
        bytes.fromhex(packet["encrypted_session_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    nonce      = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    tag        = bytes.fromhex(packet["tag"])
    aesgcm     = AESGCM(session_key)
    return json.loads(aesgcm.decrypt(nonce, ciphertext + tag, None))


def decrypt_ecc(packet):
    ecc_priv      = load_ecc_private_key()
    epk_bytes     = bytes.fromhex(packet["ephemeral_public_key"])
    ephemeral_pub = X25519PublicKey.from_public_bytes(epk_bytes)
    shared_secret = ecc_priv.exchange(ephemeral_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=b"smart-agriculture-v1")
    session_key = hkdf.derive(shared_secret)
    nonce      = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    tag        = bytes.fromhex(packet["tag"])
    aesgcm     = AESGCM(session_key)
    return json.loads(aesgcm.decrypt(nonce, ciphertext + tag, None))


def decrypt_file(filepath):
    with open(filepath) as f:
        packet = json.load(f)
    mode = packet.get("mode", "?").upper()
    try:
        if mode == "RSA":
            return decrypt_rsa(packet), None
        elif mode == "ECC":
            return decrypt_ecc(packet), None
        else:
            return None, f"Mode tidak dikenal: {mode}"
    except InvalidTag:
        return None, "DITOLAK — tag tidak valid"
    except Exception as e:
        return None, f"Error: {e}"


def print_result(filepath, plaintext, error):
    print(f"\n{'─'*55}")
    print(f"File   : {os.path.basename(filepath)}")
    if error:
        print(f"Status : ❌ GAGAL — {error}")
        return
    print(f"Status : ✓ BERHASIL")
    print(f"\n--- Plaintext Data Sensor ---")
    for k, v in plaintext.items():
        if k != "dummy":
            print(f"  {k:<20}: {v}")
    if "dummy" in plaintext:
        print(f"  {'dummy':<20}: [{len(plaintext['dummy'])} karakter]")


def decrypt_all():
    if not os.path.exists(STORAGE_DIR):
        print(f"Folder '{STORAGE_DIR}/' tidak ditemukan.")
        return
    files = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(".json")])
    if not files:
        print(f"Tidak ada file di '{STORAGE_DIR}/'.")
        return

    print(f"Ditemukan {len(files)} file ciphertext.")
    success = failed = 0

    for fname in files:
        fpath           = os.path.join(STORAGE_DIR, fname)
        plaintext, error = decrypt_file(fpath)
        print_result(fpath, plaintext, error)
        if error:
            failed += 1
        else:
            success += 1
            # Simpan plaintext ke decrypted_output/
            out = os.path.join(OUTPUT_DIR, fname.replace("packet_", "plaintext_"))
            with open(out, "w") as f:
                json.dump(plaintext, f, indent=2)

    print(f"\n{'='*55}")
    print(f"Selesai — Berhasil: {success} | Gagal: {failed}")
    print(f"Plaintext tersimpan di: {OUTPUT_DIR}/")


if __name__ == "__main__":
    print("=" * 55)
    print("  DEKRIPSI MANUAL SERVER STORAGE")
    print("=" * 55)

    if len(sys.argv) > 1:
        path = sys.argv[1].replace("\\", "/")
        plaintext, error = decrypt_file(path)
        print_result(path, plaintext, error)
        if plaintext and not error:
            save = input("\nSimpan plaintext ke file? (y/n): ").strip().lower()
            if save == "y":
                out = os.path.join(OUTPUT_DIR,
                      os.path.basename(path).replace("packet_", "plaintext_"))
                with open(out, "w") as f:
                    json.dump(plaintext, f, indent=2)
                print(f"Tersimpan: {out}")
    else:
        decrypt_all()
