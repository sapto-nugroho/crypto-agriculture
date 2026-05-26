# decrypt_storage.py
# Dekripsi manual file ciphertext dari folder server_storage/
# Jalankan: python decrypt_storage.py
# Atau dekripsi file tertentu: python decrypt_storage.py server_storage/packet_123.json

import json
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

STORAGE_DIR = "server_storage"


# ── Load Private Keys ─────────────────────────────────────────────────────────

def load_rsa_private_key():
    with open("keys/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_ecc_private_key():
    with open("keys/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ── Dekripsi RSA Mode ─────────────────────────────────────────────────────────

def decrypt_rsa(packet):
    rsa_priv = load_rsa_private_key()
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
    plaintext  = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


# ── Dekripsi ECC Mode (X25519 / Curve25519) ───────────────────────────────────

def decrypt_ecc(packet):
    ecc_priv      = load_ecc_private_key()
    epk_bytes     = bytes.fromhex(packet["ephemeral_public_key"])
    ephemeral_pub = X25519PublicKey.from_public_bytes(epk_bytes)
    shared_secret = ecc_priv.exchange(ephemeral_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"smart-agriculture-v1"
    )
    session_key = hkdf.derive(shared_secret)
    nonce       = bytes.fromhex(packet["nonce"])
    ciphertext  = bytes.fromhex(packet["ciphertext"])
    tag         = bytes.fromhex(packet["tag"])
    aesgcm      = AESGCM(session_key)
    plaintext   = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


# ── Dekripsi Satu File ────────────────────────────────────────────────────────

def decrypt_file(filepath):
    with open(filepath) as f:
        packet = json.load(f)

    mode = packet.get("mode", "?").upper()

    try:
        if mode == "RSA":
            plaintext = decrypt_rsa(packet)
        elif mode == "ECC":
            plaintext = decrypt_ecc(packet)
        else:
            return None, f"Mode tidak dikenal: {mode}"
        return plaintext, None
    except InvalidTag:
        return None, "DITOLAK — authentication tag tidak valid (ciphertext mungkin dimodifikasi)"
    except Exception as e:
        return None, f"Error: {e}"


# ── Tampilkan Hasil ───────────────────────────────────────────────────────────

def print_result(filepath, plaintext, error):
    filename = os.path.basename(filepath)
    print(f"\n{'─'*55}")
    print(f"File    : {filename}")

    if error:
        print(f"Status  : ❌ GAGAL")
        print(f"Alasan  : {error}")
        return

    mode = plaintext.get("mode", "?") if "mode" in plaintext else "?"
    print(f"Status  : ✓ BERHASIL")
    print(f"Mode    : {plaintext.get('mode', '-') if 'mode' in plaintext else '-'}")
    print(f"\n--- Plaintext Data Sensor ---")
    for key, value in plaintext.items():
        if key != "dummy":  # skip field dummy jika ada
            print(f"  {key:<20}: {value}")
    if "dummy" in plaintext:
        print(f"  {'dummy':<20}: [field dummy, {len(plaintext['dummy'])} karakter]")


# ── Mode: Dekripsi Semua File ─────────────────────────────────────────────────

def decrypt_all():
    if not os.path.exists(STORAGE_DIR):
        print(f"Folder '{STORAGE_DIR}/' tidak ditemukan.")
        print("Pastikan server sudah pernah dijalankan dan menerima data.")
        return

    files = sorted([
        f for f in os.listdir(STORAGE_DIR)
        if f.endswith(".json")
    ])

    if not files:
        print(f"Tidak ada file ciphertext di '{STORAGE_DIR}/'.")
        return

    print(f"Ditemukan {len(files)} file ciphertext di '{STORAGE_DIR}/'")
    print("Mulai dekripsi...\n")

    success = 0
    failed  = 0

    for fname in files:
        fpath     = os.path.join(STORAGE_DIR, fname)
        plaintext, error = decrypt_file(fpath)
        print_result(fpath, plaintext, error)
        if error:
            failed += 1
        else:
            success += 1

    print(f"\n{'='*55}")
    print(f"Selesai — Berhasil: {success} | Gagal: {failed} | Total: {len(files)}")


# ── Mode: Dekripsi File Tertentu ──────────────────────────────────────────────

def decrypt_single(filepath):
    if not os.path.exists(filepath):
        print(f"File tidak ditemukan: {filepath}")
        return

    plaintext, error = decrypt_file(filepath)
    print_result(filepath, plaintext, error)

    # Tawari simpan hasil ke file plaintext
    if plaintext and not error:
        save = input("\nSimpan plaintext ke file? (y/n): ").strip().lower()
        if save == "y":
            out_name = os.path.basename(filepath).replace("packet_", "plaintext_")
            out_path = os.path.join("decrypted_output", out_name)
            os.makedirs("decrypted_output", exist_ok=True)
            with open(out_path, "w") as f:
                json.dump(plaintext, f, indent=2)
            print(f"Plaintext disimpan ke: {out_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  DEKRIPSI MANUAL SERVER STORAGE")
    print("=" * 55)

    if len(sys.argv) > 1:
        # Dekripsi file spesifik yang disebutkan sebagai argumen
        decrypt_single(sys.argv[1])
    else:
        # Dekripsi semua file di server_storage/
        decrypt_all()
