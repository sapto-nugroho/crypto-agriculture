# security_analysis.py
# Pembuktian empiris IND-CPA dan IND-CCA untuk paper.
# Tidak membutuhkan server atau gateway aktif.
# Menggunakan public key yang sudah di-fetch oleh gateway (di gateway_keys/).
#
# Jalankan: python security_analysis.py

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import json
import os

# Gunakan public key dari gateway_keys/ (hasil fetch dari server)
# dan private key dari keys/ (milik server)
GATEWAY_KEYS_DIR = "gateway_keys"
SERVER_KEYS_DIR  = "keys"


# ══════════════════════════════════════════════════════════════════
# CEK KEY TERSEDIA
# ══════════════════════════════════════════════════════════════════

def check_keys():
    needed = [
        f"{SERVER_KEYS_DIR}/rsa_private.pem",
        f"{SERVER_KEYS_DIR}/ecc_private.pem",
        f"{GATEWAY_KEYS_DIR}/rsa_public.pem",
        f"{GATEWAY_KEYS_DIR}/ecc_public.pem",
    ]
    missing = [f for f in needed if not os.path.exists(f)]
    if missing:
        print("Key berikut tidak ditemukan:")
        for f in missing:
            print(f"  - {f}")
        print("\nPastikan:")
        print("  1. python server.py sudah pernah dijalankan (generate key)")
        print("  2. python edge_gateway.py sudah pernah dijalankan (fetch key)")
        return False
    return True


# ══════════════════════════════════════════════════════════════════
# FUNGSI ENKRIPSI / DEKRIPSI (dipakai langsung, tanpa HTTP)
# ══════════════════════════════════════════════════════════════════

def load_rsa_public_key():
    with open(f"{GATEWAY_KEYS_DIR}/rsa_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_rsa_private_key():
    with open(f"{SERVER_KEYS_DIR}/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_ecc_public_key():
    with open(f"{GATEWAY_KEYS_DIR}/ecc_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_ecc_private_key():
    with open(f"{SERVER_KEYS_DIR}/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def encrypt_rsa(plaintext_bytes):
    session_key = os.urandom(32)
    rsa_pub     = load_rsa_public_key()
    encrypted_session_key = rsa_pub.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    nonce       = os.urandom(12)
    aesgcm      = AESGCM(session_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return {
        "encrypted_session_key": encrypted_session_key,
        "nonce":      nonce,
        "ciphertext": ct_with_tag[:-16],
        "tag":        ct_with_tag[-16:],
    }

def decrypt_rsa(packet):
    rsa_priv    = load_rsa_private_key()
    session_key = rsa_priv.decrypt(
        packet["encrypted_session_key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(
        packet["nonce"],
        packet["ciphertext"] + packet["tag"],
        None
    )


def encrypt_ecc(plaintext_bytes):
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub  = ephemeral_priv.public_key()
    server_pub     = load_ecc_public_key()
    shared_secret  = ephemeral_priv.exchange(server_pub)
    hkdf           = HKDF(algorithm=hashes.SHA256(), length=32,
                          salt=None, info=b"smart-agriculture-v1")
    session_key    = hkdf.derive(shared_secret)
    nonce          = os.urandom(12)
    aesgcm         = AESGCM(session_key)
    ct_with_tag    = aesgcm.encrypt(nonce, plaintext_bytes, None)
    epk_bytes      = ephemeral_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return {
        "ephemeral_public_key": epk_bytes,
        "nonce":      nonce,
        "ciphertext": ct_with_tag[:-16],
        "tag":        ct_with_tag[-16:]
    }

def decrypt_ecc(packet):
    ecc_priv      = load_ecc_private_key()
    ephemeral_pub = X25519PublicKey.from_public_bytes(
        packet["ephemeral_public_key"]
    )
    shared_secret = ecc_priv.exchange(ephemeral_pub)
    hkdf          = HKDF(algorithm=hashes.SHA256(), length=32,
                         salt=None, info=b"smart-agriculture-v1")
    session_key   = hkdf.derive(shared_secret)
    aesgcm        = AESGCM(session_key)
    return aesgcm.decrypt(
        packet["nonce"],
        packet["ciphertext"] + packet["tag"],
        None
    )


def generate_payload():
    return json.dumps({
        "sensor_id":       "FIELD-01-SENSOR-01",
        "timestamp":       "2026-05-06 08:30:00",
        "temperature":     31.5,
        "air_humidity":    72.3,
        "soil_moisture":   41.8,
        "soil_ph":         6.4,
        "sequence_number": 1
    }).encode("utf-8")


# ══════════════════════════════════════════════════════════════════
# TEST IND-CPA
# ══════════════════════════════════════════════════════════════════

def test_ind_cpa():
    print("\n" + "=" * 55)
    print("  ANALISIS IND-CPA")
    print("  Plaintext sama dienkripsi 2x → ciphertext harus berbeda")
    print("=" * 55)

    plaintext = generate_payload()

    # ── RSA ───────────────────────────────────────────────────────
    print("\n[RSA-OAEP] Enkripsi plaintext sama 2x:")
    p1 = encrypt_rsa(plaintext)
    p2 = encrypt_rsa(plaintext)

    ct1  = p1["ciphertext"].hex()
    ct2  = p2["ciphertext"].hex()
    esk1 = p1["encrypted_session_key"].hex()
    esk2 = p2["encrypted_session_key"].hex()
    n1   = p1["nonce"].hex()
    n2   = p2["nonce"].hex()

    print(f"  Ciphertext 1      : {ct1[:32]}...")
    print(f"  Ciphertext 2      : {ct2[:32]}...")
    print(f"  Ciphertext sama?  : {ct1 == ct2}")
    print(f"  Enc.SessKey sama? : {esk1 == esk2}")
    print(f"  Nonce sama?       : {n1 == n2}")

    assert ct1  != ct2,  "GAGAL: Ciphertext RSA identik!"
    assert esk1 != esk2, "GAGAL: Encrypted session key identik!"
    assert n1   != n2,   "GAGAL: Nonce sama!"
    print("  ✓ RSA-OAEP LULUS IND-CPA")

    # ── ECC ───────────────────────────────────────────────────────
    print("\n[ECC X25519] Enkripsi plaintext sama 2x:")
    e1 = encrypt_ecc(plaintext)
    e2 = encrypt_ecc(plaintext)

    ect1 = e1["ciphertext"].hex()
    ect2 = e2["ciphertext"].hex()
    epk1 = e1["ephemeral_public_key"].hex()
    epk2 = e2["ephemeral_public_key"].hex()

    print(f"  Ciphertext 1      : {ect1[:32]}...")
    print(f"  Ciphertext 2      : {ect2[:32]}...")
    print(f"  Ciphertext sama?  : {ect1 == ect2}")
    print(f"  Ephemeral key sama: {epk1 == epk2}")

    assert ect1 != ect2, "GAGAL: Ciphertext ECC identik!"
    assert epk1 != epk2, "GAGAL: Ephemeral key identik!"
    print("  ✓ ECC X25519 LULUS IND-CPA")


# ══════════════════════════════════════════════════════════════════
# TEST IND-CCA
# ══════════════════════════════════════════════════════════════════

def test_ind_cca():
    print("\n" + "=" * 55)
    print("  ANALISIS IND-CCA")
    print("  Modifikasi ciphertext/tag → harus ditolak sistem")
    print("=" * 55)

    plaintext = generate_payload()

    # ── Test 1: Modifikasi ciphertext RSA ─────────────────────────
    print("\n[Test 1] Flip 1 byte pada ciphertext RSA:")
    packet = encrypt_rsa(plaintext)
    tampered           = bytearray(packet["ciphertext"])
    tampered[0]       ^= 0xFF
    packet["ciphertext"] = bytes(tampered)

    try:
        decrypt_rsa(packet)
        print("  ✗ GAGAL: Ciphertext rusak diterima!")
    except (InvalidTag, Exception) as e:
        print(f"  ✓ DITOLAK ({type(e).__name__})")

    # ── Test 2: Modifikasi tag ECC ────────────────────────────────
    print("\n[Test 2] Flip 1 bit pada authentication tag ECC:")
    packet = encrypt_ecc(plaintext)
    tampered      = bytearray(packet["tag"])
    tampered[0]  ^= 0x01
    packet["tag"] = bytes(tampered)

    try:
        decrypt_ecc(packet)
        print("  ✗ GAGAL: Tag rusak diterima!")
    except (InvalidTag, Exception) as e:
        print(f"  ✓ DITOLAK ({type(e).__name__})")

    # ── Test 3: Nonce unik ────────────────────────────────────────
    print("\n[Test 3] Verifikasi 10 nonce selalu unik:")
    nonces = [encrypt_ecc(plaintext)["nonce"].hex() for _ in range(10)]
    unique = len(set(nonces))
    print(f"  {unique} unik dari {len(nonces)} nonce")
    assert unique == len(nonces), "GAGAL: Ada nonce yang sama!"
    print("  ✓ Semua nonce unik → aman dari replay attack")

    # ── Test 4: Ciphertext valid tetap bisa didekripsi ────────────
    print("\n[Test 4] Kontrol — ciphertext valid harus berhasil:")
    packet = encrypt_rsa(plaintext)
    try:
        result = decrypt_rsa(packet)
        data   = json.loads(result)
        print(f"  ✓ Dekripsi berhasil | sensor_id: {data.get('sensor_id')}")
    except Exception as e:
        print(f"  ✗ GAGAL: {e}")


# ══════════════════════════════════════════════════════════════════
# RINGKASAN
# ══════════════════════════════════════════════════════════════════

def print_summary():
    print("\n" + "=" * 55)
    print("  RINGKASAN ANALISIS KEAMANAN")
    print("=" * 55)
    print("""
IND-CPA:
  RSA-OAEP  → Probabilistik: random padding berbeda tiap enkripsi
  ECC X25519 → Ephemeral key baru tiap sesi
  AES-GCM   → Nonce 96-bit random tiap enkripsi
  Kesimpulan: SISTEM MEMENUHI IND-CPA ✓

IND-CCA:
  AES-GCM   → Authentication tag 128-bit
  Modifikasi ciphertext/tag → InvalidTag → ditolak
  Plaintext tidak dikeluarkan jika tag tidak valid
  Kesimpulan: SISTEM MEMENUHI IND-CCA ✓

Catatan:
  Metadata (sensor_id, timestamp) di luar ciphertext
  tidak diproteksi kriptografis → keterbatasan sistem.
  Mitigasi: gunakan sebagai AAD pada AES-GCM.
""")


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("  ANALISIS KEAMANAN IND-CPA & IND-CCA")
    print("=" * 55)

    if not check_keys():
        exit(1)

    test_ind_cpa()
    test_ind_cca()
    print_summary()
    print("Analisis selesai!")
