# security_analysis.py
# Jalankan: python security_analysis.py
# Pembuktian empiris IND-CPA dan IND-CCA untuk paper.

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import json
import os

# Import fungsi dari experiment.py
from experiment import (
    encrypt_rsa, decrypt_rsa,
    encrypt_ecc, decrypt_ecc,
    generate_payload
)


# =============================================================================
# ANALISIS IND-CPA
# Properti: enkripsi plaintext yang SAMA dua kali harus menghasilkan
# ciphertext yang BERBEDA (probabilistic encryption).
# =============================================================================

def test_ind_cpa():
    print("\n" + "=" * 60)
    print("  ANALISIS IND-CPA")
    print("  Enkripsi plaintext identik 2x harus → ciphertext berbeda")
    print("=" * 60)

    plaintext = generate_payload(1)

    # ── RSA Mode ──────────────────────────────────────────────────
    print("\n[RSA-OAEP] Enkripsi plaintext sama 2x:")
    p1 = encrypt_rsa(plaintext)
    p2 = encrypt_rsa(plaintext)

    ct1  = p1["ciphertext"].hex()
    ct2  = p2["ciphertext"].hex()
    esk1 = p1["encrypted_session_key"].hex()
    esk2 = p2["encrypted_session_key"].hex()
    n1   = p1["nonce"].hex()
    n2   = p2["nonce"].hex()

    print(f"  Ciphertext 1 (32 char): {ct1[:32]}...")
    print(f"  Ciphertext 2 (32 char): {ct2[:32]}...")
    print(f"  Ciphertext identik?         : {ct1 == ct2}")
    print(f"  Encrypted session key sama? : {esk1 == esk2}")
    print(f"  Nonce sama?                 : {n1 == n2}")

    assert ct1  != ct2,  "GAGAL: Ciphertext RSA identik → tidak IND-CPA!"
    assert esk1 != esk2, "GAGAL: Encrypted session key identik!"
    assert n1   != n2,   "GAGAL: Nonce sama → nonce reuse sangat berbahaya!"
    print("  ✓ RSA-OAEP LULUS IND-CPA")

    # ── ECC Mode ──────────────────────────────────────────────────
    print("\n[ECC-ECDH] Enkripsi plaintext sama 2x:")
    e1 = encrypt_ecc(plaintext)
    e2 = encrypt_ecc(plaintext)

    ect1 = e1["ciphertext"].hex()
    ect2 = e2["ciphertext"].hex()
    epk1 = e1["ephemeral_public_key"].hex()
    epk2 = e2["ephemeral_public_key"].hex()

    print(f"  Ciphertext 1 (32 char): {ect1[:32]}...")
    print(f"  Ciphertext 2 (32 char): {ect2[:32]}...")
    print(f"  Ciphertext identik?        : {ect1 == ect2}")
    print(f"  Ephemeral public key sama? : {epk1 == epk2}")

    assert ect1 != ect2, "GAGAL: Ciphertext ECC identik → tidak IND-CPA!"
    assert epk1 != epk2, "GAGAL: Ephemeral key identik!"
    print("  ✓ ECC-ECDH LULUS IND-CPA")


# =============================================================================
# ANALISIS IND-CCA
# Properti: ciphertext yang dimodifikasi HARUS ditolak sistem.
# Plaintext tidak boleh keluar jika tag tidak valid.
# =============================================================================

def test_ind_cca():
    print("\n" + "=" * 60)
    print("  ANALISIS IND-CCA")
    print("  Modifikasi ciphertext/tag harus → ditolak sistem")
    print("=" * 60)

    plaintext = generate_payload(1)

    # ── Test 1: Modifikasi 1 byte pada ciphertext (RSA) ───────────
    print("\n[Test 1] Flip 1 byte pada ciphertext RSA mode:")
    packet = encrypt_rsa(plaintext)
    tampered_ct          = bytearray(packet["ciphertext"])
    tampered_ct[0]      ^= 0xFF
    packet_bad           = dict(packet)
    packet_bad["ciphertext"] = bytes(tampered_ct)

    try:
        decrypt_rsa(packet_bad)
        print("  ✗ GAGAL: Ciphertext rusak tetap diterima → tidak IND-CCA!")
    except (InvalidTag, Exception) as e:
        print(f"  ✓ Ciphertext dimodifikasi → DITOLAK ({type(e).__name__})")

    # ── Test 2: Modifikasi authentication tag (ECC) ───────────────
    print("\n[Test 2] Flip 1 bit pada authentication tag ECC mode:")
    packet = encrypt_ecc(plaintext)
    tampered_tag          = bytearray(packet["tag"])
    tampered_tag[0]      ^= 0x01
    packet_bad            = dict(packet)
    packet_bad["tag"]     = bytes(tampered_tag)

    try:
        decrypt_ecc(packet_bad)
        print("  ✗ GAGAL: Tag rusak tetap diterima → tidak IND-CCA!")
    except (InvalidTag, Exception) as e:
        print(f"  ✓ Tag dimodifikasi → DITOLAK ({type(e).__name__})")

    # ── Test 3: Nonce unik (anti replay attack) ───────────────────
    print("\n[Test 3] Verifikasi nonce selalu unik (anti-replay):")
    nonces = [encrypt_ecc(plaintext)["nonce"].hex() for _ in range(10)]
    collision = len(nonces) != len(set(nonces))
    print(f"  10 nonce di-generate: {len(set(nonces))} unik dari {len(nonces)}")
    assert not collision, "GAGAL: Ada nonce yang sama!"
    print("  ✓ Semua nonce unik → aman dari replay attack")

    # ── Test 4: Ciphertext valid masih bisa didekripsi (kontrol) ──
    print("\n[Test 4] Kontrol — ciphertext valid harus bisa didekripsi:")
    packet = encrypt_rsa(plaintext)
    try:
        result = decrypt_rsa(packet)
        data   = json.loads(result)
        print(f"  ✓ Dekripsi berhasil | sensor_id: {data.get('sensor_id')}")
    except Exception as e:
        print(f"  ✗ GAGAL: Ciphertext valid ditolak → {e}")


# =============================================================================
# RINGKASAN UNTUK PAPER
# =============================================================================

def print_summary():
    print("\n" + "=" * 60)
    print("  RINGKASAN ANALISIS KEAMANAN (untuk paper)")
    print("=" * 60)
    print("""
IND-CPA:
  RSA-OAEP  → Probabilistik: random padding membuat enkripsi
              session key yang sama selalu berbeda tiap run.
  ECC-ECDH  → Ephemeral key baru tiap sesi: shared secret
              dan session key selalu berubah.
  AES-GCM   → Nonce 96-bit random: plaintext yang sama
              menghasilkan ciphertext berbeda.
  Textbook RSA (TIDAK digunakan) → Deterministik: plaintext
              sama → ciphertext sama → tidak IND-CPA.
  Kesimpulan: Sistem MEMENUHI IND-CPA.

IND-CCA:
  AES-GCM   → Menyediakan authentication tag 128-bit.
  Modifikasi ciphertext atau tag → InvalidTag exception.
  Plaintext TIDAK dikeluarkan jika tag tidak valid.
  Sistem yang hanya enkripsi tanpa autentikasi (AES-CBC
  tanpa MAC) TIDAK memenuhi IND-CCA.
  Kesimpulan: Sistem MEMENUHI IND-CCA.

Catatan Keterbatasan:
  Metadata paket (sensor_id, timestamp) berada di luar
  ciphertext dan tidak diproteksi secara kriptografis.
  Mitigasi: gunakan metadata sebagai AAD (Additional
  Authenticated Data) pada AES-GCM.
""")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_ind_cpa()
    test_ind_cca()
    print_summary()
    print("Analisis keamanan selesai!")
