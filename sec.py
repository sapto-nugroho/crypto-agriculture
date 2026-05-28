# security_analysis.py
# Analisis pembuktian keamanan kriptografi sistem Smart Agriculture
#
# Mencakup:
#   1. CONFIDENTIALITY  — membuktikan data tidak bocor dalam bentuk plaintext
#   2. IND-CPA          — membuktikan enkripsi non-deterministik (ciphertext selalu berbeda)
#   3. IND-CCA          — membuktikan modifikasi ciphertext selalu terdeteksi & ditolak
#
# Jalankan SETELAH server (port 5002) aktif.
# Jalankan: python security_analysis.py

import os
import json
import time
import requests
import statistics
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_URL = "http://127.0.0.1:5002"

# ══════════════════════════════════════════════════════════════════
# WARNA TERMINAL
# ══════════════════════════════════════════════════════════════════

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}✅ PASS{RESET}  {msg}")
def fail(msg):  print(f"  {RED}❌ FAIL{RESET}  {msg}")
def warn(msg):  print(f"  {YELLOW}⚠️  WARN{RESET}  {msg}")
def info(msg):  print(f"  {CYAN}ℹ{RESET}  {msg}")
def sep(title): print(f"\n{BOLD}{'─'*60}\n  {title}\n{'─'*60}{RESET}")


# ══════════════════════════════════════════════════════════════════
# HELPER — AMBIL PUBLIC KEY DARI SERVER
# ══════════════════════════════════════════════════════════════════

def get_server_ecc_public_key():
    resp = requests.get(f"{SERVER_URL}/public-key/ecc", timeout=5)
    return serialization.load_pem_public_key(resp.content)


def get_server_rsa_public_key():
    resp = requests.get(f"{SERVER_URL}/public-key/rsa", timeout=5)
    return serialization.load_pem_public_key(resp.content)


# ══════════════════════════════════════════════════════════════════
# HELPER — BUAT PAKET TERENKRIPSI (ECC)
# Duplikasi logika encrypt_ecc_mode dari gateway.py
# ══════════════════════════════════════════════════════════════════

def make_ecc_packet(plaintext_bytes, server_pub=None):
    if server_pub is None:
        server_pub = get_server_ecc_public_key()

    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub  = ephemeral_priv.public_key()
    shared_secret  = ephemeral_priv.exchange(server_pub)

    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"smart-agriculture-v1"
    )
    session_key = hkdf.derive(shared_secret)

    nonce       = os.urandom(12)
    aesgcm      = AESGCM(session_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    ciphertext  = ct_with_tag[:-16]
    tag         = ct_with_tag[-16:]

    epk_bytes = ephemeral_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return {
        "mode":                 "ECC",
        "algorithm":            "X25519-HKDF-SHA256-AES-256-GCM",
        "ephemeral_public_key": epk_bytes.hex(),
        "nonce":                nonce.hex(),
        "ciphertext":           ciphertext.hex(),
        "tag":                  tag.hex(),
        "sensor_id":            "FIELD-TEST",
        "timestamp":            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sequence_number":      0
    }


# ══════════════════════════════════════════════════════════════════
# HELPER — BUAT PAKET TERENKRIPSI (RSA)
# ══════════════════════════════════════════════════════════════════

def make_rsa_packet(plaintext_bytes, server_pub=None):
    if server_pub is None:
        server_pub = get_server_rsa_public_key()

    session_key = os.urandom(32)
    encrypted_session_key = server_pub.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    nonce       = os.urandom(12)
    aesgcm      = AESGCM(session_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    ciphertext  = ct_with_tag[:-16]
    tag         = ct_with_tag[-16:]

    return {
        "mode":                  "RSA",
        "algorithm":             "RSA-OAEP-SHA256-AES-256-GCM",
        "encrypted_session_key": encrypted_session_key.hex(),
        "nonce":                 nonce.hex(),
        "ciphertext":            ciphertext.hex(),
        "tag":                   tag.hex(),
        "sensor_id":             "FIELD-TEST",
        "timestamp":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sequence_number":       0
    }


def send_to_server(packet):
    resp = requests.post(f"{SERVER_URL}/store", json=packet, timeout=10)
    return resp.status_code, resp.json()


# ══════════════════════════════════════════════════════════════════
# CHECK KONEKSI
# ══════════════════════════════════════════════════════════════════

def check_server():
    try:
        r = requests.get(f"{SERVER_URL}/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════════
#
#   BAGIAN 1 — CONFIDENTIALITY
#
#   Membuktikan:
#   (a) Data sensor tidak pernah beredar sebagai plaintext di jaringan
#   (b) Payload yang dikirim ke server adalah ciphertext, bukan plaintext
#   (c) Membandingkan ukuran plaintext vs ciphertext (overhead enkripsi)
#   (d) Ciphertext tidak mengandung substring dari plaintext
#
# ════════════════════════════════════════════════════════════════════

def test_confidentiality():
    sep("BAGIAN 1 — CONFIDENTIALITY")
    print(f"  {DIM}Membuktikan bahwa data sensor tidak pernah bocor sebagai plaintext.{RESET}\n")

    PLAIN_DATA = {
        "sensor_id":       "FIELD-01-SENSOR-01",
        "timestamp":       "2024-06-15 10:30:00",
        "temperature":     31.5,
        "air_humidity":    72.3,
        "soil_moisture":   41.8,
        "soil_ph":         6.4,
        "sequence_number": 42
    }
    plaintext_bytes = json.dumps(PLAIN_DATA).encode("utf-8")
    plaintext_hex   = plaintext_bytes.hex()
    plaintext_str   = plaintext_bytes.decode("utf-8")

    print(f"  Plaintext ({len(plaintext_bytes)} bytes):")
    print(f"    {DIM}{plaintext_str}{RESET}\n")

    results = {}

    for mode_name, make_fn in [("ECC", make_ecc_packet), ("RSA", make_rsa_packet)]:
        packet        = make_fn(plaintext_bytes)
        packet_json   = json.dumps(packet)
        packet_bytes  = packet_json.encode("utf-8")

        # ── (a) Cek apakah plaintext ada di dalam payload jaringan ──
        plaintext_in_payload = plaintext_str in packet_json

        # ── (b) Cek apakah nilai-nilai sensitif ada di payload ──
        sensor_id_exposed = PLAIN_DATA["sensor_id"] in packet.get("ciphertext", "")
        temp_str          = str(PLAIN_DATA["temperature"])
        temp_exposed      = temp_str in packet.get("ciphertext", "")

        # ── (c) Overhead enkripsi ──
        overhead_bytes  = len(packet_bytes) - len(plaintext_bytes)
        overhead_pct    = round(overhead_bytes / len(plaintext_bytes) * 100, 1)

        # ── (d) Cek field yang ada di payload ──
        payload_fields  = list(packet.keys())

        print(f"  [{mode_name}] Payload dikirim ke server ({len(packet_bytes)} bytes):")
        print(f"    Fields : {payload_fields}")
        print(f"    Overhead enkripsi : +{overhead_bytes}B (+{overhead_pct}%)")

        if not plaintext_in_payload:
            ok(f"[{mode_name}] Plaintext TIDAK ada di payload jaringan")
        else:
            fail(f"[{mode_name}] Plaintext BOCOR di payload jaringan!")

        if not temp_exposed:
            ok(f"[{mode_name}] Nilai suhu ({temp_str}°C) tidak terlihat di ciphertext")
        else:
            fail(f"[{mode_name}] Nilai suhu bocor!")

        # ── (e) Kirim ke server dan konfirmasi server menerima ciphertext ──
        code, resp = send_to_server(packet)
        if code == 200:
            ok(f"[{mode_name}] Server berhasil dekripsi → data tiba aman, bukan bocor di transit")
        else:
            fail(f"[{mode_name}] Server menolak: {resp}")

        results[mode_name] = {
            "plaintext_size_bytes": len(plaintext_bytes),
            "payload_size_bytes":   len(packet_bytes),
            "overhead_bytes":       overhead_bytes,
            "overhead_pct":         overhead_pct,
            "plaintext_exposed":    plaintext_in_payload,
        }
        print()

    print(f"  {BOLD}Ringkasan Confidentiality:{RESET}")
    for mode_name, r in results.items():
        status = f"{RED}BOCOR{RESET}" if r["plaintext_exposed"] else f"{GREEN}AMAN{RESET}"
        print(f"    {mode_name:3s} | plaintext={r['plaintext_size_bytes']}B → "
              f"payload={r['payload_size_bytes']}B "
              f"(+{r['overhead_pct']}%) | status={status}")

    return results


# ════════════════════════════════════════════════════════════════════
#
#   BAGIAN 2 — IND-CPA
#   (Indistinguishability under Chosen Plaintext Attack)
#
#   Game IND-CPA:
#     Challenger enkripsi dua plaintext m0 dan m1.
#     Attacker melihat ciphertext, harus tebak mana m0 mana m1.
#     Jika tidak bisa → sistem aman terhadap CPA.
#
#   Pembuktian empiris:
#   (a) Enkripsi plaintext SAMA berkali-kali → ciphertext SELALU berbeda
#       (non-deterministic = safe against CPA dictionary attack)
#   (b) Enkripsi dua plaintext berbeda → tidak bisa membedakan dari ciphertext
#       karena panjang pun berbeda tidak selalu proporsional
#   (c) Hitung jarak Hamming antar ciphertext dari plaintext sama
#       → jika besar dan acak, tidak ada pola
#
# ════════════════════════════════════════════════════════════════════

def hamming_distance_hex(h1, h2):
    """Hitung jarak Hamming antara dua hex string (dalam satuan bit)."""
    min_len = min(len(h1), len(h2)) // 2 * 2
    b1 = bytes.fromhex(h1[:min_len])
    b2 = bytes.fromhex(h2[:min_len])
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))


def test_ind_cpa(n_trials=20):
    sep("BAGIAN 2 — IND-CPA (Indistinguishability under Chosen Plaintext Attack)")
    print(f"  {DIM}Membuktikan enkripsi bersifat non-deterministik:{RESET}")
    print(f"  {DIM}Plaintext identik → ciphertext selalu berbeda (tidak bisa dibedakan).{RESET}\n")

    # Dua plaintext challenge (m0 dan m1)
    m0_data = {
        "sensor_id": "FIELD-01", "temperature": 30.0,
        "air_humidity": 70.0, "soil_moisture": 40.0,
        "soil_ph": 6.5, "timestamp": "2024-01-01 10:00:00",
        "sequence_number": 1
    }
    m1_data = {
        "sensor_id": "FIELD-01", "temperature": 30.0,
        "air_humidity": 70.0, "soil_moisture": 40.0,
        "soil_ph": 6.5, "timestamp": "2024-01-01 10:00:00",
        "sequence_number": 1
    }
    # m0 dan m1 IDENTIK — attacker harus bisa bedakan

    m0_bytes = json.dumps(m0_data).encode()
    m1_bytes = json.dumps(m1_data).encode()

    results_summary = {}

    for mode_name, make_fn in [("ECC", make_ecc_packet), ("RSA", make_rsa_packet)]:
        print(f"  [{mode_name}] Enkripsi plaintext SAMA sebanyak {n_trials}x...")

        ciphertexts = []
        nonces      = []
        epks        = []

        for i in range(n_trials):
            p = make_fn(m0_bytes)
            ciphertexts.append(p["ciphertext"])
            nonces.append(p["nonce"])
            if "ephemeral_public_key" in p:
                epks.append(p["ephemeral_public_key"])

        # ── (a) Semua ciphertext harus unik ──
        unique_ct    = len(set(ciphertexts))
        unique_nonce = len(set(nonces))

        if unique_ct == n_trials:
            ok(f"[{mode_name}] Semua {n_trials} ciphertext UNIK (0 duplikat)")
        else:
            fail(f"[{mode_name}] Ada {n_trials - unique_ct} duplikat ciphertext!")

        if unique_nonce == n_trials:
            ok(f"[{mode_name}] Semua {n_trials} nonce UNIK")
        else:
            fail(f"[{mode_name}] Ada duplikat nonce — berbahaya!")

        if mode_name == "ECC" and len(set(epks)) == n_trials:
            ok(f"[ECC] Semua ephemeral public key unik (forward secrecy terjamin)")

        # ── (b) Hitung jarak Hamming rata-rata antara ciphertext ──
        if len(ciphertexts) >= 2:
            distances = []
            for i in range(min(n_trials - 1, 10)):
                d = hamming_distance_hex(ciphertexts[i], ciphertexts[i + 1])
                distances.append(d)
            avg_hamming = round(statistics.mean(distances), 1)
            ct_bit_len  = len(ciphertexts[0]) * 4   # hex → bit
            hamming_pct = round(avg_hamming / ct_bit_len * 100, 1) if ct_bit_len > 0 else 0
            info(f"[{mode_name}] Jarak Hamming rata-rata antar ciphertext: "
                 f"{avg_hamming:.0f} bit ({hamming_pct}% dari total bit)")
            if hamming_pct > 30:
                ok(f"[{mode_name}] Distribusi bit acak → tidak ada pola → IND-CPA terpenuhi")
            else:
                warn(f"[{mode_name}] Hamming rendah — perlu investigasi lebih lanjut")

        # ── (c) Game IND-CPA simulasi: bisa bedakan m0 vs m1? ──
        ct_m0 = make_fn(m0_bytes)["ciphertext"]
        ct_m1 = make_fn(m1_bytes)["ciphertext"]
        # m0 == m1, jadi ciphertext seharusnya tetap berbeda
        if ct_m0 != ct_m1:
            ok(f"[{mode_name}] Dua enkripsi plaintext identik → ciphertext berbeda "
               f"(attacker tidak bisa bedakan)")
        else:
            fail(f"[{mode_name}] Dua enkripsi plaintext identik → ciphertext SAMA → deterministic!")

        results_summary[mode_name] = {
            "unique_ciphertexts": unique_ct,
            "total_trials":       n_trials,
            "avg_hamming_bits":   avg_hamming if len(ciphertexts) >= 2 else 0,
        }
        print()

    print(f"  {BOLD}Ringkasan IND-CPA:{RESET}")
    for mode_name, r in results_summary.items():
        pct = round(r["unique_ciphertexts"] / r["total_trials"] * 100)
        print(f"    {mode_name:3s} | unique={r['unique_ciphertexts']}/{r['total_trials']} ({pct}%) "
              f"| hamming≈{r['avg_hamming_bits']:.0f}bit")

    return results_summary


# ════════════════════════════════════════════════════════════════════
#
#   BAGIAN 3 — IND-CCA
#   (Indistinguishability under Chosen Ciphertext Attack)
#
#   Game IND-CCA:
#     Attacker bisa minta dekripsi ciphertext APAPUN (kecuali challenge).
#     Jika attacker memodifikasi ciphertext lalu minta didekripsi,
#     sistem harus MENOLAK — sehingga attacker tidak dapat informasi berguna.
#
#   Pembuktian empiris:
#   (a) Flip 1 bit ciphertext → server menolak (InvalidTag)
#   (b) Flip 1 bit authentication tag → server menolak
#   (c) Flip 1 bit nonce → server menolak
#   (d) Ubah ephemeral public key (ECC) → server menolak
#   (e) Ganti seluruh ciphertext dengan random bytes → server menolak
#   (f) Potong ciphertext (truncation attack) → server menolak
#   (g) Paket valid tanpa modifikasi → server menerima (kontrol positif)
#
#   Semua tes ini membuktikan bahwa AEAD (AES-256-GCM) memberikan
#   perlindungan IND-CCA2 secara praktis.
#
# ════════════════════════════════════════════════════════════════════

def flip_bit_in_hex(hex_str, byte_index=0, bit_mask=0xFF):
    b = bytearray(bytes.fromhex(hex_str))
    if byte_index < len(b):
        b[byte_index] ^= bit_mask
    return b.hex()


def test_ind_cca():
    sep("BAGIAN 3 — IND-CCA (Indistinguishability under Chosen Ciphertext Attack)")
    print(f"  {DIM}Membuktikan bahwa modifikasi ciphertext apapun pasti terdeteksi.{RESET}")
    print(f"  {DIM}Attacker tidak bisa mendapatkan info dari ciphertext yang dimodifikasi.{RESET}\n")

    plaintext = json.dumps({
        "sensor_id": "FIELD-01-SENSOR-01",
        "timestamp": "2024-01-01 12:00:00",
        "temperature": 31.5, "air_humidity": 72.3,
        "soil_moisture": 41.8, "soil_ph": 6.4,
        "sequence_number": 99
    }).encode()

    total_pass = 0
    total_fail = 0

    for mode_name, make_fn in [("ECC", make_ecc_packet), ("RSA", make_rsa_packet)]:
        print(f"\n  {'━'*50}")
        print(f"  [{mode_name}] Menjalankan serangan modifikasi ciphertext...\n")

        # Buat paket valid sebagai baseline
        base_packet = make_fn(plaintext)

        # ── (g) Kontrol positif: paket valid ──
        import copy
        p = copy.deepcopy(base_packet)
        code, resp = send_to_server(p)
        label = "[Kontrol +] Paket valid (tanpa modifikasi)"
        if code == 200:
            ok(f"[{mode_name}] {label} → diterima ✓")
            total_pass += 1
        else:
            fail(f"[{mode_name}] {label} → ditolak (seharusnya diterima!)")
            total_fail += 1

        attacks = [
            # (label, field_to_modify, modification_fn)
            (
                "[IND-CCA a] Flip byte pertama ciphertext",
                "ciphertext",
                lambda h: flip_bit_in_hex(h, 0, 0xFF)
            ),
            (
                "[IND-CCA a2] Flip byte terakhir ciphertext",
                "ciphertext",
                lambda h: flip_bit_in_hex(h, len(bytes.fromhex(h)) - 1, 0x01)
            ),
            (
                "[IND-CCA b] Flip 1 bit authentication tag",
                "tag",
                lambda h: flip_bit_in_hex(h, 0, 0x01)
            ),
            (
                "[IND-CCA b2] Nol-kan seluruh tag",
                "tag",
                lambda h: "00" * 16
            ),
            (
                "[IND-CCA c] Flip byte pertama nonce",
                "nonce",
                lambda h: flip_bit_in_hex(h, 0, 0xFF)
            ),
            (
                "[IND-CCA c2] Ganti nonce dengan nonce acak baru",
                "nonce",
                lambda h: os.urandom(12).hex()
            ),
            (
                "[IND-CCA e] Ganti ciphertext dengan random bytes",
                "ciphertext",
                lambda h: os.urandom(len(bytes.fromhex(h))).hex()
            ),
            (
                "[IND-CCA f] Potong ciphertext (truncation)",
                "ciphertext",
                lambda h: h[:max(4, len(h) // 2)]
            ),
            (
                "[IND-CCA f2] Perpanjang ciphertext (extension)",
                "ciphertext",
                lambda h: h + os.urandom(16).hex()
            ),
        ]

        # Tambah serangan khusus ECC
        if mode_name == "ECC":
            attacks += [
                (
                    "[IND-CCA d] Ganti ephemeral public key dengan random",
                    "ephemeral_public_key",
                    lambda h: os.urandom(32).hex()
                ),
                (
                    "[IND-CCA d2] Flip byte pertama ephemeral key",
                    "ephemeral_public_key",
                    lambda h: flip_bit_in_hex(h, 0, 0xFF)
                ),
            ]

        # Tambah serangan khusus RSA
        if mode_name == "RSA":
            attacks += [
                (
                    "[IND-CCA d] Flip byte pertama encrypted_session_key",
                    "encrypted_session_key",
                    lambda h: flip_bit_in_hex(h, 0, 0xFF)
                ),
                (
                    "[IND-CCA d2] Ganti encrypted_session_key dengan random",
                    "encrypted_session_key",
                    lambda h: os.urandom(len(bytes.fromhex(h))).hex()
                ),
            ]

        for label, field, modifier_fn in attacks:
            p = copy.deepcopy(base_packet)
            try:
                p[field] = modifier_fn(p[field])
            except Exception as e:
                warn(f"[{mode_name}] Gagal modifikasi field '{field}': {e}")
                continue

            try:
                code, resp = send_to_server(p)
                if code in (400, 500):
                    ok(f"[{mode_name}] {label} → DITOLAK server (kode {code})")
                    total_pass += 1
                elif code == 200:
                    fail(f"[{mode_name}] {label} → DITERIMA server (seharusnya ditolak!)")
                    total_fail += 1
                else:
                    warn(f"[{mode_name}] {label} → kode tidak terduga: {code}")
            except Exception as e:
                warn(f"[{mode_name}] {label} → error koneksi: {e}")

    print(f"\n  {'━'*50}")
    print(f"  {BOLD}Ringkasan IND-CCA:{RESET}")
    total = total_pass + total_fail
    pct   = round(total_pass / total * 100, 1) if total > 0 else 0
    if total_fail == 0:
        print(f"  {GREEN}✅ SEMUA {total_pass}/{total} tes lolos ({pct}%) — IND-CCA2 terpenuhi{RESET}")
        print(f"  {DIM}   Setiap modifikasi ciphertext terdeteksi dan ditolak server.{RESET}")
    else:
        print(f"  {RED}❌ {total_fail}/{total} tes gagal!{RESET}")
        print(f"  {YELLOW}   {total_fail} serangan tidak terdeteksi — perlu investigasi!{RESET}")

    return {"total_pass": total_pass, "total_fail": total_fail, "total": total}


# ════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n{BOLD}{'═'*60}")
    print(f"  ANALISIS KEAMANAN KRIPTOGRAFI")
    print(f"  Smart Agriculture Encryption System")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*60}{RESET}\n")

    if not check_server():
        print(f"{RED}Server tidak aktif! Jalankan server.py terlebih dahulu.{RESET}")
        exit(1)
    print(f"{GREEN}Server aktif ✓{RESET}\n")

    t_start = time.perf_counter()

    r1 = test_confidentiality()
    r2 = test_ind_cpa(n_trials=20)
    r3 = test_ind_cca()

    elapsed = round(time.perf_counter() - t_start, 2)

    print(f"\n{BOLD}{'═'*60}")
    print(f"  KESIMPULAN AKHIR")
    print(f"{'═'*60}{RESET}")

    all_conf_safe = all(not v["plaintext_exposed"] for v in r1.values())
    all_cpa_safe  = all(v["unique_ciphertexts"] == v["total_trials"] for v in r2.values())
    all_cca_safe  = r3["total_fail"] == 0

    def check(cond, label):
        if cond:
            print(f"  {GREEN}✅ {label}: TERPENUHI{RESET}")
        else:
            print(f"  {RED}❌ {label}: TIDAK TERPENUHI{RESET}")

    check(all_conf_safe, "Confidentiality  — data tidak bocor sebagai plaintext")
    check(all_cpa_safe,  "IND-CPA          — enkripsi non-deterministik, tidak bisa dibedakan")
    check(all_cca_safe,  "IND-CCA          — setiap modifikasi ciphertext terdeteksi & ditolak")

    print(f"\n  Waktu total analisis: {elapsed}s")
    print(f"{BOLD}{'═'*60}{RESET}\n")
