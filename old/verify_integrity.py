# verify_integrity.py
# Mencocokkan data historis sensor (sensor_logs/) dengan hasil dekripsi server (server_storage/)
# Membuktikan bahwa data tidak berubah selama proses enkripsi-dekripsi
# Jalankan: python verify_integrity.py

import json
import os
import sys
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

STORAGE_DIR  = "server_storage"
LOG_DIR      = "sensor_logs"
OUTPUT_DIR   = "decrypted_output"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ── Load Private Keys ─────────────────────────────────────────────────────────

def load_rsa_private_key():
    with open("keys/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_ecc_private_key():
    with open("keys/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ── Dekripsi ──────────────────────────────────────────────────────────────────

def decrypt_packet(packet):
    mode = packet.get("mode", "").upper()
    nonce      = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    tag        = bytes.fromhex(packet["tag"])

    if mode == "RSA":
        rsa_priv    = load_rsa_private_key()
        session_key = rsa_priv.decrypt(
            bytes.fromhex(packet["encrypted_session_key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    elif mode == "ECC":
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
    else:
        raise ValueError(f"Mode tidak dikenal: {mode}")

    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


# ── Load Semua Log Sensor ─────────────────────────────────────────────────────

def load_all_sensor_logs():
    """
    Baca semua file log sensor dan bangun dictionary:
    { sequence_number: data_sensor }
    """
    all_logs = {}

    if not os.path.exists(LOG_DIR):
        print(f"[WARN] Folder '{LOG_DIR}/' tidak ditemukan.")
        return all_logs

    log_files = sorted([f for f in os.listdir(LOG_DIR) if f.endswith(".json")])
    if not log_files:
        print(f"[WARN] Tidak ada file log di '{LOG_DIR}/'.")
        return all_logs

    for fname in log_files:
        fpath = os.path.join(LOG_DIR, fname)
        with open(fpath) as f:
            entries = json.load(f)
        for entry in entries:
            seq = entry.get("sequence_number")
            if seq is not None:
                all_logs[seq] = entry

    print(f"[INFO] Loaded {len(all_logs)} entri dari {len(log_files)} file log sensor.")
    return all_logs


# ── Dekripsi Semua Ciphertext ─────────────────────────────────────────────────

def decrypt_all_storage():
    """
    Dekripsi semua file di server_storage/ dan kembalikan:
    { sequence_number: plaintext_data }
    """
    decrypted = {}
    failed    = []

    if not os.path.exists(STORAGE_DIR):
        print(f"[WARN] Folder '{STORAGE_DIR}/' tidak ditemukan.")
        return decrypted, failed

    files = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(".json")])
    if not files:
        print(f"[WARN] Tidak ada file ciphertext di '{STORAGE_DIR}/'.")
        return decrypted, failed

    print(f"[INFO] Mendekripsi {len(files)} file dari '{STORAGE_DIR}/'...")

    for fname in files:
        fpath = os.path.join(STORAGE_DIR, fname)
        with open(fpath) as f:
            packet = json.load(f)

        try:
            plaintext = decrypt_packet(packet)
            seq = plaintext.get("sequence_number")
            if seq is not None:
                decrypted[seq] = plaintext

                # Simpan plaintext ke decrypted_output/
                out_name = fname.replace("packet_", "plaintext_")
                out_path = os.path.join(OUTPUT_DIR, out_name)
                with open(out_path, "w") as f_out:
                    json.dump(plaintext, f_out, indent=2)

        except InvalidTag:
            failed.append((fname, "InvalidTag — ciphertext dimodifikasi atau rusak"))
        except Exception as e:
            failed.append((fname, str(e)))

    print(f"[INFO] Berhasil dekripsi: {len(decrypted)} | Gagal: {len(failed)}")
    return decrypted, failed


# ── Bandingkan Field per Field ────────────────────────────────────────────────

FIELDS_TO_CHECK = [
    "sensor_id", "timestamp", "temperature",
    "air_humidity", "soil_moisture", "soil_ph"
]

def compare_entry(seq, original, decrypted):
    """
    Bandingkan field penting antara data asli sensor dan hasil dekripsi.
    Return (match: bool, details: list of str)
    """
    details = []
    all_match = True

    for field in FIELDS_TO_CHECK:
        orig_val = original.get(field)
        dec_val  = decrypted.get(field)
        if orig_val == dec_val:
            details.append(f"  ✓ {field:<15}: {orig_val}")
        else:
            details.append(f"  ✗ {field:<15}: asli={orig_val} | dekripsi={dec_val}")
            all_match = False

    return all_match, details


# ── Laporan Pencocokan ────────────────────────────────────────────────────────

def verify_and_report(sensor_logs, decrypted_data, failed_decryptions):
    print(f"\n{'='*60}")
    print(f"  LAPORAN PENCOCOKAN HISTORIS")
    print(f"  Sensor logs vs Hasil Dekripsi Server Storage")
    print(f"{'='*60}")

    all_seqs     = sorted(set(list(sensor_logs.keys()) + list(decrypted_data.keys())))
    total        = len(all_seqs)
    matched      = 0
    mismatch     = 0
    only_sensor  = 0   # ada di log sensor tapi tidak di server (data hilang/belum sampai)
    only_server  = 0   # ada di server tapi tidak di log sensor (anomali)

    mismatch_details = []

    for seq in all_seqs:
        in_log    = seq in sensor_logs
        in_server = seq in decrypted_data

        if in_log and in_server:
            match, details = compare_entry(seq, sensor_logs[seq], decrypted_data[seq])
            if match:
                matched += 1
            else:
                mismatch += 1
                mismatch_details.append((seq, details))
        elif in_log and not in_server:
            only_sensor += 1
        elif not in_log and in_server:
            only_server += 1

    # ── Ringkasan ──────────────────────────────────────────────────────────
    print(f"\n  Total sequence number unik : {total}")
    print(f"  ✓ Data cocok sempurna      : {matched}")
    print(f"  ✗ Data tidak cocok         : {mismatch}")
    print(f"  ⚠ Ada di sensor, tidak di server (belum/gagal terkirim): {only_sensor}")
    print(f"  ⚠ Ada di server, tidak di log sensor (anomali)         : {only_server}")
    print(f"  ✗ Dekripsi gagal (ciphertext rusak/dimodifikasi)        : {len(failed_decryptions)}")

    # ── Integrity rate ─────────────────────────────────────────────────────
    if matched + mismatch > 0:
        integrity_rate = matched / (matched + mismatch) * 100
        print(f"\n  Integrity rate : {integrity_rate:.2f}%")
        if integrity_rate == 100.0:
            print("  → Semua data yang diterima server identik dengan data sensor asli ✓")
        else:
            print("  → Ada data yang berubah selama proses enkripsi-dekripsi ✗")

    # ── Data hilang (untuk availability experiment) ────────────────────────
    if only_sensor > 0:
        availability = (matched / len(sensor_logs)) * 100 if sensor_logs else 0
        print(f"\n  Availability   : {availability:.2f}%")
        print(f"  → {only_sensor} data sensor belum/tidak sampai ke server")
        print(f"    (mungkin masih di gateway_buffer/ atau hilang)")

    # ── Detail mismatch ────────────────────────────────────────────────────
    if mismatch_details:
        print(f"\n{'─'*60}")
        print(f"  DETAIL DATA TIDAK COCOK:")
        for seq, details in mismatch_details:
            print(f"\n  seq#{seq}:")
            for d in details:
                print(d)

    # ── Detail dekripsi gagal ──────────────────────────────────────────────
    if failed_decryptions:
        print(f"\n{'─'*60}")
        print(f"  DETAIL DEKRIPSI GAGAL:")
        for fname, reason in failed_decryptions:
            print(f"  {fname}: {reason}")

    print(f"\n{'='*60}")
    print(f"  Plaintext hasil dekripsi disimpan di: {OUTPUT_DIR}/")
    print(f"{'='*60}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  VERIFIKASI INTEGRITAS DATA")
    print("  Mencocokkan sensor_logs/ dengan server_storage/")
    print("=" * 60 + "\n")

    sensor_logs     = load_all_sensor_logs()
    decrypted_data, failed = decrypt_all_storage()

    if not sensor_logs and not decrypted_data:
        print("\n[INFO] Tidak ada data untuk diverifikasi.")
        print("Pastikan sensor simulator dan server sudah pernah dijalankan.")
        sys.exit(0)

    verify_and_report(sensor_logs, decrypted_data, failed)
