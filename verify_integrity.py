# verify_integrity.py
# Mencocokkan data historis sensor (sensor_logs/) dengan hasil dekripsi server (server_storage/)
# Membuktikan data tidak berubah selama enkripsi-dekripsi.
#
# Jalankan: python verify_integrity.py

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
LOG_DIR         = "sensor_logs"
OUTPUT_DIR      = "decrypted_output"
SERVER_KEYS_DIR = "keys"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_rsa_private_key():
    with open(f"{SERVER_KEYS_DIR}/rsa_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_ecc_private_key():
    with open(f"{SERVER_KEYS_DIR}/ecc_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


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
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=None, info=b"smart-agriculture-v1")
        session_key = hkdf.derive(shared_secret)
    else:
        raise ValueError(f"Mode tidak dikenal: {mode}")

    aesgcm    = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return json.loads(plaintext)


def load_all_sensor_logs():
    all_logs = {}
    if not os.path.exists(LOG_DIR):
        return all_logs
    for fname in sorted(os.listdir(LOG_DIR)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(LOG_DIR, fname)) as f:
            for entry in json.load(f):
                seq = entry.get("sequence_number")
                if seq is not None:
                    all_logs[seq] = entry
    print(f"[INFO] Loaded {len(all_logs)} entri dari sensor_logs/")
    return all_logs


def decrypt_all_storage():
    decrypted = {}
    failed    = []
    if not os.path.exists(STORAGE_DIR):
        return decrypted, failed
    files = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(".json")])
    print(f"[INFO] Mendekripsi {len(files)} file dari server_storage/...")

    for fname in files:
        fpath = os.path.join(STORAGE_DIR, fname)
        with open(fpath) as f:
            packet = json.load(f)
        try:
            plaintext = decrypt_packet(packet)
            seq = plaintext.get("sequence_number")
            if seq is not None:
                decrypted[seq] = plaintext
                out = os.path.join(OUTPUT_DIR, fname.replace("packet_", "plaintext_"))
                with open(out, "w") as f_out:
                    json.dump(plaintext, f_out, indent=2)
        except InvalidTag:
            failed.append((fname, "InvalidTag — ciphertext dimodifikasi"))
        except Exception as e:
            failed.append((fname, str(e)))

    print(f"[INFO] Berhasil: {len(decrypted)} | Gagal: {len(failed)}")
    return decrypted, failed


FIELDS = ["sensor_id", "timestamp", "temperature",
          "air_humidity", "soil_moisture", "soil_ph"]

def compare_entry(seq, original, decrypted):
    details   = []
    all_match = True
    for field in FIELDS:
        ov = original.get(field)
        dv = decrypted.get(field)
        if ov == dv:
            details.append(f"  ✓ {field:<15}: {ov}")
        else:
            details.append(f"  ✗ {field:<15}: asli={ov} | dekripsi={dv}")
            all_match = False
    return all_match, details


def verify_and_report(sensor_logs, decrypted_data, failed):
    print(f"\n{'='*55}")
    print(f"  LAPORAN PENCOCOKAN HISTORIS")
    print(f"{'='*55}")

    all_seqs    = sorted(set(list(sensor_logs.keys()) +
                             list(decrypted_data.keys())))
    matched     = mismatch = only_sensor = only_server = 0
    mismatches  = []

    for seq in all_seqs:
        in_log    = seq in sensor_logs
        in_server = seq in decrypted_data
        if in_log and in_server:
            ok, details = compare_entry(seq, sensor_logs[seq],
                                        decrypted_data[seq])
            if ok:
                matched += 1
            else:
                mismatch += 1
                mismatches.append((seq, details))
        elif in_log:
            only_sensor += 1
        else:
            only_server += 1

    print(f"\n  Total sequence unik          : {len(all_seqs)}")
    print(f"  ✓ Data cocok sempurna        : {matched}")
    print(f"  ✗ Data tidak cocok           : {mismatch}")
    print(f"  ⚠ Di sensor, tidak di server : {only_sensor}")
    print(f"  ⚠ Di server, tidak di sensor : {only_server}")
    print(f"  ✗ Dekripsi gagal             : {len(failed)}")

    if matched + mismatch > 0:
        rate = matched / (matched + mismatch) * 100
        print(f"\n  Integrity rate : {rate:.2f}%")
        if rate == 100.0:
            print("  → Semua data identik dengan data sensor asli ✓")
        else:
            print("  → Ada data yang berubah! ✗")

    if sensor_logs:
        avail = (matched / len(sensor_logs)) * 100
        print(f"  Availability   : {avail:.2f}%")
        if only_sensor > 0:
            print(f"  → {only_sensor} data sensor tidak sampai ke server")

    if mismatches:
        print(f"\n{'─'*55}")
        print("  DETAIL DATA TIDAK COCOK:")
        for seq, details in mismatches:
            print(f"\n  seq#{seq}:")
            for d in details:
                print(d)

    if failed:
        print(f"\n{'─'*55}")
        print("  DETAIL DEKRIPSI GAGAL:")
        for fname, reason in failed:
            print(f"  {fname}: {reason}")

    print(f"\n{'='*55}")
    print(f"  Plaintext tersimpan di: {OUTPUT_DIR}/")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    print("=" * 55)
    print("  VERIFIKASI INTEGRITAS DATA")
    print("=" * 55 + "\n")

    sensor_logs              = load_all_sensor_logs()
    decrypted_data, failed   = decrypt_all_storage()

    if not sensor_logs and not decrypted_data:
        print("Tidak ada data. Jalankan sistem terlebih dahulu.")
        sys.exit(0)

    verify_and_report(sensor_logs, decrypted_data, failed)
