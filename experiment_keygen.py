"""
Eksperimen: Pengukuran Waktu Pembangkitan dan Verifikasi Keypair
Mengukur waktu generate + verify untuk RSA-2048 dan ECC X25519
n=30 iterasi, melaporkan mean ± standar deviasi
"""

import time
import statistics
import csv
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.backends import default_backend

N = 30  # jumlah iterasi

# ─── RSA-2048 ──────────────────────────────────────────────────────────────────

rsa_gen_times   = []
rsa_verify_times = []

print(f"[RSA-2048] Menjalankan {N} iterasi...")

for i in range(N):
    # --- Generate ---
    t0 = time.perf_counter()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    t1 = time.perf_counter()
    rsa_gen_times.append((t1 - t0) * 1000)

    # --- Verify (ekstrak public numbers → validasi keypair) ---
    t0 = time.perf_counter()
    pub_numbers = public_key.public_numbers()  # akses angka kunci → validasi keypair
    t1 = time.perf_counter()
    rsa_verify_times.append((t1 - t0) * 1000)

    print(f"  Run {i+1:2d}: gen={rsa_gen_times[-1]:.4f} ms | verify={rsa_verify_times[-1]:.4f} ms")

# ─── ECC X25519 ────────────────────────────────────────────────────────────────

ecc_gen_times    = []
ecc_verify_times = []

print(f"\n[ECC X25519] Menjalankan {N} iterasi...")

for i in range(N):
    # --- Generate ---
    t0 = time.perf_counter()
    ecc_private = x25519.X25519PrivateKey.generate()
    ecc_public  = ecc_private.public_key()
    t1 = time.perf_counter()
    ecc_gen_times.append((t1 - t0) * 1000)

    # --- Verify (ekstrak raw public key bytes → validasi keypair) ---
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    t0 = time.perf_counter()
    raw = ecc_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert len(raw) == 32, "Public key X25519 harus 32 bytes"
    t1 = time.perf_counter()
    ecc_verify_times.append((t1 - t0) * 1000)

    print(f"  Run {i+1:2d}: gen={ecc_gen_times[-1]:.4f} ms | verify={ecc_verify_times[-1]:.4f} ms")

# ─── Laporan ───────────────────────────────────────────────────────────────────

def summarize(label, times):
    mean = statistics.mean(times)
    sd   = statistics.stdev(times)
    print(f"  {label}: {mean:.4f} ± {sd:.4f} ms")
    return mean, sd

print("\n" + "="*55)
print("  LAPORAN WAKTU PEMBANGKITAN DAN VERIFIKASI KEYPAIR")
print(f"  (n={N}, mean ± standar deviasi, satuan ms)")
print("="*55)

print("\n[RSA-2048]")
rsa_gen_mean,    rsa_gen_sd    = summarize("Generate  ", rsa_gen_times)
rsa_ver_mean,    rsa_ver_sd    = summarize("Verify    ", rsa_verify_times)

print("\n[ECC X25519]")
ecc_gen_mean,    ecc_gen_sd    = summarize("Generate  ", ecc_gen_times)
ecc_ver_mean,    ecc_ver_sd    = summarize("Verify    ", ecc_verify_times)

# ─── Simpan ke CSV ─────────────────────────────────────────────────────────────

csv_filename = "hasil_keygen.csv"
with open(csv_filename, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["run", "rsa_gen_ms", "rsa_verify_ms", "ecc_gen_ms", "ecc_verify_ms"])
    for i in range(N):
        writer.writerow([
            i+1,
            f"{rsa_gen_times[i]:.4f}",
            f"{rsa_verify_times[i]:.4f}",
            f"{ecc_gen_times[i]:.4f}",
            f"{ecc_verify_times[i]:.4f}",
        ])

print(f"\n[INFO] Data mentah disimpan ke: {csv_filename}")
print("\n[RINGKASAN UNTUK TABEL PAPER]")
print(f"  RSA-2048  | Generate: {rsa_gen_mean:.4f} ± {rsa_gen_sd:.4f} ms | Verify: {rsa_ver_mean:.4f} ± {rsa_ver_sd:.4f} ms")
print(f"  ECC X25519| Generate: {ecc_gen_mean:.4f} ± {ecc_gen_sd:.4f} ms | Verify: {ecc_ver_mean:.4f} ± {ecc_ver_sd:.4f} ms")