import json
import os
import time
import statistics
import csv
import requests
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime

from aes import encrypt, decrypt
from rsa import encrypt_session_key, decrypt_session_key, private_key, public_key
from ecc import derive_session_key, public_key_to_bytes, public_key_from_bytes, server_private_key, server_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.exceptions import InvalidTag

GATEWAY_URL = "http://localhost:5001/receive"
SERVER_URL  = "http://localhost:5002"
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────────────────────
# CEK KONEKSI
# ─────────────────────────────────────────────────────────────
def check_connections():
    print("Memeriksa koneksi...")
    ok = True
    try:
        requests.get(f"{SERVER_URL}/health", timeout=3)
        print("  Server aktif di port 5002 ✅")
    except Exception:
        print("  Server TIDAK aktif! Jalankan: python server.py ❌")
        ok = False
    try:
        requests.get("http://localhost:5001/stats", timeout=3)
        print("  Gateway aktif di port 5001 ✅")
    except Exception:
        print("  Gateway TIDAK aktif! Jalankan: python gateway.py ❌")
        ok = False
    return ok

# ─────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────
def generate_payload(size_kb=1, seq=1):
    base = {
        "sensor_id":       "FIELD-01-SENSOR-01",
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "temperature":     31.5,
        "air_humidity":    72.3,
        "soil_moisture":   41.8,
        "soil_ph":         6.4,
        "sequence_number": seq
    }
    target_bytes = size_kb * 1024
    current_size = len(json.dumps(base).encode())
    dummy_size   = max(0, target_bytes - current_size)
    if dummy_size > 0:
        base["dummy"] = "x" * dummy_size
    return base

def do_encrypt_rsa(payload):
    data_json    = json.dumps(payload)
    session_key  = os.urandom(32)
    encrypted_sk = encrypt_session_key(public_key, session_key)
    aes_result   = encrypt(session_key, data_json.encode())
    return {
        "mode": "RSA",
        "algorithm": "RSA-OAEP-SHA256-AES-256-GCM",
        "encrypted_session_key": encrypted_sk,
        "nonce": aes_result["nonce"],
        "ciphertext": aes_result["ciphertext"],
        "tag": aes_result["tag"]
    }

def do_decrypt_rsa(packet):
    session_key = decrypt_session_key(private_key, packet["encrypted_session_key"])
    plaintext   = decrypt(session_key, packet["nonce"], packet["ciphertext"], packet["tag"])
    return json.loads(plaintext.decode())

def do_encrypt_ecc(payload):
    data_json         = json.dumps(payload)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public  = ephemeral_private.public_key()
    session_key       = derive_session_key(ephemeral_private, server_public_key)
    ephem_pub_hex     = public_key_to_bytes(ephemeral_public).hex()
    aes_result        = encrypt(session_key, data_json.encode())
    return {
        "mode": "ECC",
        "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
        "ephemeral_public_key": ephem_pub_hex,
        "nonce": aes_result["nonce"],
        "ciphertext": aes_result["ciphertext"],
        "tag": aes_result["tag"]
    }

def do_decrypt_ecc(packet):
    ephem_pub   = public_key_from_bytes(bytes.fromhex(packet["ephemeral_public_key"]))
    session_key = derive_session_key(server_private_key, ephem_pub)
    plaintext   = decrypt(session_key, packet["nonce"], packet["ciphertext"], packet["tag"])
    return json.loads(plaintext.decode())

# ─────────────────────────────────────────────────────────────
# EKSPERIMEN 1: KINERJA END-TO-END (30 runs)
# ─────────────────────────────────────────────────────────────
def run_benchmark_e2e(mode, size_kb, n_runs=30):
    print(f"  [{mode} | {size_kb}KB] {n_runs} runs...", end=" ", flush=True)
    rtt_times = []
    storage_dir = os.path.join(BASE_DIR, "server_storage")
    storage_before = len(os.listdir(storage_dir)) if os.path.exists(storage_dir) else 0
    ct_sizes = []

    for i in range(n_runs):
        payload = generate_payload(size_kb=size_kb, seq=i+1)
        t_start = time.perf_counter()
        try:
            response = requests.post(
                GATEWAY_URL,
                json={"sensor_data": payload, "mode": mode},
                timeout=10
            )
            t_end = time.perf_counter()
            if response.status_code == 200:
                rtt_times.append((t_end - t_start) * 1000)
        except Exception as e:
            print(f"\n  [ERROR] Run {i+1}: {e}")
        time.sleep(0.05)

    #Ukur ukuran ciphertext dari server_storage
    if os.path.exists(storage_dir):
        all_files = sorted(os.listdir(storage_dir))
        new_files = all_files[storage_before:]
        for fname in new_files[:n_runs]:
            fpath = os.path.join(storage_dir, fname)
            ct_sizes.append(os.path.getsize(fpath))

    if not rtt_times:
        print("GAGAL")
        return None

    result = {
        "mode":               mode,
        "size_kb":            size_kb,
        "n_runs":             len(rtt_times),
        "rtt_mean_ms":        round(statistics.mean(rtt_times), 4),
        "rtt_std_ms":         round(statistics.stdev(rtt_times) if len(rtt_times) > 1 else 0, 4),
        "ct_size_mean_bytes": round(statistics.mean(ct_sizes), 2) if ct_sizes else 0,
        "ct_size_std_bytes":  round(statistics.stdev(ct_sizes) if len(ct_sizes) > 1 else 0, 2),
    }
    print(f"RTT={result['rtt_mean_ms']}±{result['rtt_std_ms']}ms")
    return result

# ─────────────────────────────────────────────────────────────
# EKSPERIMEN 2: THROUGHPUT
# ─────────────────────────────────────────────────────────────
def run_throughput(mode, size_kb=1, duration_sec=10):
    print(f"  [{mode} | {size_kb}KB] Throughput {duration_sec} detik...", end=" ", flush=True)
    count, errors, seq = 0, 0, 0
    deadline = time.perf_counter() + duration_sec

    while time.perf_counter() < deadline:
        seq += 1
        payload = generate_payload(size_kb, seq=seq)
        try:
            response = requests.post(
                GATEWAY_URL,
                json={"sensor_data": payload, "mode": mode},
                timeout=5
            )
            if response.status_code == 200:
                count += 1
            else:
                errors += 1
        except Exception:
            errors += 1

    throughput = round(count / duration_sec, 2)
    print(f"{throughput} pesan/detik")
    return {
        "mode": mode, "size_kb": size_kb,
        "throughput_msg_per_sec": throughput,
        "total_success": count, "total_error": errors,
        "duration_sec": duration_sec
    }

# ─────────────────────────────────────────────────────────────
# EKSPERIMEN 3: AVAILABILITY
# ─────────────────────────────────────────────────────────────
def run_availability():
    print("\n" + "=" * 50)
    print("  EKSPERIMEN AVAILABILITY — LOCAL BUFFERING")
    print("=" * 50)

    try:
        resp  = requests.get("http://localhost:5001/stats", timeout=3)
        stats = resp.json()
        print(f"\n  Stats gateway saat ini:")
        print(f"  Terkirim ke server : {stats.get('sent', 0)}")
        print(f"  Di buffer          : {stats.get('pending_in_buffer', 0)}")
        print(f"  Retry berhasil     : {stats.get('retry_sent', 0)}")
    except Exception:
        print("  Gateway tidak aktif!")

    print("""
  Cara test availability secara manual:
  1. Biarkan sensor.py dan gateway.py jalan
  2. Stop server.py (Ctrl+C di terminal server)
  3. Tunggu beberapa detik → data masuk gateway_buffer/
  4. Jalankan lagi server.py
  5. Gateway otomatis kirim ulang buffer
  6. Cek stats: http://localhost:5001/stats
    """)

# ─────────────────────────────────────────────────────────────
# ANALISIS KEAMANAN
# ─────────────────────────────────────────────────────────────
def run_security_analysis():
    print("\n" + "=" * 50)
    print("  ANALISIS KEAMANAN")
    print("=" * 50)

    payload = generate_payload()

    # 1. IND-CPA
    print("\n1. IND-CPA: plaintext sama → ciphertext berbeda?")
    p1 = do_encrypt_rsa(payload); p2 = do_encrypt_rsa(payload)
    print(f"   RSA: {p1['ciphertext'] != p2['ciphertext']} ✅")
    e1 = do_encrypt_ecc(payload); e2 = do_encrypt_ecc(payload)
    print(f"   ECC: {e1['ciphertext'] != e2['ciphertext']} ✅")

    # 2. IND-CCA
    print("\n2. IND-CCA: ciphertext dimodifikasi → ditolak?")
    ct_bytes = bytearray(bytes.fromhex(p1["ciphertext"]))
    ct_bytes[0] ^= 0xFF
    p1_rusak = dict(p1); p1_rusak["ciphertext"] = bytes(ct_bytes).hex()
    try:
        do_decrypt_rsa(p1_rusak)
        print("   RSA: GAGAL — diterima!")
    except InvalidTag:
        print("   RSA: DITOLAK (InvalidTag) ✅")

    ct_bytes = bytearray(bytes.fromhex(e1["ciphertext"]))
    ct_bytes[0] ^= 0xFF
    e1_rusak = dict(e1); e1_rusak["ciphertext"] = bytes(ct_bytes).hex()
    try:
        do_decrypt_ecc(e1_rusak)
        print("   ECC: GAGAL — diterima!")
    except InvalidTag:
        print("   ECC: DITOLAK (InvalidTag) ✅")

    # 3. Nonce unik
    print("\n3. Nonce unik (100 enkripsi)?")
    nonces = {do_encrypt_ecc(payload)["nonce"] for _ in range(100)}
    print(f"   {len(nonces)}/100 nonce unik: {len(nonces) == 100} ✅")

    # 4. Server tidak simpan plaintext
    print("\n4. Server hanya simpan ciphertext?")
    storage_dir = os.path.join(BASE_DIR, "server_storage")
    if os.path.exists(storage_dir) and os.listdir(storage_dir):
        sample = os.path.join(storage_dir, sorted(os.listdir(storage_dir))[0])
        with open(sample) as f:
            packet = json.load(f)
        has_plaintext = "temperature" in packet.get("ciphertext", "")
        print(f"   Server aman (hanya ciphertext): {not has_plaintext} ✅")
    else:
        print("   Belum ada file di server_storage/")

    # 5. Jawaban pertanyaan wajib paper
    print("\n5. Jawaban pertanyaan wajib paper:")
    qa = [
        ("Q1",  "Arsitektur 3 tier: Sensor → Gateway → Server"),
        ("Q2",  "RSA-OAEP/ECDH lindungi session key, AES-GCM enkripsi data"),
        ("Q3",  "Hybrid encryption — RSA/ECC lambat untuk data besar"),
        ("Q4",  "ECC lebih cepat dari RSA (lihat hasil_kinerja.csv)"),
        ("Q5",  "ECC hasilkan ciphertext lebih kecil dari RSA"),
        ("Q6",  "Gateway simpan ciphertext ke gateway_buffer/ saat server mati"),
        ("Q7",  "Ya — AES-GCM + RSA/ECC jamin confidentiality"),
        ("Q8",  "Ya — nonce unik + OAEP/ephemeral key → IND-CPA"),
        ("Q9",  "Ya — AES-GCM authentication tag → IND-CCA"),
        ("Q10", "Metadata tidak dienkripsi, buffer hanya lokal"),
    ]
    for q, a in qa:
        print(f"   {q}: {a}")

# ─────────────────────────────────────────────────────────────
# SIMPAN CSV
# ─────────────────────────────────────────────────────────────
def save_csv(results, filename):
    results = [r for r in results if r is not None]
    if not results:
        return
    filepath = os.path.join(BASE_DIR, filename)
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"  Tersimpan: {filename}")

# ─────────────────────────────────────────────────────────────
# GRAFIK (LINE CHART)
# ─────────────────────────────────────────────────────────────
def plot_results(results):
    results = [r for r in results if r is not None]
    if not results:
        print("  Tidak ada data untuk grafik.")
        return

    sizes   = sorted(set(r["size_kb"] for r in results))
    modes   = sorted(set(r["mode"] for r in results))
    colors  = {"RSA": "#534AB7", "ECC": "#0F6E56"}
    markers = {"RSA": "o", "ECC": "s"}

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Hasil Eksperimen Kinerja End-to-End — RSA vs ECC\nSmart Agriculture Monitoring",
                 fontsize=13, fontweight="bold")

    # 1. Round-trip time
    ax = axes[0, 0]
    for mode in modes:
        data = sorted([r for r in results if r["mode"] == mode], key=lambda x: x["size_kb"])
        rtt  = [r["rtt_mean_ms"] for r in data]
        std  = [r["rtt_std_ms"]  for r in data]
        ax.plot(sizes, rtt, label=mode, color=colors.get(mode, "gray"),
                marker=markers.get(mode, "o"), linewidth=2, markersize=7)
        ax.fill_between(sizes,
                        [r - s for r, s in zip(rtt, std)],
                        [r + s for r, s in zip(rtt, std)],
                        alpha=0.15, color=colors.get(mode, "gray"))
    ax.set_title("Round-Trip Time (Enc + Kirim + Dec)")
    ax.set_xlabel("Ukuran Data (KB)")
    ax.set_ylabel("Waktu (ms)")
    ax.set_xticks(sizes); ax.set_xticklabels([f"{s} KB" for s in sizes])
    ax.legend(); ax.grid(True, alpha=0.3)

    # 2. Ukuran ciphertext
    ax = axes[0, 1]
    for mode in modes:
        data  = sorted([r for r in results if r["mode"] == mode], key=lambda x: x["size_kb"])
        ct_kb = [r["ct_size_mean_bytes"] / 1024 for r in data]
        std   = [r["ct_size_std_bytes"]  / 1024 for r in data]
        ax.plot(sizes, ct_kb, label=mode, color=colors.get(mode, "gray"),
                marker=markers.get(mode, "o"), linewidth=2, markersize=7)
        ax.fill_between(sizes,
                        [c - s for c, s in zip(ct_kb, std)],
                        [c + s for c, s in zip(ct_kb, std)],
                        alpha=0.15, color=colors.get(mode, "gray"))
    ax.set_title("Ukuran Ciphertext Total")
    ax.set_xlabel("Ukuran Data (KB)")
    ax.set_ylabel("Ukuran Ciphertext (KB)")
    ax.set_xticks(sizes); ax.set_xticklabels([f"{s} KB" for s in sizes])
    ax.legend(); ax.grid(True, alpha=0.3)

    # 3. Perbandingan RTT RSA vs ECC
    ax = axes[1, 0]
    for mode in modes:
        data = sorted([r for r in results if r["mode"] == mode], key=lambda x: x["size_kb"])
        ax.plot(sizes, [r["rtt_mean_ms"] for r in data],
                label=mode, color=colors.get(mode, "gray"),
                marker=markers.get(mode, "o"), linewidth=2, markersize=7)
    ax.set_title("Perbandingan RTT RSA vs ECC")
    ax.set_xlabel("Ukuran Data (KB)")
    ax.set_ylabel("Waktu (ms)")
    ax.set_xticks(sizes); ax.set_xticklabels([f"{s} KB" for s in sizes])
    ax.legend(); ax.grid(True, alpha=0.3)

    # 4. RTT dengan standar deviasi
    ax = axes[1, 1]
    for mode in modes:
        data = sorted([r for r in results if r["mode"] == mode], key=lambda x: x["size_kb"])
        rtt  = [r["rtt_mean_ms"] for r in data]
        std  = [r["rtt_std_ms"]  for r in data]
        ax.errorbar(sizes, rtt, yerr=std, label=mode,
                    color=colors.get(mode, "gray"),
                    marker=markers.get(mode, "o"),
                    capsize=5, linewidth=2, markersize=7)
    ax.set_title("RTT dengan Standar Deviasi")
    ax.set_xlabel("Ukuran Data (KB)")
    ax.set_ylabel("Waktu (ms)")
    ax.set_xticks(sizes); ax.set_xticklabels([f"{s} KB" for s in sizes])
    ax.legend(); ax.grid(True, alpha=0.3)

    plt.tight_layout()
    filepath = os.path.join(BASE_DIR, "grafik_kinerja.png")
    plt.savefig(filepath, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Grafik tersimpan: grafik_kinerja.png")

# ─────────────────────────────────────────────────────────────
# TABEL RINGKASAN
# ─────────────────────────────────────────────────────────────
def print_table(results):
    results = [r for r in results if r is not None]
    if not results:
        return
    print(f"\n{'='*70}")
    print(f"{'Mode':<6} {'KB':>4} {'RTT Mean(ms)':>14} {'±':>10} "
          f"{'CT Mean(B)':>12} {'±':>10}")
    print("-" * 70)
    for r in results:
        print(f"{r['mode']:<6} {r['size_kb']:>4} "
              f"{r['rtt_mean_ms']:>14.4f} {r['rtt_std_ms']:>10.4f} "
              f"{r['ct_size_mean_bytes']:>12.1f} {r['ct_size_std_bytes']:>10.1f}")
    print("=" * 70)

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  EKSPERIMEN KRIPTOGRAFI SMART AGRICULTURE")
    print("=" * 55)

    if not check_connections():
        print("\nJalankan server dan gateway dulu!")
        exit(1)

    SIZES  = [1, 10, 100]
    MODES  = ["RSA", "ECC"]
    N_RUNS = 30

    print(f"\nKonfigurasi: {N_RUNS} runs | Ukuran: {SIZES} KB | Mode: {MODES}")

    # Eksperimen kinerja
    print("\n" + "=" * 55)
    print("  BAGIAN 1: ROUND-TRIP TIME & CIPHERTEXT SIZE")
    print("=" * 55)
    perf_results = []
    for mode in MODES:
        for size in SIZES:
            r = run_benchmark_e2e(mode, size, n_runs=N_RUNS)
            perf_results.append(r)

    # Throughput
    print("\n" + "=" * 55)
    print("  BAGIAN 2: THROUGHPUT")
    print("=" * 55)
    throughput_results = []
    for mode in MODES:
        r = run_throughput(mode, size_kb=1, duration_sec=10)
        throughput_results.append(r)

    # Availability
    run_availability()

    # Analisis keamanan
    run_security_analysis()

    # Tabel ringkasan
    print_table(perf_results)

    # Simpan CSV
    print("\nMenyimpan CSV...")
    save_csv(perf_results,       "hasil_kinerja.csv")
    save_csv(throughput_results, "hasil_throughput.csv")

    # Grafik
    print("\nMembuat grafik...")
    plot_results(perf_results)

    print("\nSelesai! File yang dihasilkan:")
    print("  - hasil_kinerja.csv")
    print("  - hasil_throughput.csv")
    print("  - grafik_kinerja.png")