# experiment.py
# Eksperimen kinerja END-TO-END yang benar sesuai requirement tugas.
#
# PENTING: Server dan Gateway HARUS aktif sebelum menjalankan script ini.
# Jalankan dulu:
#   Terminal 1: python server.py
#   Terminal 2: python edge_gateway.py
#   Terminal 3 (ini): python experiment.py
#
# Yang diukur (end-to-end):
#   Round-trip : sejak sensor kirim plaintext → gateway enkripsi
#                → server dekripsi → response kembali ke sensor
#   CT Size    : ukuran file ciphertext yang tersimpan di server_storage/

import time
import json
import os
import statistics
import csv
import requests
from datetime import datetime

GATEWAY_URL = "http://localhost:5001/receive"
SERVER_URL  = "http://localhost:5002"


# ── Cek Koneksi ───────────────────────────────────────────────────────────────

def check_connections():
    print("Memeriksa koneksi ke gateway dan server...")
    ok = True
    try:
        requests.get(f"{SERVER_URL}/health", timeout=3)
        print("  ✓ Server aktif di port 5002")
    except Exception:
        print("  ✗ Server TIDAK aktif! Jalankan: python server.py")
        ok = False
    try:
        requests.get("http://localhost:5001/stats", timeout=3)
        print("  ✓ Gateway aktif di port 5001")
    except Exception:
        print("  ✗ Gateway TIDAK aktif! Jalankan: python edge_gateway.py")
        ok = False
    return ok


# ── Generate Payload ──────────────────────────────────────────────────────────

def generate_payload(target_size_kb, seq=1):
    """Buat payload JSON sensor mendekati target_size_kb."""
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
    current_size = len(json.dumps(base).encode())
    dummy_size   = max(0, target_bytes - current_size)
    if dummy_size > 0:
        base["dummy"] = "x" * dummy_size
    return base


# ── Eksperimen End-to-End ─────────────────────────────────────────────────────

def measure_e2e(mode, size_kb, n_runs=30):
    """
    Ukur waktu round-trip end-to-end sesungguhnya:
    sensor kirim plaintext → gateway enkripsi → server dekripsi → response balik.
    Ini mencakup: enkripsi + pengiriman jaringan + dekripsi + verifikasi tag.
    """
    print(f"\n[{mode} | {size_kb}KB] Mulai pengukuran {n_runs} runs...")

    rtt_times = []
    ct_sizes  = []
    storage_before = len(os.listdir("server_storage")) if os.path.exists("server_storage") else 0

    for i in range(n_runs):
        payload = generate_payload(size_kb, seq=i + 1)

        # Catat waktu mulai → kirim → tunggu response server
        t_start  = time.perf_counter()
        try:
            response = requests.post(
                GATEWAY_URL,
                json={"sensor_data": payload, "mode": mode},
                timeout=10
            )
            t_end = time.perf_counter()

            if response.status_code == 200:
                rtt_times.append((t_end - t_start) * 1000)  # ms
            else:
                print(f"  [WARN] Run {i+1}: response {response.status_code}")
        except Exception as e:
            print(f"  [ERROR] Run {i+1}: {e}")
            continue

        time.sleep(0.05)  # jeda kecil antar run

        if (i + 1) % 10 == 0:
            print(f"  [{mode} | {size_kb}KB] Run {i+1}/{n_runs} selesai")

    # Ukuran ciphertext dari file server_storage yang baru terbuat
    if os.path.exists("server_storage"):
        all_files  = sorted(os.listdir("server_storage"))
        new_files  = all_files[storage_before:]
        for fname in new_files[:n_runs]:
            fpath = os.path.join("server_storage", fname)
            ct_sizes.append(os.path.getsize(fpath))

    if not rtt_times:
        print(f"  [ERROR] Tidak ada data valid.")
        return None

    result = {
        "mode":                mode,
        "size_kb":             size_kb,
        "n_runs":              len(rtt_times),
        "rtt_mean_ms":         round(statistics.mean(rtt_times), 4),
        "rtt_stdev_ms":        round(statistics.stdev(rtt_times) if len(rtt_times) > 1 else 0, 4),
        "ct_size_mean_bytes":  round(statistics.mean(ct_sizes), 2) if ct_sizes else 0,
        "ct_size_stdev_bytes": round(statistics.stdev(ct_sizes) if len(ct_sizes) > 1 else 0, 2),
    }

    print(f"  Round-trip time : {result['rtt_mean_ms']} ± {result['rtt_stdev_ms']} ms")
    print(f"  CT Size         : {result['ct_size_mean_bytes']} ± {result['ct_size_stdev_bytes']} bytes")
    return result


# ── Eksperimen Throughput ─────────────────────────────────────────────────────

def measure_throughput(mode, size_kb=1, duration_sec=10):
    """
    Ukur throughput end-to-end: berapa pesan/detik yang berhasil
    diproses seluruh sistem (sensor → gateway → server) dalam duration_sec.
    """
    print(f"\n[Throughput {mode} | {size_kb}KB] Selama {duration_sec} detik...")

    count    = 0
    errors   = 0
    seq      = 0
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
    print(f"  Throughput {mode}: {throughput} pesan/detik "
          f"(berhasil: {count}, error: {errors})")
    return {
        "mode":                   mode,
        "size_kb":                size_kb,
        "throughput_msg_per_sec": throughput,
        "total_success":          count,
        "total_error":            errors,
        "duration_sec":           duration_sec
    }


# ── Simpan ke CSV ─────────────────────────────────────────────────────────────

def save_csv(results, filename):
    results = [r for r in results if r is not None]
    if not results:
        return
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"Hasil disimpan ke: {filename}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  EKSPERIMEN KINERJA END-TO-END")
    print("  Sensor → Gateway (enkripsi) → Server (dekripsi)")
    print("=" * 60)

    if not check_connections():
        print("\nHentikan eksperimen.")
        print("Jalankan server dan gateway terlebih dahulu!")
        exit(1)

    SIZES  = [1, 10, 100]
    MODES  = ["RSA", "ECC", "X25519"]   # ← tambah X25519
    N_RUNS = 30

    print(f"\nKonfigurasi: {N_RUNS} runs | Ukuran: {SIZES} KB | Mode: {MODES}")

    perf_results       = []
    throughput_results = []

    print("\n" + "=" * 60)
    print("  BAGIAN 1: ROUND-TRIP TIME & CIPHERTEXT SIZE")
    print("=" * 60)

    for mode in MODES:
        for size in SIZES:
            r = measure_e2e(mode, size, n_runs=N_RUNS)
            perf_results.append(r)

    print("\n" + "=" * 60)
    print("  BAGIAN 2: THROUGHPUT (10 detik per mode)")
    print("=" * 60)

    for mode in MODES:
        r = measure_throughput(mode, size_kb=1, duration_sec=10)
        throughput_results.append(r)

    print("\n" + "=" * 60)
    save_csv(perf_results,       "experiment_results.csv")
    save_csv(throughput_results, "throughput_results.csv")

    print("\nSemua eksperimen selesai!")
    print("Hasil: experiment_results.csv & throughput_results.csv")
