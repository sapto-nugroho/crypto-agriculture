import time
import json
import os
import re
import statistics
import csv
import requests
from datetime import datetime

# GATEWAY_URL = "http://localhost:5001/receive" #IPv6
# SERVER_URL  = "http://localhost:5002"

GATEWAY_URL = "http://127.0.0.1:5001/receive" #IPv4
SERVER_URL  = "http://127.0.0.1:5002"


def check_connections():
    print("Memeriksa koneksi...")
    ok = True
    try:
        requests.get(f"{SERVER_URL}/health", timeout=3)
        print("  ✓ Server aktif")
    except Exception:
        print("  ✗ Server TIDAK aktif!")
        ok = False
    try:
        requests.get("http://localhost:5001/stats", timeout=3)
        print("  ✓ Gateway aktif")
    except Exception:
        print("  ✗ Gateway TIDAK aktif!")
        ok = False
    return ok


def generate_payload(target_size_kb, seq=1):
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
    dummy_size   = max(0, target_bytes - len(json.dumps(base).encode()))
    if dummy_size > 0:
        base["dummy"] = "x" * dummy_size
    return base


def warmup(mode, n_warmup=5):
    """
    Kirim beberapa request warm-up sebelum pengukuran.
    Tujuan: buka koneksi, inisialisasi Flask, cache OS.
    Hasil TIDAK dimasukkan ke data eksperimen.
    """
    print(f"\n[WARMUP] {n_warmup} request untuk {mode}...")
    payload = generate_payload(1, seq=0)
    for _ in range(n_warmup):
        try:
            requests.post(
                GATEWAY_URL,
                json={"sensor_data": payload, "mode": mode},
                timeout=10
            )
        except Exception:
            pass
    print(f"  [WARMUP] Selesai.\n")


def measure_e2e(mode, size_kb, n_runs=30):
    """
    Ukur per-run, setiap run = 1 baris CSV.
    Kolom output CSV:
      run                : nomor urut run (1–30)
      mode               : RSA atau ECC
      size_kb            : ukuran payload target (1 / 10 / 100)
      enc_ms             : waktu enkripsi di gateway (ms)
                           diukur: t_enc_end - t_enc_start
      dec_ms             : waktu dekripsi di server (ms)
                           diukur: t_dec_end - t_dec_start, dikirim via response
      net_ms             : waktu jaringan murni gateway↔server (ms)
                           dihitung: trans_ms - dec_ms
      e2e_ms             : end-to-end, dari enkripsi s/d data tersimpan di server (ms)
                           dihitung: enc_ms + trans_ms  (= enc + net + dec)
      payload_size_bytes : ukuran ciphertext JSON di server (bytes)
    """
    print(f"[{mode} | {size_kb}KB] Mulai {n_runs} runs...")

    rows = []

    for i in range(n_runs):
        payload = generate_payload(size_kb, seq=i + 1)

        try:
            response = requests.post(
                GATEWAY_URL,
                json={"sensor_data": payload, "mode": mode},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()

                row = {
                    "run":                i + 1,
                    "mode":               mode,
                    "size_kb":            size_kb,
                    "enc_ms":             data.get("enc_ms",             0),
                    "dec_ms":             data.get("dec_ms",             0),
                    "net_ms":             data.get("net_ms",             0),
                    "e2e_ms":             data.get("e2e_ms",             0),
                    "payload_size_bytes": data.get("payload_size_bytes", 0),
                }
                rows.append(row)
                print(f"  run {i+1:02d} | "
                      f"enc={row['enc_ms']}ms "
                      f"dec={row['dec_ms']}ms "
                      f"net={row['net_ms']}ms "
                      f"e2e={row['e2e_ms']}ms "
                      f"size={row['payload_size_bytes']}B")
            else:
                print(f"  [WARN] Run {i+1}: status {response.status_code}")

        except Exception as e:
            print(f"  [ERROR] Run {i+1}: {e}")
            continue

        if (i + 1) % 10 == 0:
            print(f"  [{mode} | {size_kb}KB] Checkpoint: {i+1}/{n_runs} selesai")

    print(f"  Total valid: {len(rows)}/{n_runs} runs\n")
    return rows


def measure_throughput(mode, size_kb, duration_sec=10):
    """Throughput: pesan/detik selama duration_sec."""
    print(f"\n[Throughput {mode} | {size_kb}KB] {duration_sec} detik...")
    count    = 0
    errors   = 0
    seq      = 0
    deadline = time.perf_counter() + duration_sec
    while time.perf_counter() < deadline:
        seq += 1
        payload = generate_payload(size_kb, seq=seq)
        try:
            resp = requests.post(
                GATEWAY_URL,
                json={"sensor_data": payload, "mode": mode},
                timeout=5
            )
            if resp.status_code == 200:
                count += 1
            else:
                errors += 1
        except Exception:
            errors += 1

    tp = round(count / duration_sec, 2)
    print(f"  {tp} pesan/detik (ok={count}, err={errors})")
    return {
        "mode": mode, "size_kb": size_kb,
        "throughput_msg_per_sec": tp,
        "total_success": count,
        "total_error":   errors,
        "duration_sec":  duration_sec
    }


# def save_csv(results, filename):
#     results = [r for r in results if r is not None]
#     if not results:
#         return
#     with open(filename, "w", newline="") as f:
#         writer = csv.DictWriter(f, fieldnames=results[0].keys())
#         writer.writeheader()
#         writer.writerows(results)
#     print(f"  Tersimpan: {filename}")


# =====================================================
# CSV NAME
# =====================================================
def get_next_filename(base_name):

    i = 1
    while True:
        filename = f"{base_name}_{i}.csv"
        if not os.path.exists(filename):
            return filename
        i += 1

# =====================================================
# SAVE CSV
# =====================================================
def save_csv(results, base_name):

    filename = get_next_filename(base_name)

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f,fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"[OK] Saved: {filename}")


if __name__ == "__main__":
    print("=" * 60)
    print("  EKSPERIMEN KINERJA END-TO-END")
    print("  Enc Time + Trans Time + Dec Time + Total")
    print("=" * 60)

    if not check_connections():
        print("\nJalankan server dan gateway terlebih dahulu!")
        exit(1)

    SIZES  = [1, 10, 100]
    MODES  = ["RSA", "ECC"]
    N_RUNS = 30

    print(f"\nKonfigurasi: {N_RUNS} runs | {SIZES}KB | {MODES}\n")

    # all_rows: kumpulan semua baris raw per-run (target 6x30 = 180 baris)
    all_rows           = []
    throughput_results = []

    print("=" * 60)
    print("  BAGIAN 1: ENC + TRANS + DEC + RTT TIME (PER RUN)")
    print("  Target: 6 kombinasi x 30 runs = 180 baris CSV")
    print("=" * 60)
    for mode in MODES:
        warmup(mode, n_warmup=7)
        for size in SIZES:
            rows = measure_e2e(mode, size, n_runs=N_RUNS)
            all_rows.extend(rows)   # setiap run = 1 baris

    print(f"  Total baris terkumpul: {len(all_rows)} baris")
    print("\n" + "=" * 60)
    print("  BAGIAN 2: THROUGHPUT")
    print("=" * 60)
    for mode in MODES:
        for size in SIZES:
            r = measure_throughput(mode, size, duration_sec=10)
            throughput_results.append(r)

    print("\n" + "=" * 60)
    # CSV raw per-run: 180 baris (6 kombinasi x 30 runs)
    # Kolom CSV: run, mode, size_kb, enc_ms, dec_ms, net_ms, e2e_ms, payload_size_bytes
    save_csv(all_rows,           "experiment_raw")
    save_csv(throughput_results, "throughput_results")
    print("\nSemua eksperimen selesai!")
    print(f"  experiment_raw_N.csv      : {len(all_rows)} baris (per-run detail)")
    print(f"  throughput_results_N.csv  : {len(throughput_results)} baris (per kombinasi)")