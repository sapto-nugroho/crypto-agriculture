import time
import json
import os
import re
import statistics
import csv
import requests
from datetime import datetime

GATEWAY_URL = "http://localhost:5001/receive"
SERVER_URL  = "http://localhost:5002"


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
    Ukur 3 komponen waktu + total:
      enc_ms   : waktu enkripsi di gateway
      trans_ms : waktu transmisi gateway → server (termasuk I/O)
      dec_ms   : waktu dekripsi di server
      total_ms : enc + trans + dec
    """
    # print(f"\n[{mode} | {size_kb}KB] Warmup dulu...")
    # warmup(mode, n_warmup=5)
    print(f"[{mode} | {size_kb}KB] Mulai {n_runs} runs...")

    enc_times   = []
    trans_times = []
    dec_times   = []
    total_times = []
    ct_sizes    = []

    storage_before = len(os.listdir("server_storage")) \
                     if os.path.exists("server_storage") else 0

    for i in range(n_runs):
        payload = generate_payload(size_kb, seq=i + 1)

        try:
            response = requests.post(
                GATEWAY_URL,
                json={"sensor_data": payload, "mode": mode},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                enc_ms   = data.get("enc_ms",   0)
                trans_ms = data.get("trans_ms", 0)
                dec_ms   = data.get("dec_ms",   0)
                total_ms = data.get("total_ms", enc_ms + trans_ms + dec_ms)

                enc_times.append(enc_ms)
                trans_times.append(trans_ms)
                dec_times.append(dec_ms)
                total_times.append(total_ms)
            else:
                print(f"  [WARN] Run {i+1}: {response.status_code}")

        except Exception as e:
            print(f"  [ERROR] Run {i+1}: {e}")
            continue

        # Tidak ada sleep di sini!

        if (i + 1) % 10 == 0:
            print(f"  [{mode} | {size_kb}KB] Run {i+1}/{n_runs} selesai")

    # Ukuran ciphertext dari file server_storage
    if os.path.exists("server_storage"):
        all_files = sorted(os.listdir("server_storage"))
        new_files = all_files[storage_before:]
        for fname in new_files[:n_runs]:
            fpath = os.path.join("server_storage", fname)
            ct_sizes.append(os.path.getsize(fpath))

    if not enc_times:
        print(f"  [ERROR] Tidak ada data valid.")
        return None

    def stats(vals):
        if not vals:
            return {"mean": 0, "stdev": 0}
        return {
            "mean":  round(statistics.mean(vals), 4),
            "stdev": round(statistics.stdev(vals)
                           if len(vals) > 1 else 0, 4)
        }

    enc_s   = stats(enc_times)
    trans_s = stats(trans_times)
    dec_s   = stats(dec_times)
    total_s = stats(total_times)
    ct_s    = stats(ct_sizes)

    result = {
        "mode":               mode,
        "size_kb":            size_kb,
        "n_runs":             len(enc_times),
        # Waktu enkripsi
        "enc_mean_ms":        enc_s["mean"],
        "enc_stdev_ms":       enc_s["stdev"],
        # Waktu transmisi
        "trans_mean_ms":      trans_s["mean"],
        "trans_stdev_ms":     trans_s["stdev"],
        # Waktu dekripsi
        "dec_mean_ms":        dec_s["mean"],
        "dec_stdev_ms":       dec_s["stdev"],
        # Waktu total
        "total_mean_ms":      total_s["mean"],
        "total_stdev_ms":     total_s["stdev"],
        # Ukuran ciphertext
        "ct_size_mean_bytes": ct_s["mean"],
        "ct_size_stdev_bytes":ct_s["stdev"],
    }

    print(f"  Enkripsi  : {result['enc_mean_ms']} ± "
          f"{result['enc_stdev_ms']} ms")
    print(f"  Transmisi : {result['trans_mean_ms']} ± "
          f"{result['trans_stdev_ms']} ms")
    print(f"  Dekripsi  : {result['dec_mean_ms']} ± "
          f"{result['dec_stdev_ms']} ms")
    print(f"  Total     : {result['total_mean_ms']} ± "
          f"{result['total_stdev_ms']} ms")
    print(f"  CT Size   : {result['ct_size_mean_bytes']} ± "
          f"{result['ct_size_stdev_bytes']} bytes")
    return result


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

    perf_results       = []
    throughput_results = []

    print("=" * 60)
    print("  BAGIAN 1: ENC + TRANS + DEC TIME")
    print("=" * 60)
    for mode in MODES:
        warmup(mode, n_warmup=7)
        for size in SIZES:
            r = measure_e2e(mode, size, n_runs=N_RUNS)
            perf_results.append(r)

    print("\n" + "=" * 60)
    print("  BAGIAN 2: THROUGHPUT")
    print("=" * 60)
    for mode in MODES:
        for size in SIZES:
            r = measure_throughput(mode, size, duration_sec=10)
            throughput_results.append(r)

    print("\n" + "=" * 60)
    save_csv(perf_results, "experiment_results")
    save_csv(throughput_results, "throughput_results")
    print("\nSemua eksperimen selesai!")