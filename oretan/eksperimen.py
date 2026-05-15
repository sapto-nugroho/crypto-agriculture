# eksperimen.py
# Eksperimen kinerja dan availability
# Jalankan: python eksperimen.py

import json
import os
import time
import statistics
import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# Import modul kriptografi
from aes import encrypt, decrypt
from rsa import encrypt_session_key, decrypt_session_key, private_key, public_key
from ecc import derive_session_key, public_key_to_bytes, public_key_from_bytes, server_private_key, server_public_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.exceptions import InvalidTag

# Import sensor dan server
from sensor import dataset
from server import Server

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "hasil_eksperimen")
os.makedirs(RESULTS_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# FUNGSI ENKRIPSI (sama seperti di gateway)
# ─────────────────────────────────────────────────────────────

def encrypt_rsa(data_json):
    session_key = os.urandom(32)
    encrypted_sk = encrypt_session_key(public_key, session_key)
    aes_result = encrypt(session_key, data_json.encode())
    d = json.loads(data_json)
    return {
        "mode": "RSA",
        "algorithm": "RSA-OAEP-SHA256-AES-256-GCM",
        "sensor_id": d.get("sensor_id"),
        "timestamp": d.get("timestamp"),
        "sequence_number": d.get("sequence_number"),
        "encrypted_session_key": encrypted_sk,
        "nonce": aes_result["nonce"],
        "ciphertext": aes_result["ciphertext"],
        "tag": aes_result["tag"]
    }

def encrypt_ecc(data_json):
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    session_key = derive_session_key(ephemeral_private, server_public_key)
    ephem_pub_hex = public_key_to_bytes(ephemeral_public).hex()
    aes_result = encrypt(session_key, data_json.encode())
    d = json.loads(data_json)
    return {
        "mode": "ECC",
        "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
        "sensor_id": d.get("sensor_id"),
        "timestamp": d.get("timestamp"),
        "sequence_number": d.get("sequence_number"),
        "ephemeral_public_key": ephem_pub_hex,
        "nonce": aes_result["nonce"],
        "ciphertext": aes_result["ciphertext"],
        "tag": aes_result["tag"]
    }

# ─────────────────────────────────────────────────────────────
# GENERATE PAYLOAD UKURAN TERTENTU
# ─────────────────────────────────────────────────────────────

def generate_payload(size_kb, seq=1):
    import random
    base = {
        "sensor_id": "FIELD-01-SENSOR-01",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "temperature": round(random.uniform(25.0, 38.0), 1),
        "air_humidity": round(random.uniform(50.0, 90.0), 1),
        "soil_moisture": round(random.uniform(20.0, 60.0), 1),
        "soil_ph": round(random.uniform(5.5, 7.5), 1),
        "sequence_number": seq
    }
    target_bytes = size_kb * 1024
    current = len(json.dumps(base).encode())
    if target_bytes > current:
        base["dummy"] = "x" * (target_bytes - current)
    return base

# ─────────────────────────────────────────────────────────────
# EKSPERIMEN KINERJA (30 runs per skenario)
# ─────────────────────────────────────────────────────────────

def run_benchmark(mode, size_kb, n_runs=30):
    print(f"  [{mode} | {size_kb}KB] Benchmark {n_runs} runs...")

    enc_times = []
    dec_times = []
    ct_sizes  = []

    server = Server()

    for i in range(n_runs):
        data_json = json.dumps(generate_payload(size_kb, i+1))

        # Enkripsi
        t_start = time.perf_counter()
        if mode == "RSA":
            packet = encrypt_rsa(data_json)
        else:
            packet = encrypt_ecc(data_json)
        enc_times.append((time.perf_counter() - t_start) * 1000)

        # Ukuran ciphertext
        ct_sizes.append(len(json.dumps(packet).encode()))

        # Dekripsi
        t_start = time.perf_counter()
        server.decrypt_packet(packet)
        dec_times.append((time.perf_counter() - t_start) * 1000)

    result = {
        "mode": mode,
        "size_kb": size_kb,
        "enc_mean_ms": round(statistics.mean(enc_times), 4),
        "enc_std_ms":  round(statistics.stdev(enc_times), 4),
        "dec_mean_ms": round(statistics.mean(dec_times), 4),
        "dec_std_ms":  round(statistics.stdev(dec_times), 4),
        "ct_mean_bytes": round(statistics.mean(ct_sizes)),
        "ct_std_bytes":  round(statistics.stdev(ct_sizes), 2)
    }

    print(f"    Enkripsi : {result['enc_mean_ms']} ± {result['enc_std_ms']} ms")
    print(f"    Dekripsi : {result['dec_mean_ms']} ± {result['dec_std_ms']} ms")
    print(f"    CT Size  : {result['ct_mean_bytes']} bytes")
    return result

# ─────────────────────────────────────────────────────────────
# EKSPERIMEN THROUGHPUT
# ─────────────────────────────────────────────────────────────

def run_throughput(mode, size_kb=1, n=50):
    print(f"  [Throughput {mode} | {size_kb}KB] {n} pesan...")
    data_json = json.dumps(generate_payload(size_kb))

    t_start = time.perf_counter()
    for _ in range(n):
        if mode == "RSA":
            encrypt_rsa(data_json)
        else:
            encrypt_ecc(data_json)
    elapsed = time.perf_counter() - t_start

    throughput = round(n / elapsed, 2)
    print(f"    Throughput: {throughput} pesan/detik")
    return {"mode": mode, "size_kb": size_kb, "n_messages": n, "throughput_msg_per_sec": throughput}

# ─────────────────────────────────────────────────────────────
# EKSPERIMEN AVAILABILITY (LOCAL BUFFERING)
# Skenario: 30 data online → 30 data offline (buffer) → server hidup → kirim ulang
# ─────────────────────────────────────────────────────────────

def run_availability():
    print("\n" + "=" * 55)
    print("  EKSPERIMEN AVAILABILITY — LOCAL BUFFERING")
    print("=" * 55)

    buffer_dir = os.path.join(BASE_DIR, "gateway_buffer_avail")
    os.makedirs(buffer_dir, exist_ok=True)

    # Bersihkan buffer lama
    for f in os.listdir(buffer_dir):
        os.remove(os.path.join(buffer_dir, f))

    server = Server()
    avail_rows = []
    stats = {"sent": 0, "buffered": 0, "lost": 0, "recovery_time_ms": 0}
    seq = 0

    # FASE 1: Server online, 30 data langsung terkirim
    print("\nFase 1: Server ONLINE — kirim 30 data")
    server.is_online = True
    for _ in range(30):
        seq += 1
        packet = encrypt_ecc(json.dumps(generate_payload(1, seq)))
        server.receive(packet)
        stats["sent"] += 1
        avail_rows.append({
            "sequence_number": seq,
            "phase": "ONLINE",
            "status": "sent_directly",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    print(f"  Data terkirim langsung: {stats['sent']}")

    # FASE 2: Server mati, 30 data ke buffer lokal
    print("\nFase 2: Server OFFLINE — 30 data ke buffer lokal")
    server.is_online = False
    for _ in range(30):
        seq += 1
        packet = encrypt_ecc(json.dumps(generate_payload(1, seq)))
        fname = os.path.join(buffer_dir, f"pkt_{seq:04d}.json")
        with open(fname, "w") as f:
            json.dump(packet, f)
        stats["buffered"] += 1
        avail_rows.append({
            "sequence_number": seq,
            "phase": "OFFLINE",
            "status": "buffered_locally",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    buf_count = len(os.listdir(buffer_dir))
    print(f"  Buffer lokal: {buf_count} paket (hanya ciphertext)")

    # FASE 3: Server hidup kembali, kirim ulang buffer
    print("\nFase 3: Server ONLINE kembali — kirim ulang buffer")
    server.is_online = True
    t_rec_start = time.perf_counter()
    files = sorted(os.listdir(buffer_dir))
    for fname in files:
        fpath = os.path.join(buffer_dir, fname)
        with open(fpath, "r") as f:
            packet = json.load(f)
        server.receive(packet)
        stats["sent"] += 1
        stats["buffered"] -= 1
        os.remove(fpath)
        avail_rows.append({
            "sequence_number": packet["sequence_number"],
            "phase": "RECOVERY",
            "status": "sent_after_recovery",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    stats["recovery_time_ms"] = round((time.perf_counter() - t_rec_start) * 1000, 2)

    # FASE 4: Lanjut online
    print("\nFase 4: Lanjut ONLINE — 10 data tambahan")
    for _ in range(10):
        seq += 1
        packet = encrypt_ecc(json.dumps(generate_payload(1, seq)))
        server.receive(packet)
        stats["sent"] += 1
        avail_rows.append({
            "sequence_number": seq,
            "phase": "ONLINE_2",
            "status": "sent_directly",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    total_generated = seq
    print(f"\n{'='*55}")
    print(f"  LAPORAN AVAILABILITY")
    print(f"{'='*55}")
    print(f"  Total data digenerate  : {total_generated}")
    print(f"  Berhasil dikirim       : {stats['sent']}")
    print(f"  Masih di buffer        : {stats['buffered']}")
    print(f"  Data hilang            : {stats['lost']}")
    print(f"  Recovery time          : {stats['recovery_time_ms']} ms")
    print(f"  Target data hilang = 0 : {'TERCAPAI ✓' if stats['lost'] == 0 else 'GAGAL ✗'}")

    summary = {
        "total_generated": total_generated,
        "total_sent": stats["sent"],
        "remaining_in_buffer": stats["buffered"],
        "data_lost": stats["lost"],
        "recovery_time_ms": stats["recovery_time_ms"],
        "target_met": "YES" if stats["lost"] == 0 else "NO"
    }
    return summary, avail_rows

# ─────────────────────────────────────────────────────────────
# SIMPAN CSV
# ─────────────────────────────────────────────────────────────

def save_csv(results, filename):
    results = [r for r in results if r is not None]
    if not results:
        return
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"  CSV disimpan: {filepath}")

# ─────────────────────────────────────────────────────────────
# BUAT GRAFIK
# ─────────────────────────────────────────────────────────────

def plot_results(results):
    sizes = [1, 10, 100]
    labels = ["1 KB", "10 KB", "100 KB"]

    rsa_enc     = [r["enc_mean_ms"]   for r in results if r["mode"] == "RSA"]
    ecc_enc     = [r["enc_mean_ms"]   for r in results if r["mode"] == "ECC"]
    rsa_dec     = [r["dec_mean_ms"]   for r in results if r["mode"] == "RSA"]
    ecc_dec     = [r["dec_mean_ms"]   for r in results if r["mode"] == "ECC"]
    rsa_ct      = [r["ct_mean_bytes"] for r in results if r["mode"] == "RSA"]
    ecc_ct      = [r["ct_mean_bytes"] for r in results if r["mode"] == "ECC"]
    rsa_enc_std = [r["enc_std_ms"]    for r in results if r["mode"] == "RSA"]
    ecc_enc_std = [r["enc_std_ms"]    for r in results if r["mode"] == "ECC"]
    rsa_dec_std = [r["dec_std_ms"]    for r in results if r["mode"] == "RSA"]
    ecc_dec_std = [r["dec_std_ms"]    for r in results if r["mode"] == "ECC"]

    x     = np.arange(len(sizes))
    width = 0.35
    C_RSA = "#185FA5"
    C_ECC = "#A32D2D"

    def annotate_bars(ax, bars, color):
        for bar in bars:
            ax.annotate(f"{bar.get_height():.3f}",
                        xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8, color=color)

    # Grafik 1: Waktu Enkripsi
    fig, ax = plt.subplots(figsize=(8, 5))
    b1 = ax.bar(x - width/2, rsa_enc, width, label="RSA-OAEP", color=C_RSA,
                yerr=rsa_enc_std, capsize=5, error_kw={"ecolor": "#0C447C", "linewidth": 1.5})
    b2 = ax.bar(x + width/2, ecc_enc, width, label="ECC/X25519", color=C_ECC,
                yerr=ecc_enc_std, capsize=5, error_kw={"ecolor": "#791F1F", "linewidth": 1.5})
    annotate_bars(ax, b1, C_RSA)
    annotate_bars(ax, b2, C_ECC)
    ax.set_xlabel("Ukuran Data", fontsize=12, fontweight="bold")
    ax.set_ylabel("Waktu (ms)", fontsize=12, fontweight="bold")
    ax.set_title("Waktu Enkripsi End-to-End: RSA vs ECC\n(n=30 runs, error bar = ±1 SD)", fontsize=13, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=11)
    ax.legend(fontsize=11); ax.grid(axis="y", alpha=0.3, linestyle="--")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "grafik_enkripsi.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("  Grafik enkripsi disimpan")

    # Grafik 2: Waktu Dekripsi
    fig, ax = plt.subplots(figsize=(8, 5))
    b1 = ax.bar(x - width/2, rsa_dec, width, label="RSA-OAEP", color=C_RSA,
                yerr=rsa_dec_std, capsize=5, error_kw={"ecolor": "#0C447C", "linewidth": 1.5})
    b2 = ax.bar(x + width/2, ecc_dec, width, label="ECC/X25519", color=C_ECC,
                yerr=ecc_dec_std, capsize=5, error_kw={"ecolor": "#791F1F", "linewidth": 1.5})
    annotate_bars(ax, b1, C_RSA)
    annotate_bars(ax, b2, C_ECC)
    ax.set_xlabel("Ukuran Data", fontsize=12, fontweight="bold")
    ax.set_ylabel("Waktu (ms)", fontsize=12, fontweight="bold")
    ax.set_title("Waktu Dekripsi End-to-End: RSA vs ECC\n(n=30 runs, error bar = ±1 SD)", fontsize=13, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=11)
    ax.legend(fontsize=11); ax.grid(axis="y", alpha=0.3, linestyle="--")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "grafik_dekripsi.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("  Grafik dekripsi disimpan")

    # Grafik 3: Ukuran Ciphertext
    fig, ax = plt.subplots(figsize=(8, 5))
    b1 = ax.bar(x - width/2, rsa_ct, width, label="RSA-OAEP", color=C_RSA)
    b2 = ax.bar(x + width/2, ecc_ct, width, label="ECC/X25519", color=C_ECC)
    for bar, val in zip(list(b1) + list(b2), rsa_ct + ecc_ct):
        ax.annotate(f"{val:,}", xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=7.5)
    ax.set_xlabel("Ukuran Data", fontsize=12, fontweight="bold")
    ax.set_ylabel("Ukuran (bytes)", fontsize=12, fontweight="bold")
    ax.set_title("Ukuran Total Paket Ciphertext: RSA vs ECC", fontsize=13, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=11)
    ax.legend(fontsize=11); ax.grid(axis="y", alpha=0.3, linestyle="--")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "grafik_ciphertext_size.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("  Grafik ciphertext size disimpan")

    # Grafik 4: Throughput
    tp_rsa = run_throughput("RSA")
    tp_ecc = run_throughput("ECC")
    fig, ax = plt.subplots(figsize=(6, 5))
    bars = ax.bar(["RSA-OAEP", "ECC/X25519"],
                  [tp_rsa["throughput_msg_per_sec"], tp_ecc["throughput_msg_per_sec"]],
                  color=[C_RSA, C_ECC], width=0.45)
    for bar in bars:
        ax.annotate(f"{bar.get_height():,.1f} msg/s",
                    xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                    xytext=(0, 5), textcoords="offset points",
                    ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax.set_xlabel("Mode Enkripsi", fontsize=12, fontweight="bold")
    ax.set_ylabel("Throughput (pesan/detik)", fontsize=12, fontweight="bold")
    ax.set_title("Throughput Enkripsi: RSA vs ECC\n(data 1 KB, n=50 pesan)", fontsize=13, fontweight="bold")
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_ylim(0, max(tp_rsa["throughput_msg_per_sec"], tp_ecc["throughput_msg_per_sec"]) * 1.2)
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "grafik_throughput.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("  Grafik throughput disimpan")

    # Grafik 5: Combined (2 panel)
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, (m_data, std_data), title in zip(
        axes,
        [(rsa_enc, ecc_enc, rsa_enc_std, ecc_enc_std), (rsa_dec, ecc_dec, rsa_dec_std, ecc_dec_std)],
        ["Waktu Enkripsi (ms)", "Waktu Dekripsi (ms)"]
    ):
        rd, ed, rs, es = m_data
        b1 = ax.bar(x - width/2, rd, width, label="RSA-OAEP", color=C_RSA, yerr=rs, capsize=4)
        b2 = ax.bar(x + width/2, ed, width, label="ECC/X25519", color=C_ECC, yerr=es, capsize=4)
        ax.set_title(title, fontsize=12, fontweight="bold")
        ax.set_xticks(x); ax.set_xticklabels(labels)
        ax.legend(fontsize=10); ax.grid(axis="y", alpha=0.3, linestyle="--")
        ax.set_xlabel("Ukuran Data"); ax.set_ylabel("ms")
    fig.suptitle("Perbandingan Kinerja RSA vs ECC (n=30)", fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "grafik_combined.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("  Grafik combined disimpan")

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  EKSPERIMEN KINERJA — SMART AGRICULTURE")
    print("  RSA-OAEP vs ECC/X25519 + AES-256-GCM")
    print("=" * 55)

    SIZES  = [1, 10, 100]
    MODES  = ["RSA", "ECC"]
    N_RUNS = 30

    print(f"\nKonfigurasi: {N_RUNS} runs | Ukuran: {SIZES} KB | Mode: {MODES}")

    # ── BAGIAN 1: ENKRIPSI, DEKRIPSI, UKURAN CIPHERTEXT ──
    print("\n" + "=" * 55)
    print("  BAGIAN 1: ENKRIPSI, DEKRIPSI, UKURAN CIPHERTEXT")
    print("=" * 55)

    results = []
    for mode in MODES:
        for size in SIZES:
            r = run_benchmark(mode, size, n_runs=N_RUNS)
            results.append(r)

    print(f"\n{'Mode':<5} {'KB':>4} {'Enc(ms)':>10} {'±':>8} {'Dec(ms)':>10} {'±':>8} {'CT(bytes)':>10}")
    print("-" * 60)
    for r in results:
        print(f"{r['mode']:<5} {r['size_kb']:>4} "
              f"{r['enc_mean_ms']:>10.4f} {r['enc_std_ms']:>8.4f} "
              f"{r['dec_mean_ms']:>10.4f} {r['dec_std_ms']:>8.4f} "
              f"{r['ct_mean_bytes']:>10,}")

    # ── BAGIAN 2: THROUGHPUT ──
    print("\n" + "=" * 55)
    print("  BAGIAN 2: THROUGHPUT")
    print("=" * 55)
    throughput_results = []
    for mode in MODES:
        r = run_throughput(mode)
        throughput_results.append(r)

    # ── BAGIAN 3: AVAILABILITY ──
    print("\n" + "=" * 55)
    print("  BAGIAN 3: AVAILABILITY")
    print("=" * 55)
    avail_summary, avail_rows = run_availability()

    # ── SIMPAN CSV ──
    print("\n" + "=" * 55)
    print("  SIMPAN HASIL")
    print("=" * 55)
    save_csv(results, "hasil_kinerja.csv")
    save_csv(throughput_results, "hasil_throughput.csv")
    save_csv([avail_summary], "hasil_availability_summary.csv")
    save_csv(avail_rows, "hasil_availability_detail.csv")

    # ── BUAT GRAFIK ──
    print("\nMembuat grafik...")
    plot_results(results)

    print("\n" + "=" * 55)
    print("  SEMUA EKSPERIMEN SELESAI!")
    print(f"  Hasil ada di folder: {RESULTS_DIR}/")
    print("=" * 55)