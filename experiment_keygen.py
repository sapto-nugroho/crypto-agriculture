# experiment_keygen.py
# Eksperimen: Pengukuran Waktu Pembangkitan Kunci (Key Generation)
# Mengukur waktu setiap tahap key preparation RSA dan ECC di gateway.
#
# REQUIREMENT:
#   - Server harus aktif (gateway butuh public key dari server)
#   - Gateway harus aktif
#   - Sensor TIDAK perlu aktif
#
# Jalankan: python experiment_keygen.py

import requests
import statistics
import csv
import os
import time
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

GATEWAY_URL = "http://127.0.0.1:5001"
SERVER_URL  = "http://127.0.0.1:5002"
N_RUNS      = 30
N_WARMUP    = 5


# ══════════════════════════════════════════════════════════════════
# CEK KONEKSI
# ══════════════════════════════════════════════════════════════════

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
        requests.get(f"{GATEWAY_URL}/stats", timeout=3)
        print("  ✓ Gateway aktif")
    except Exception:
        print("  ✗ Gateway TIDAK aktif!")
        ok = False
    return ok


# ══════════════════════════════════════════════════════════════════
# WARMUP
# ══════════════════════════════════════════════════════════════════

def warmup(mode, n=N_WARMUP):
    print(f"\n[WARMUP] {n} request untuk {mode}...")
    for _ in range(n):
        try:
            requests.post(
                f"{GATEWAY_URL}/experiment/keygen",
                json={"mode": mode},
                timeout=10
            )
        except Exception:
            pass
    print(f"  [WARMUP] Selesai.")


# ══════════════════════════════════════════════════════════════════
# PENGUKURAN
# ══════════════════════════════════════════════════════════════════

def measure_keygen(mode, n_runs=N_RUNS):
    print(f"\n[{mode}] Menjalankan {n_runs} iterasi...")
    rows = []

    for i in range(n_runs):
        try:
            resp = requests.post(
                f"{GATEWAY_URL}/experiment/keygen",
                json={"mode": mode},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                row  = {"run": i + 1, "mode": mode, **data}
                rows.append(row)

                if mode == "RSA":
                    print(f"  run {i+1:02d} | "
                          f"session_key_gen={data['session_key_gen_ms']}ms | "
                          f"load_pubkey={data['load_pubkey_ms']}ms | "
                          f"rsa_oaep={data['rsa_oaep_encrypt_ms']}ms | "
                          f"total={data['total_key_prep_ms']}ms")
                else:
                    print(f"  run {i+1:02d} | "
                          f"ephemeral_gen={data['ephemeral_key_gen_ms']}ms | "
                          f"load_pubkey={data['load_pubkey_ms']}ms | "
                          f"ecdh={data['ecdh_ms']}ms | "
                          f"hkdf={data['hkdf_ms']}ms | "
                          f"total={data['total_key_prep_ms']}ms")
            else:
                print(f"  [WARN] Run {i+1}: status {resp.status_code}")
        except Exception as e:
            print(f"  [ERROR] Run {i+1}: {e}")

    print(f"  Total valid: {len(rows)}/{n_runs} runs")
    return rows


# ══════════════════════════════════════════════════════════════════
# SIMPAN CSV — raw + ringkasan dalam 1 file
# ══════════════════════════════════════════════════════════════════

def get_next_filename(base, ext="csv"):
    i = 1
    while True:
        fname = f"{base}_{i}.{ext}"
        if not os.path.exists(fname):
            return fname
        i += 1


def save_csv(rsa_rows, ecc_rows):
    fname = get_next_filename("keygen_raw", "csv")

    # Kolom RSA dan ECC berbeda, satukan dengan nilai kosong jika tidak ada
    all_cols = [
        "run", "mode",
        "session_key_gen_ms",   # RSA only
        "ephemeral_key_gen_ms", # ECC only
        "load_pubkey_ms",
        "rsa_oaep_encrypt_ms",  # RSA only
        "ecdh_ms",              # ECC only
        "hkdf_ms",              # ECC only
        "total_key_prep_ms"
    ]

    with open(fname, "w", newline="") as f:
        writer = csv.writer(f)

        # ── Header raw data ──
        writer.writerow(["# RAW DATA (n=30 per mode)"])
        writer.writerow(all_cols)

        # ── Baris RSA ──
        for r in rsa_rows:
            writer.writerow([
                r["run"], r["mode"],
                r.get("session_key_gen_ms", ""),
                r.get("ephemeral_key_gen_ms", ""),
                r.get("load_pubkey_ms", ""),
                r.get("rsa_oaep_encrypt_ms", ""),
                r.get("ecdh_ms", ""),
                r.get("hkdf_ms", ""),
                r.get("total_key_prep_ms", ""),
            ])

        # ── Baris ECC ──
        for r in ecc_rows:
            writer.writerow([
                r["run"], r["mode"],
                r.get("session_key_gen_ms", ""),
                r.get("ephemeral_key_gen_ms", ""),
                r.get("load_pubkey_ms", ""),
                r.get("rsa_oaep_encrypt_ms", ""),
                r.get("ecdh_ms", ""),
                r.get("hkdf_ms", ""),
                r.get("total_key_prep_ms", ""),
            ])

        # ── Baris kosong pemisah ──
        writer.writerow([])
        writer.writerow([])

        # ── Header ringkasan ──
        writer.writerow(["# RINGKASAN STATISTIK (mean ± std_dev, n=30)"])
        writer.writerow(["section", "mode", "metric", "mean_ms", "std_dev_ms", "n"])

        # Metrik RSA
        rsa_metrics = [
            ("session_key_gen_ms",  "Session key gen (os.urandom)"),
            ("load_pubkey_ms",      "Load public key"),
            ("rsa_oaep_encrypt_ms", "RSA-OAEP encrypt session key"),
            ("total_key_prep_ms",   "TOTAL key preparation"),
        ]
        for key, label in rsa_metrics:
            vals = [r[key] for r in rsa_rows if key in r]
            if vals:
                writer.writerow([
                    "summary", "RSA-2048", label,
                    round(statistics.mean(vals), 4),
                    round(statistics.stdev(vals), 4),
                    len(vals)
                ])

        # Metrik ECC
        ecc_metrics = [
            ("ephemeral_key_gen_ms", "Ephemeral key gen (X25519)"),
            ("load_pubkey_ms",       "Load public key"),
            ("ecdh_ms",              "ECDH (X25519 exchange)"),
            ("hkdf_ms",              "HKDF-SHA256 derive"),
            ("total_key_prep_ms",    "TOTAL key preparation"),
        ]
        for key, label in ecc_metrics:
            vals = [r[key] for r in ecc_rows if key in r]
            if vals:
                writer.writerow([
                    "summary", "ECC X25519", label,
                    round(statistics.mean(vals), 4),
                    round(statistics.stdev(vals), 4),
                    len(vals)
                ])

    print(f"[OK] CSV tersimpan: {fname}")
    return fname


# ══════════════════════════════════════════════════════════════════
# LAPORAN STATISTIK DI TERMINAL
# ══════════════════════════════════════════════════════════════════

def print_report(rsa_rows, ecc_rows):
    print("\n" + "=" * 62)
    print("  LAPORAN WAKTU PEMBANGKITAN KUNCI")
    print(f"  (n={N_RUNS}, mean ± standar deviasi, satuan ms)")
    print("=" * 62)

    def stat(rows, key):
        vals = [r[key] for r in rows if key in r]
        if not vals:
            return "-", "-"
        return round(statistics.mean(vals), 4), round(statistics.stdev(vals), 4)

    print("\n┌─ RSA-2048 ─────────────────────────────────────────────┐")
    m, s = stat(rsa_rows, "session_key_gen_ms")
    print(f"  Session key gen (os.urandom)  : {m} ± {s} ms")
    m, s = stat(rsa_rows, "load_pubkey_ms")
    print(f"  Load public key               : {m} ± {s} ms")
    m, s = stat(rsa_rows, "rsa_oaep_encrypt_ms")
    print(f"  RSA-OAEP encrypt session key  : {m} ± {s} ms")
    m, s = stat(rsa_rows, "total_key_prep_ms")
    print(f"  ── TOTAL key preparation      : {m} ± {s} ms")
    print("└────────────────────────────────────────────────────────┘")

    print("\n┌─ ECC X25519 ───────────────────────────────────────────┐")
    m, s = stat(ecc_rows, "ephemeral_key_gen_ms")
    print(f"  Ephemeral key gen (X25519)    : {m} ± {s} ms")
    m, s = stat(ecc_rows, "load_pubkey_ms")
    print(f"  Load public key               : {m} ± {s} ms")
    m, s = stat(ecc_rows, "ecdh_ms")
    print(f"  ECDH (X25519 exchange)        : {m} ± {s} ms")
    m, s = stat(ecc_rows, "hkdf_ms")
    print(f"  HKDF-SHA256 derive            : {m} ± {s} ms")
    m, s = stat(ecc_rows, "total_key_prep_ms")
    print(f"  ── TOTAL key preparation      : {m} ± {s} ms")
    print("└────────────────────────────────────────────────────────┘")


# ══════════════════════════════════════════════════════════════════
# PLOT 1: LINE PLOT PER RUN
# ══════════════════════════════════════════════════════════════════

def plot_lineplot(rsa_rows, ecc_rows):
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Waktu Key Preparation per Run (n=30)", fontsize=13, fontweight="bold")

    runs = list(range(1, N_RUNS + 1))

    # ── RSA ──
    ax = axes[0]
    rsa_session = [r["session_key_gen_ms"]  for r in rsa_rows]
    rsa_load    = [r["load_pubkey_ms"]      for r in rsa_rows]
    rsa_oaep    = [r["rsa_oaep_encrypt_ms"] for r in rsa_rows]
    rsa_total   = [r["total_key_prep_ms"]   for r in rsa_rows]

    ax.plot(runs, rsa_session, label="Session key gen",  color="#4C9BE8", linewidth=1.2, alpha=0.8)
    ax.plot(runs, rsa_load,    label="Load public key",  color="#F4A261", linewidth=1.2, alpha=0.8)
    ax.plot(runs, rsa_oaep,    label="RSA-OAEP encrypt", color="#E76F51", linewidth=1.2, alpha=0.8)
    ax.plot(runs, rsa_total,   label="Total",            color="#2D3047", linewidth=1.8, linestyle="--")
    ax.axhline(statistics.mean(rsa_total), color="#2D3047", linewidth=1,
               linestyle=":", alpha=0.6, label=f"Mean ({round(statistics.mean(rsa_total),2)} ms)")
    ax.set_title("RSA-2048", fontsize=11, fontweight="bold")
    ax.set_xlabel("Run ke-")
    ax.set_ylabel("Waktu (ms)")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_locator(ticker.MultipleLocator(5))

    # ── ECC ──
    ax = axes[1]
    ecc_ephem = [r["ephemeral_key_gen_ms"] for r in ecc_rows]
    ecc_load  = [r["load_pubkey_ms"]       for r in ecc_rows]
    ecc_ecdh  = [r["ecdh_ms"]              for r in ecc_rows]
    ecc_hkdf  = [r["hkdf_ms"]             for r in ecc_rows]
    ecc_total = [r["total_key_prep_ms"]    for r in ecc_rows]

    ax.plot(runs, ecc_ephem, label="Ephemeral key gen", color="#4C9BE8", linewidth=1.2, alpha=0.8)
    ax.plot(runs, ecc_load,  label="Load public key",   color="#F4A261", linewidth=1.2, alpha=0.8)
    ax.plot(runs, ecc_ecdh,  label="ECDH exchange",     color="#E76F51", linewidth=1.2, alpha=0.8)
    ax.plot(runs, ecc_hkdf,  label="HKDF derive",       color="#57CC99", linewidth=1.2, alpha=0.8)
    ax.plot(runs, ecc_total, label="Total",             color="#2D3047", linewidth=1.8, linestyle="--")
    ax.axhline(statistics.mean(ecc_total), color="#2D3047", linewidth=1,
               linestyle=":", alpha=0.6, label=f"Mean ({round(statistics.mean(ecc_total),2)} ms)")
    ax.set_title("ECC X25519", fontsize=11, fontweight="bold")
    ax.set_xlabel("Run ke-")
    ax.set_ylabel("Waktu (ms)")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_locator(ticker.MultipleLocator(5))

    plt.tight_layout()
    fname = get_next_filename("keygen_lineplot", "png")
    plt.savefig(fname, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Line plot tersimpan: {fname}")
    return fname


# ══════════════════════════════════════════════════════════════════
# PLOT 2: BAR CHART MEAN ± SD PER MODE
# ══════════════════════════════════════════════════════════════════

def plot_barchart(rsa_rows, ecc_rows):
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Waktu Key Preparation — Mean ± Standar Deviasi (n=30)",
                 fontsize=13, fontweight="bold")

    def ms(rows, key):
        vals = [r[key] for r in rows if key in r]
        return statistics.mean(vals), statistics.stdev(vals)

    # ── RSA ──
    ax = axes[0]
    labels = ["Session key gen\n(os.urandom)", "Load public key", "RSA-OAEP\nencrypt", "Total"]
    keys   = ["session_key_gen_ms", "load_pubkey_ms", "rsa_oaep_encrypt_ms", "total_key_prep_ms"]
    colors = ["#4C9BE8", "#F4A261", "#E76F51", "#2D3047"]
    means = []; stds = []
    for k in keys:
        m, s = ms(rsa_rows, k)
        means.append(m); stds.append(s)
    bars = ax.bar(labels, means, yerr=stds, capsize=5,
                  color=colors, alpha=0.85, edgecolor="white",
                  error_kw={"elinewidth": 1.5, "ecolor": "gray"})
    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + std + max(means) * 0.02,
                f"{mean:.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_title("RSA-2048", fontsize=11, fontweight="bold")
    ax.set_ylabel("Waktu (ms)")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    # ── ECC ──
    ax = axes[1]
    labels = ["Ephemeral\nkey gen", "Load public key", "ECDH\nexchange", "HKDF\nderive", "Total"]
    keys   = ["ephemeral_key_gen_ms", "load_pubkey_ms", "ecdh_ms", "hkdf_ms", "total_key_prep_ms"]
    colors = ["#4C9BE8", "#F4A261", "#E76F51", "#57CC99", "#2D3047"]
    means = []; stds = []
    for k in keys:
        m, s = ms(ecc_rows, k)
        means.append(m); stds.append(s)
    bars = ax.bar(labels, means, yerr=stds, capsize=5,
                  color=colors, alpha=0.85, edgecolor="white",
                  error_kw={"elinewidth": 1.5, "ecolor": "gray"})
    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + std + max(means) * 0.02,
                f"{mean:.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_title("ECC X25519", fontsize=11, fontweight="bold")
    ax.set_ylabel("Waktu (ms)")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    plt.tight_layout()
    fname = get_next_filename("keygen_barchart", "png")
    plt.savefig(fname, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Bar chart tersimpan: {fname}")
    return fname


# ══════════════════════════════════════════════════════════════════
# PLOT 3: DIAGRAM PERBANDINGAN RSA vs ECC (TOTAL)
# ══════════════════════════════════════════════════════════════════

def plot_comparison(rsa_rows, ecc_rows):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Perbandingan Total Key Preparation: RSA-2048 vs ECC X25519 (n=30)",
                 fontsize=13, fontweight="bold")

    rsa_total = [r["total_key_prep_ms"] for r in rsa_rows]
    ecc_total = [r["total_key_prep_ms"] for r in ecc_rows]
    runs      = list(range(1, N_RUNS + 1))

    # ── Subplot kiri: line plot perbandingan ──
    ax = axes[0]
    ax.plot(runs, rsa_total, label=f"RSA-2048 (mean={round(statistics.mean(rsa_total),2)} ms)",
            color="#E76F51", linewidth=1.5, marker="o", markersize=3)
    ax.plot(runs, ecc_total, label=f"ECC X25519 (mean={round(statistics.mean(ecc_total),2)} ms)",
            color="#4C9BE8", linewidth=1.5, marker="s", markersize=3)
    ax.axhline(statistics.mean(rsa_total), color="#E76F51", linewidth=1, linestyle=":", alpha=0.6)
    ax.axhline(statistics.mean(ecc_total), color="#4C9BE8", linewidth=1, linestyle=":", alpha=0.6)
    ax.set_title("Total per Run", fontsize=11, fontweight="bold")
    ax.set_xlabel("Run ke-")
    ax.set_ylabel("Waktu (ms)")
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_locator(ticker.MultipleLocator(5))

    # ── Subplot kanan: bar chart perbandingan mean ± SD ──
    ax = axes[1]
    modes  = ["RSA-2048", "ECC X25519"]
    means  = [statistics.mean(rsa_total), statistics.mean(ecc_total)]
    stds   = [statistics.stdev(rsa_total), statistics.stdev(ecc_total)]
    colors = ["#E76F51", "#4C9BE8"]

    bars = ax.bar(modes, means, yerr=stds, capsize=8,
                  color=colors, alpha=0.85, edgecolor="white", width=0.5,
                  error_kw={"elinewidth": 2, "ecolor": "gray"})

    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + std + max(means) * 0.02,
                f"{mean:.3f} ± {std:.3f} ms",
                ha="center", va="bottom", fontsize=9, fontweight="bold")

    # Tambahkan label berapa kali lebih cepat
    if means[1] > 0:
        ratio = round(means[0] / means[1], 2)
        ax.text(0.5, max(means) * 0.5,
                f"RSA {ratio}× lebih lambat\ndari ECC",
                ha="center", va="center", fontsize=10,
                color="#2D3047", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="lightyellow",
                          edgecolor="gray", alpha=0.8))

    ax.set_title("Mean ± Standar Deviasi", fontsize=11, fontweight="bold")
    ax.set_ylabel("Waktu (ms)")
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    plt.tight_layout()
    fname = get_next_filename("keygen_comparison", "png")
    plt.savefig(fname, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Diagram perbandingan tersimpan: {fname}")
    return fname


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 62)
    print("  EKSPERIMEN WAKTU PEMBANGKITAN KUNCI")
    print("  RSA-2048 vs ECC X25519")
    print(f"  n={N_RUNS} runs per mode")
    print("=" * 62)

    if not check_connections():
        print("\nJalankan server dan gateway terlebih dahulu!")
        print("Sensor TIDAK perlu aktif.")
        exit(1)

    # Warmup
    warmup("RSA")
    warmup("ECC")

    # Pengukuran
    print("\n" + "=" * 62)
    print("  PENGUKURAN RSA")
    print("=" * 62)
    rsa_rows = measure_keygen("RSA")

    print("\n" + "=" * 62)
    print("  PENGUKURAN ECC")
    print("=" * 62)
    ecc_rows = measure_keygen("ECC")

    # Laporan terminal
    print_report(rsa_rows, ecc_rows)

    # Simpan CSV (raw + ringkasan dalam 1 file)
    print("\n" + "=" * 62)
    print("  MENYIMPAN HASIL")
    print("=" * 62)
    save_csv(rsa_rows, ecc_rows)

    # Plot grafik
    plot_lineplot(rsa_rows, ecc_rows)
    plot_barchart(rsa_rows, ecc_rows)
    plot_comparison(rsa_rows, ecc_rows)

    print("\n" + "=" * 62)
    print("  EKSPERIMEN SELESAI")
    print("  File output:")
    print("    keygen_raw_N.csv          — raw data + ringkasan mean/SD")
    print("    keygen_lineplot_N.png     — line plot per run (RSA & ECC)")
    print("    keygen_barchart_N.png     — bar chart mean ± SD per tahap")
    print("    keygen_comparison_N.png   — perbandingan RSA vs ECC")
    print("=" * 62)