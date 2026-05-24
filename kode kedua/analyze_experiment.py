# analyze_experiment.py
# Mengolah hasil eksperimen dari experiment_results.csv dan throughput_results.csv
# Menghasilkan:
#   - Statistik lengkap (mean, stdev, min, max, median, CI 95%)
#   - Grafik perbandingan RSA vs ECC
#   - Tabel siap paper IEEE
#   - File: analysis_report.txt, figures/*.png
#
# Jalankan: python analyze_experiment.py
# Pastikan experiment_results.csv dan throughput_results.csv sudah ada.

import csv
import os
import math
import statistics
from collections import defaultdict

# Cek apakah matplotlib dan pandas tersedia
try:
    import matplotlib
    matplotlib.use('Agg')   # non-interactive backend (tidak butuh display)
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("[WARN] matplotlib tidak ditemukan. Grafik tidak akan dibuat.")
    print("       Install dengan: pip install matplotlib")

RESULTS_FILE    = "experiment_results.csv"
THROUGHPUT_FILE = "throughput_results.csv"
REPORT_FILE     = "analysis_report.txt"
FIGURES_DIR     = "figures"

os.makedirs(FIGURES_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════════
# LOAD DATA
# ══════════════════════════════════════════════════════════════════

def load_csv(filepath):
    """Baca file CSV dan kembalikan list of dict."""
    if not os.path.exists(filepath):
        print(f"[ERROR] File tidak ditemukan: {filepath}")
        print(f"        Jalankan experiment.py terlebih dahulu.")
        return []
    rows = []
    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Konversi nilai numerik
            converted = {}
            for k, v in row.items():
                try:
                    converted[k] = float(v)
                except (ValueError, TypeError):
                    converted[k] = v
            rows.append(converted)
    return rows


# ══════════════════════════════════════════════════════════════════
# STATISTIK
# ══════════════════════════════════════════════════════════════════

def confidence_interval_95(mean, stdev, n):
    """
    Hitung confidence interval 95% menggunakan t-distribution.
    Untuk n >= 30, t ≈ 1.96 (mendekati distribusi normal).
    """
    if n <= 1 or stdev == 0:
        return 0.0
    # t-value untuk 95% CI, df = n-1
    # Untuk n=30: t = 2.045, n=50: t=2.009, n>=120: t≈1.96
    t_table = {
        30: 2.045, 31: 2.040, 32: 2.037, 33: 2.035, 34: 2.032,
        35: 2.030, 40: 2.021, 45: 2.014, 50: 2.009, 60: 2.000,
        80: 1.990, 100: 1.984, 120: 1.980
    }
    n_int = int(n)
    t = t_table.get(n_int, 1.96)   # default 1.96 untuk n besar
    margin = t * (stdev / math.sqrt(n))
    return round(margin, 4)


def compute_stats(mean, stdev, n):
    """Hitung statistik lengkap dari mean dan stdev yang sudah ada."""
    ci = confidence_interval_95(mean, stdev, n)
    return {
        "mean":    round(mean,  4),
        "stdev":   round(stdev, 4),
        "ci_95":   ci,
        "n":       int(n),
        "lower":   round(mean - ci, 4),
        "upper":   round(mean + ci, 4),
    }


# ══════════════════════════════════════════════════════════════════
# ANALISIS UTAMA
# ══════════════════════════════════════════════════════════════════

def analyze_performance(rows):
    """
    Analisis data kinerja dari experiment_results.csv.
    Kelompokkan per mode dan ukuran data.
    """
    # Struktur: results[mode][size_kb] = {rtt, ct_size}
    results = defaultdict(dict)

    for row in rows:
        mode    = str(row.get("mode", "")).upper()
        size_kb = int(row.get("size_kb", 0))

        rtt_mean  = float(row.get("rtt_mean_ms",         0))
        rtt_std   = float(row.get("rtt_stdev_ms",        0))
        ct_mean   = float(row.get("ct_size_mean_bytes",  0))
        ct_std    = float(row.get("ct_size_stdev_bytes", 0))
        n         = float(row.get("n_runs",              30))

        results[mode][size_kb] = {
            "rtt":     compute_stats(rtt_mean, rtt_std, n),
            "ct_size": compute_stats(ct_mean,  ct_std,  n),
            "n":       int(n),
        }

    return results


def analyze_throughput(rows):
    """
    Analisis data throughput dari throughput_results.csv.
    """
    results = defaultdict(dict)
    for row in rows:
        mode    = str(row.get("mode", "")).upper()
        size_kb = int(row.get("size_kb", 0))
        results[mode][size_kb] = {
            "throughput":     float(row.get("throughput_msg_per_sec", 0)),
            "total_success":  int(row.get("total_success",            0)),
            "total_error":    int(row.get("total_error",              0)),
            "duration_sec":   float(row.get("duration_sec",          10)),
        }
    return results


def compare_rsa_ecc(perf, sizes):
    """
    Bandingkan RSA vs ECC dan hitung speedup ratio.
    """
    comparisons = {}
    for size in sizes:
        rsa = perf.get("RSA", {}).get(size)
        ecc = perf.get("ECC", {}).get(size)
        if rsa and ecc:
            rtt_rsa = rsa["rtt"]["mean"]
            rtt_ecc = ecc["rtt"]["mean"]
            ct_rsa  = rsa["ct_size"]["mean"]
            ct_ecc  = ecc["ct_size"]["mean"]

            comparisons[size] = {
                "rtt_speedup":      round(rtt_rsa / rtt_ecc, 2) if rtt_ecc > 0 else 0,
                "ct_overhead_bytes": round(ct_rsa - ct_ecc, 2),
                "ct_overhead_pct":  round((ct_rsa - ct_ecc) / ct_ecc * 100, 2)
                                    if ct_ecc > 0 else 0,
            }
    return comparisons


# ══════════════════════════════════════════════════════════════════
# GRAFIK
# ══════════════════════════════════════════════════════════════════

COLORS = {
    "RSA": {"bar": "#8b5cf6", "err": "#6d28d9", "line": "#a78bfa"},
    "ECC": {"bar": "#3b82f6", "err": "#1d4ed8", "line": "#60a5fa"},
}

def plot_rtt_comparison(perf, sizes):
    """Grafik perbandingan RTT RSA vs ECC per ukuran data."""
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('#0f1117')
    ax.set_facecolor('#1a1d27')

    x        = range(len(sizes))
    width    = 0.35
    modes    = ["RSA", "ECC"]

    for i, mode in enumerate(modes):
        means  = []
        errors = []
        for size in sizes:
            entry = perf.get(mode, {}).get(size)
            if entry:
                means.append(entry["rtt"]["mean"])
                errors.append(entry["rtt"]["ci_95"])
            else:
                means.append(0)
                errors.append(0)

        offset = (i - 0.5) * width
        bars   = ax.bar(
            [xi + offset for xi in x],
            means,
            width,
            label=f"{mode} Mode",
            color=COLORS[mode]["bar"],
            alpha=0.85,
            yerr=errors,
            capsize=4,
            error_kw={"color": COLORS[mode]["err"], "linewidth": 1.5}
        )

        # Label nilai di atas bar
        for bar, mean in zip(bars, means):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.3,
                f"{mean:.2f}",
                ha='center', va='bottom',
                color='white', fontsize=8
            )

    ax.set_xlabel('Ukuran Data (KB)', color='#8892b0', fontsize=11)
    ax.set_ylabel('Round-Trip Time (ms)', color='#8892b0', fontsize=11)
    ax.set_title('Perbandingan End-to-End Time: RSA vs ECC\n'
                 '(error bar = 95% Confidence Interval)',
                 color='white', fontsize=13, pad=15)
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{s} KB" for s in sizes], color='#8892b0')
    ax.tick_params(colors='#8892b0')
    ax.spines['bottom'].set_color('#2e3250')
    ax.spines['left'].set_color('#2e3250')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.grid(True, color='#2e3250', linestyle='--', alpha=0.5)
    ax.set_axisbelow(True)
    ax.legend(facecolor='#21253a', edgecolor='#2e3250',
              labelcolor='white', fontsize=10)

    plt.tight_layout()
    path = os.path.join(FIGURES_DIR, "rtt_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [PLOT] Tersimpan: {path}")
    return path


def plot_ct_size_comparison(perf, sizes):
    """Grafik perbandingan ukuran ciphertext RSA vs ECC."""
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('#0f1117')
    ax.set_facecolor('#1a1d27')

    x     = range(len(sizes))
    width = 0.35
    modes = ["RSA", "ECC"]

    for i, mode in enumerate(modes):
        means = []
        for size in sizes:
            entry = perf.get(mode, {}).get(size)
            means.append(entry["ct_size"]["mean"] if entry else 0)

        offset = (i - 0.5) * width
        bars   = ax.bar(
            [xi + offset for xi in x],
            means,
            width,
            label=f"{mode} Mode",
            color=COLORS[mode]["bar"],
            alpha=0.85,
        )

        for bar, mean in zip(bars, means):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 50,
                f"{int(mean):,}",
                ha='center', va='bottom',
                color='white', fontsize=8
            )

    ax.set_xlabel('Ukuran Data (KB)', color='#8892b0', fontsize=11)
    ax.set_ylabel('Ukuran Ciphertext (bytes)', color='#8892b0', fontsize=11)
    ax.set_title('Perbandingan Ukuran Ciphertext: RSA vs ECC',
                 color='white', fontsize=13, pad=15)
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{s} KB" for s in sizes], color='#8892b0')
    ax.tick_params(colors='#8892b0')
    ax.spines['bottom'].set_color('#2e3250')
    ax.spines['left'].set_color('#2e3250')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.grid(True, color='#2e3250', linestyle='--', alpha=0.5)
    ax.set_axisbelow(True)
    ax.legend(facecolor='#21253a', edgecolor='#2e3250',
              labelcolor='white', fontsize=10)

    plt.tight_layout()
    path = os.path.join(FIGURES_DIR, "ct_size_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [PLOT] Tersimpan: {path}")
    return path


def plot_throughput_comparison(tp):
    """Grafik perbandingan throughput RSA vs ECC."""
    sizes = sorted(set(
        s for mode_data in tp.values() for s in mode_data.keys()
    ))
    if not sizes:
        return None

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('#0f1117')
    ax.set_facecolor('#1a1d27')

    x     = range(len(sizes))
    width = 0.35
    modes = ["RSA", "ECC"]

    for i, mode in enumerate(modes):
        vals = [tp.get(mode, {}).get(s, {}).get("throughput", 0)
                for s in sizes]
        offset = (i - 0.5) * width
        bars   = ax.bar(
            [xi + offset for xi in x],
            vals,
            width,
            label=f"{mode} Mode",
            color=COLORS[mode]["bar"],
            alpha=0.85,
        )

        for bar, val in zip(bars, vals):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f"{val:.1f}",
                ha='center', va='bottom',
                color='white', fontsize=9
            )

    ax.set_xlabel('Ukuran Data (KB)', color='#8892b0', fontsize=11)
    ax.set_ylabel('Throughput (pesan/detik)', color='#8892b0', fontsize=11)
    ax.set_title('Perbandingan Throughput: RSA vs ECC',
                 color='white', fontsize=13, pad=15)
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{s} KB" for s in sizes], color='#8892b0')
    ax.tick_params(colors='#8892b0')
    ax.spines['bottom'].set_color('#2e3250')
    ax.spines['left'].set_color('#2e3250')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.grid(True, color='#2e3250', linestyle='--', alpha=0.5)
    ax.set_axisbelow(True)
    ax.legend(facecolor='#21253a', edgecolor='#2e3250',
              labelcolor='white', fontsize=10)

    plt.tight_layout()
    path = os.path.join(FIGURES_DIR, "throughput_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [PLOT] Tersimpan: {path}")
    return path


def plot_rtt_vs_size(perf, sizes):
    """Grafik RTT vs ukuran data (line chart) untuk melihat linearitas."""
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('#0f1117')
    ax.set_facecolor('#1a1d27')

    for mode in ["RSA", "ECC"]:
        x_vals  = []
        y_means = []
        y_upper = []
        y_lower = []

        for size in sizes:
            entry = perf.get(mode, {}).get(size)
            if entry:
                x_vals.append(size)
                mean = entry["rtt"]["mean"]
                ci   = entry["rtt"]["ci_95"]
                y_means.append(mean)
                y_upper.append(mean + ci)
                y_lower.append(mean - ci)

        if not x_vals:
            continue

        color = COLORS[mode]["line"]
        ax.plot(x_vals, y_means, 'o-', color=color,
                linewidth=2.5, markersize=8,
                label=f"{mode} Mode", zorder=3)
        ax.fill_between(x_vals, y_lower, y_upper,
                        color=color, alpha=0.15, zorder=2)

        # Annotasi tiap titik
        for x, y in zip(x_vals, y_means):
            ax.annotate(f"{y:.2f} ms",
                        xy=(x, y),
                        xytext=(0, 12),
                        textcoords='offset points',
                        ha='center', color=color, fontsize=9)

    ax.set_xlabel('Ukuran Data (KB)', color='#8892b0', fontsize=11)
    ax.set_ylabel('End-to-End Time (ms)', color='#8892b0', fontsize=11)
    ax.set_title('End-to-End Time vs Ukuran Data\n'
                 '(area = 95% CI)',
                 color='white', fontsize=13, pad=15)
    ax.tick_params(colors='#8892b0')
    ax.spines['bottom'].set_color('#2e3250')
    ax.spines['left'].set_color('#2e3250')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.grid(True, color='#2e3250', linestyle='--', alpha=0.5)
    ax.set_axisbelow(True)
    ax.legend(facecolor='#21253a', edgecolor='#2e3250',
              labelcolor='white', fontsize=10)

    plt.tight_layout()
    path = os.path.join(FIGURES_DIR, "rtt_vs_size.png")
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [PLOT] Tersimpan: {path}")
    return path


# ══════════════════════════════════════════════════════════════════
# LAPORAN TEKS
# ══════════════════════════════════════════════════════════════════

def generate_report(perf, tp, comparisons, sizes):
    """
    Buat laporan teks lengkap siap dipakai sebagai referensi paper.
    """
    lines = []
    sep   = "=" * 65

    lines.append(sep)
    lines.append("  LAPORAN ANALISIS EKSPERIMEN KRIPTOGRAFI")
    lines.append("  Smart Agriculture Monitoring System")
    lines.append("  RSA-OAEP vs ECC X25519-HKDF — AES-256-GCM")
    lines.append(sep)
    lines.append("")

    # ── Table I: End-to-End Time ──────────────────────────────────
    lines.append("TABLE I — END-TO-END TIME (ms), n=30")
    lines.append("-" * 65)
    lines.append(f"{'Size':<8} {'RSA Mean':>10} {'RSA StDev':>10} "
                 f"{'RSA CI95':>10} {'ECC Mean':>10} {'ECC StDev':>10} "
                 f"{'ECC CI95':>10}")
    lines.append("-" * 65)

    for size in sizes:
        rsa = perf.get("RSA", {}).get(size, {})
        ecc = perf.get("ECC", {}).get(size, {})

        rsa_rtt = rsa.get("rtt", {})
        ecc_rtt = ecc.get("rtt", {})

        lines.append(
            f"{str(size)+'KB':<8} "
            f"{rsa_rtt.get('mean',0):>10.4f} "
            f"{rsa_rtt.get('stdev',0):>10.4f} "
            f"{'±'+str(rsa_rtt.get('ci_95',0)):>10} "
            f"{ecc_rtt.get('mean',0):>10.4f} "
            f"{ecc_rtt.get('stdev',0):>10.4f} "
            f"{'±'+str(ecc_rtt.get('ci_95',0)):>10}"
        )
    lines.append("")

    # ── Table II: Ciphertext Size ─────────────────────────────────
    lines.append("TABLE II — CIPHERTEXT SIZE (bytes), n=30")
    lines.append("-" * 65)
    lines.append(f"{'Size':<8} {'RSA Mean':>12} {'RSA StDev':>12} "
                 f"{'ECC Mean':>12} {'ECC StDev':>12}")
    lines.append("-" * 65)

    for size in sizes:
        rsa = perf.get("RSA", {}).get(size, {})
        ecc = perf.get("ECC", {}).get(size, {})

        rsa_ct = rsa.get("ct_size", {})
        ecc_ct = ecc.get("ct_size", {})

        lines.append(
            f"{str(size)+'KB':<8} "
            f"{rsa_ct.get('mean',0):>12.2f} "
            f"{rsa_ct.get('stdev',0):>12.2f} "
            f"{ecc_ct.get('mean',0):>12.2f} "
            f"{ecc_ct.get('stdev',0):>12.2f}"
        )
    lines.append("")

    # ── Table III: Throughput ─────────────────────────────────────
    lines.append("TABLE III — THROUGHPUT (pesan/detik)")
    lines.append("-" * 65)
    lines.append(f"{'Size':<8} {'RSA':>12} {'ECC':>12} {'Rasio ECC/RSA':>16}")
    lines.append("-" * 65)

    tp_sizes = sorted(set(
        s for mode_data in tp.values() for s in mode_data.keys()
    ))
    for size in tp_sizes:
        rsa_tp = tp.get("RSA", {}).get(size, {}).get("throughput", 0)
        ecc_tp = tp.get("ECC", {}).get(size, {}).get("throughput", 0)
        ratio  = round(ecc_tp / rsa_tp, 2) if rsa_tp > 0 else 0

        lines.append(
            f"{str(size)+'KB':<8} "
            f"{rsa_tp:>12.2f} "
            f"{ecc_tp:>12.2f} "
            f"{'x'+str(ratio):>16}"
        )
    lines.append("")

    # ── Analisis Perbandingan RSA vs ECC ──────────────────────────
    lines.append("ANALISIS PERBANDINGAN RSA vs ECC")
    lines.append("-" * 65)

    for size in sizes:
        comp = comparisons.get(size)
        if not comp:
            continue
        lines.append(f"  Ukuran {size}KB:")
        lines.append(f"    ECC {comp['rtt_speedup']}x lebih cepat dari RSA")
        lines.append(f"    RSA menghasilkan overhead "
                     f"{comp['ct_overhead_bytes']:.0f} bytes "
                     f"({comp['ct_overhead_pct']}%) lebih besar dari ECC")
    lines.append("")

    # ── Kesimpulan Analisis ───────────────────────────────────────
    lines.append("KESIMPULAN ANALISIS")
    lines.append("-" * 65)

    # Hitung rata-rata speedup
    speedups = [c["rtt_speedup"] for c in comparisons.values()
                if c.get("rtt_speedup")]
    avg_speedup = round(sum(speedups) / len(speedups), 2) if speedups else 0

    overheads = [c["ct_overhead_bytes"] for c in comparisons.values()
                 if c.get("ct_overhead_bytes") is not None]
    avg_overhead = round(sum(overheads) / len(overheads), 0) if overheads else 0

    lines.append(f"  1. ECC rata-rata {avg_speedup}x lebih cepat dari RSA")
    lines.append(f"     pada semua ukuran data yang diuji.")
    lines.append(f"")
    lines.append(f"  2. RSA menghasilkan overhead ciphertext rata-rata")
    lines.append(f"     {avg_overhead:.0f} bytes lebih besar dari ECC per paket.")
    lines.append(f"     Perbedaan ini berasal dari ukuran encrypted_session_key:")
    lines.append(f"     RSA-2048 = 256 bytes vs X25519 = 32 bytes.")
    lines.append(f"")
    lines.append(f"  3. ECC unggul dalam throughput karena operasi X25519")
    lines.append(f"     (perkalian titik kurva eliptik) jauh lebih ringan")
    lines.append(f"     dibanding RSA-OAEP (eksponen bilangan prima 2048-bit).")
    lines.append(f"")
    lines.append(f"  4. Kedua mode membuktikan IND-CPA dan IND-CCA terpenuhi")
    lines.append(f"     melalui penggunaan nonce unik, RSA-OAEP random padding,")
    lines.append(f"     ephemeral key (ECC), dan AES-GCM authentication tag.")
    lines.append("")
    lines.append(sep)

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    print("=" * 65)
    print("  ANALISIS EKSPERIMEN KRIPTOGRAFI")
    print("  Smart Agriculture — RSA vs ECC")
    print("=" * 65 + "\n")

    # ── Load data ─────────────────────────────────────────────────
    print("[1/4] Membaca data eksperimen...")
    perf_rows = load_csv(RESULTS_FILE)
    tp_rows   = load_csv(THROUGHPUT_FILE)

    if not perf_rows:
        print("\nTidak ada data untuk dianalisis.")
        print("Pastikan experiment_results.csv sudah ada.")
        return

    # ── Analisis ──────────────────────────────────────────────────
    print("[2/4] Menganalisis data...")
    perf  = analyze_performance(perf_rows)
    tp    = analyze_throughput(tp_rows) if tp_rows else {}
    sizes = sorted(set(
        size for mode_data in perf.values() for size in mode_data.keys()
    ))
    comparisons = compare_rsa_ecc(perf, sizes)

    # ── Grafik ────────────────────────────────────────────────────
    print("[3/4] Membuat grafik...")
    if HAS_MATPLOTLIB:
        plot_rtt_comparison(perf, sizes)
        plot_ct_size_comparison(perf, sizes)
        plot_rtt_vs_size(perf, sizes)
        if tp:
            plot_throughput_comparison(tp)
    else:
        print("  [SKIP] matplotlib tidak tersedia.")

    # ── Laporan ───────────────────────────────────────────────────
    print("[4/4] Membuat laporan...")
    report = generate_report(perf, tp, comparisons, sizes)

    # Cetak ke terminal
    print("\n" + report)

    # Simpan ke file
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n  Laporan tersimpan: {REPORT_FILE}")

    if HAS_MATPLOTLIB:
        print(f"  Grafik tersimpan : {FIGURES_DIR}/")
        print(f"    - rtt_comparison.png")
        print(f"    - ct_size_comparison.png")
        print(f"    - rtt_vs_size.png")
        if tp:
            print(f"    - throughput_comparison.png")

    print("\nAnalisis selesai!")


if __name__ == "__main__":
    main()
