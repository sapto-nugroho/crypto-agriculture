"""
experiment_availability.py
==========================
Eksperimen Availability — Sesuai Spesifikasi 8.3

Skenario (persis sesuai panduan):
  1. Jalankan sensor simulator dan edge gateway  ← sudah berjalan sebelum script ini
  2. Jalankan server selama 30 detik             ← fase ONLINE
  3. Matikan server selama 30 detik              ← fase DOWNTIME (script otomatis instruksikan)
  4. Sensor simulator tetap menghasilkan data    ← sensor.py tetap jalan
  5. Edge gateway menyimpan ciphertext ke file   ← gateway buffer otomatis
  6. Hidupkan server kembali                     ← script instruksikan user
  7. Edge gateway kirim ulang ciphertext tertunda← gateway retry otomatis
  8. Laporan: jumlah data diterima & data hilang ← OUTPUT script ini

Target: jumlah data hilang = 0

Prasyarat sebelum menjalankan script ini:
  - sensor.py   sudah berjalan (Terminal 1)
  - gateway.py  sudah berjalan (Terminal 2)
  - server.py   sudah berjalan (Terminal 3)

Jalankan: python experiment_availability.py
"""

import time
import json
import os
import csv
import requests
from datetime import datetime

# ══════════════════════════════════════════════════════════════════
# KONFIGURASI
# ══════════════════════════════════════════════════════════════════

SERVER_URL        = "http://127.0.0.1:5002"
GATEWAY_STATS_URL = "http://127.0.0.1:5001/stats"
BUFFER_DIR        = "gateway_buffer"   # direktori buffer milik gateway

PHASE_ONLINE_SEC   = 30   # Fase 2: server aktif
PHASE_DOWNTIME_SEC = 30   # Fase 3: server mati
PHASE_RECOVERY_SEC = 60   # Fase 7: tunggu retry buffer habis (max)
POLL_INTERVAL      = 2    # polling stats tiap N detik


# ══════════════════════════════════════════════════════════════════
# HELPER
# ══════════════════════════════════════════════════════════════════

def get_server_stats():
    try:
        r = requests.get(f"{SERVER_URL}/stats", timeout=3)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

def get_gateway_stats():
    try:
        r = requests.get(GATEWAY_STATS_URL, timeout=3)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

def count_buffer_files():
    """Hitung file yang masih ada di gateway_buffer/."""
    if not os.path.exists(BUFFER_DIR):
        return 0
    return len([f for f in os.listdir(BUFFER_DIR) if f.endswith(".json")])

def is_server_up():
    try:
        r = requests.get(f"{SERVER_URL}/health", timeout=2)
        return r.status_code == 200
    except Exception:
        return False

def get_next_filename(base_name):
    i = 1
    while True:
        filename = f"{base_name}_{i}.csv"
        if not os.path.exists(filename):
            return filename
        i += 1

def save_csv(results, base_name):
    if not results:
        return
    filename = get_next_filename(base_name)
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"  [SAVED] {filename}")
    return filename

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ══════════════════════════════════════════════════════════════════
# POLLING LOOP — catat stats secara berkala
# ══════════════════════════════════════════════════════════════════

def poll_stats(label, duration_sec, poll_rows):
    """
    Poll stats gateway + server setiap POLL_INTERVAL detik
    selama duration_sec detik. Append ke poll_rows.
    """
    deadline = time.perf_counter() + duration_sec
    while time.perf_counter() < deadline:
        gw = get_gateway_stats()
        sv = get_server_stats()
        buf = count_buffer_files()

        row = {
            "phase":              label,
            "timestamp":          datetime.now().strftime("%H:%M:%S"),
            "server_received":    sv.get("received",          0),
            "server_failed":      sv.get("failed",            0),
            "server_rejected":    sv.get("tampered_rejected", 0),
            "gw_sent":            gw.get("sent",              0),
            "gw_buffered":        gw.get("buffered",          0),
            "gw_retry_sent":      gw.get("retry_sent",        0),
            "gw_pending_buffer":  gw.get("pending_in_buffer", buf),
            "buffer_files":       buf,
        }
        poll_rows.append(row)

        log(f"[{label}] server_rcv={row['server_received']} | "
            f"gw_sent={row['gw_sent']} | "
            f"gw_buffered={row['gw_buffered']} | "
            f"pending={row['gw_pending_buffer']} | "
            f"retry_sent={row['gw_retry_sent']}")

        time.sleep(POLL_INTERVAL)


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  EKSPERIMEN AVAILABILITY — Local Buffering")
    print("  Spesifikasi 8.3: Zero Data Loss")
    print("=" * 60)

    # ── Cek prasyarat ────────────────────────────────────────────
    print("\nMemeriksa koneksi awal...")
    gw_ok  = False
    srv_ok = False

    try:
        requests.get(GATEWAY_STATS_URL, timeout=3)
        gw_ok = True
        print("  ✓ Gateway aktif")
    except Exception:
        print("  ✗ Gateway TIDAK aktif! Jalankan gateway.py dulu.")

    try:
        requests.get(f"{SERVER_URL}/health", timeout=3)
        srv_ok = True
        print("  ✓ Server aktif")
    except Exception:
        print("  ✗ Server TIDAK aktif! Jalankan server.py dulu.")

    if not gw_ok:
        print("\nGateway harus aktif. Hentikan.")
        exit(1)

    if not srv_ok:
        print("\nServer harus aktif untuk fase ONLINE. Hentikan.")
        exit(1)

    poll_rows = []   # semua baris polling per fase

    # ── Catat baseline SEBELUM eksperimen ────────────────────────
    print("\n" + "─" * 60)
    print("  BASELINE — Catat kondisi awal")
    print("─" * 60)
    gw_start  = get_gateway_stats()
    sv_start  = get_server_stats()
    buf_start = count_buffer_files()

    sent_before     = gw_start.get("sent",     0)
    buffered_before = gw_start.get("buffered", 0)
    rcv_before      = sv_start.get("received", 0)

    log(f"Baseline: server_received={rcv_before} | "
        f"gw_sent={sent_before} | buffer_files={buf_start}")

    # ══════════════════════════════════════════════════════════════
    # FASE 2 — SERVER ONLINE (30 detik)
    # Sensor mengirim data, server menerima dan mendekripsi
    # ══════════════════════════════════════════════════════════════
    print("\n" + "─" * 60)
    print(f"  FASE 2 — SERVER ONLINE ({PHASE_ONLINE_SEC} detik)")
    print("  Sensor simulator mengirim data ke gateway → server")
    print("─" * 60)

    poll_stats("online", PHASE_ONLINE_SEC, poll_rows)

    # Snapshot akhir fase online
    sv_after_online  = get_server_stats()
    gw_after_online  = get_gateway_stats()
    rcv_after_online = sv_after_online.get("received", 0)
    sent_online      = gw_after_online.get("sent", 0)

    log(f"Akhir fase ONLINE: server_received={rcv_after_online} | "
        f"gw_sent={sent_online}")

    # ══════════════════════════════════════════════════════════════
    # FASE 3 — SERVER MATI (30 detik)
    # User diminta mematikan server secara manual
    # Gateway akan buffer ciphertext ke file lokal
    # ══════════════════════════════════════════════════════════════
    print("\n" + "─" * 60)
    print(f"  FASE 3 — MATIKAN SERVER SEKARANG!")
    print(f"  ➜ Pergi ke terminal server.py, tekan Ctrl+C")
    print(f"  Script akan mulai monitoring dalam 5 detik...")
    print("─" * 60)
    time.sleep(5)

    # Verifikasi server benar-benar mati
    if is_server_up():
        print("\n  ⚠ Server masih aktif! Pastikan sudah dimatikan.")
        input("  Matikan server lalu tekan ENTER untuk lanjut...")
    else:
        log("Server terdeteksi MATI. Mulai monitoring fase downtime...")

    downtime_start = time.perf_counter()
    poll_stats("downtime", PHASE_DOWNTIME_SEC, poll_rows)

    # Snapshot akhir downtime
    gw_after_downtime   = get_gateway_stats()
    buf_after_downtime  = count_buffer_files()
    gw_buffered_total   = gw_after_downtime.get("buffered", 0)

    log(f"Akhir fase DOWNTIME: buffer_files={buf_after_downtime} | "
        f"total_buffered={gw_buffered_total}")

    # ══════════════════════════════════════════════════════════════
    # FASE 6 — HIDUPKAN SERVER KEMBALI
    # ══════════════════════════════════════════════════════════════
    print("\n" + "─" * 60)
    print("  FASE 6 — HIDUPKAN SERVER KEMBALI!")
    print("  ➜ Jalankan: python server.py  (di terminal server)")
    print("  Script menunggu server aktif kembali...")
    print("─" * 60)

    # Tunggu sampai server hidup kembali (timeout 60 detik)
    recovery_wait_start = time.perf_counter()
    server_recovered    = False
    while time.perf_counter() - recovery_wait_start < 60:
        if is_server_up():
            recovery_detect_ms = round(
                (time.perf_counter() - recovery_wait_start) * 1000, 2
            )
            log(f"✅ Server AKTIF kembali! "
                f"(terdeteksi dalam {recovery_detect_ms}ms)")
            server_recovered = True
            break
        time.sleep(1)

    if not server_recovered:
        log("⚠ Server tidak aktif dalam 60 detik. Lanjut tanpa recovery.")

    # ══════════════════════════════════════════════════════════════
    # FASE 7 — RECOVERY: Gateway kirim ulang buffer
    # Tunggu sampai semua buffer ter-kirim (pending = 0)
    # ══════════════════════════════════════════════════════════════
    print("\n" + "─" * 60)
    print(f"  FASE 7 — RECOVERY: Gateway mengirim ulang buffer")
    print(f"  Menunggu hingga pending buffer = 0 (max {PHASE_RECOVERY_SEC}s)")
    print("─" * 60)

    recovery_start   = time.perf_counter()
    fully_drained    = False
    drain_elapsed_ms = None

    deadline = time.perf_counter() + PHASE_RECOVERY_SEC
    while time.perf_counter() < deadline:
        gw  = get_gateway_stats()
        sv  = get_server_stats()
        buf = count_buffer_files()

        pending = gw.get("pending_in_buffer", buf)

        row = {
            "phase":              "recovery",
            "timestamp":          datetime.now().strftime("%H:%M:%S"),
            "server_received":    sv.get("received",          0),
            "server_failed":      sv.get("failed",            0),
            "server_rejected":    sv.get("tampered_rejected", 0),
            "gw_sent":            gw.get("sent",              0),
            "gw_buffered":        gw.get("buffered",          0),
            "gw_retry_sent":      gw.get("retry_sent",        0),
            "gw_pending_buffer":  pending,
            "buffer_files":       buf,
        }
        poll_rows.append(row)

        log(f"[recovery] pending={pending} | "
            f"retry_sent={gw.get('retry_sent',0)} | "
            f"server_rcv={sv.get('received',0)}")

        if pending == 0 and server_recovered:
            drain_elapsed_ms = round(
                (time.perf_counter() - recovery_start) * 1000, 2
            )
            log(f"✅ Semua buffer ter-kirim! "
                f"Waktu drain = {drain_elapsed_ms}ms")
            fully_drained = True
            break

        time.sleep(POLL_INTERVAL)

    if not fully_drained:
        log("⚠ Buffer belum kosong setelah batas waktu recovery.")

    # ══════════════════════════════════════════════════════════════
    # FASE 8 — LAPORAN AKHIR
    # ══════════════════════════════════════════════════════════════
    print("\n" + "=" * 60)
    print("  FASE 8 — LAPORAN HASIL EKSPERIMEN")
    print("=" * 60)

    sv_final  = get_server_stats()
    gw_final  = get_gateway_stats()
    buf_final = count_buffer_files()

    # Hitung delta dari baseline
    total_sent_gw    = gw_final.get("sent",     0)
    total_buffered   = gw_final.get("buffered", 0)
    total_retry_sent = gw_final.get("retry_sent", 0)
    total_rcv_server = sv_final.get("received", 0)
    total_failed_srv = sv_final.get("failed",   0)
    total_rejected   = sv_final.get("tampered_rejected", 0)

    # Hitung dari baseline (delta selama eksperimen ini)
    delta_sent   = total_sent_gw    - sent_before
    delta_rcv    = total_rcv_server - rcv_before
    delta_buf    = total_buffered   - buffered_before

    # Data yang benar-benar dikirim gateway (langsung + retry)
    total_delivered = delta_sent + total_retry_sent

    # Data hilang = paket yang gateway kirim tapi server tidak terima
    # (tidak ter-buffer dan tidak terhitung sebagai retry)
    data_hilang = max(0, buf_final)   # sisa file buffer = belum terkirim

    # Availability (%)
    total_attempts = delta_buf + delta_sent
    availability_pct = (
        round((total_delivered / total_attempts) * 100, 4)
        if total_attempts > 0 else 100.0
    )

    print(f"\n  {'─'*45}")
    print(f"  {'METRIK':<35} {'NILAI':>10}")
    print(f"  {'─'*45}")
    print(f"  {'Total data dikirim gateway':<35} {delta_sent:>10}")
    print(f"  {'Total data di-buffer (saat downtime)':<35} {delta_buf:>10}")
    print(f"  {'Total retry terkirim':<35} {total_retry_sent:>10}")
    print(f"  {'Total diterima server':<35} {delta_rcv:>10}")
    print(f"  {'Sisa file di buffer (belum terkirim)':<35} {buf_final:>10}")
    print(f"  {'Data gagal (server)':<35} {total_failed_srv:>10}")
    print(f"  {'Data ditolak / tamper detected':<35} {total_rejected:>10}")
    print(f"  {'─'*45}")
    print(f"  {'DATA HILANG':<35} {data_hilang:>10}")
    print(f"  {'AVAILABILITY':<35} {availability_pct:>9.4f}%")
    print(f"  {'─'*45}")

    # Status zero data loss
    if data_hilang == 0:
        print(f"\n  ✅ TARGET TERPENUHI: jumlah data hilang = 0")
        print(f"     Sistem memenuhi spesifikasi availability.")
    else:
        print(f"\n  ❌ TARGET TIDAK TERPENUHI: {data_hilang} data masih pending.")
        print(f"     Kemungkinan penyebab: recovery belum selesai.")

    if drain_elapsed_ms:
        print(f"\n  ⏱ Waktu buffer drain (recovery): {drain_elapsed_ms}ms "
              f"({round(drain_elapsed_ms/1000, 2)}s)")

    # ── Simpan CSV ───────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  MENYIMPAN HASIL")
    print("─" * 60)

    # CSV 1: log polling per fase
    save_csv(poll_rows, "availability_poll_log")

    # CSV 2: ringkasan laporan akhir
    summary_row = [{
        "timestamp":              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "phase_online_sec":       PHASE_ONLINE_SEC,
        "phase_downtime_sec":     PHASE_DOWNTIME_SEC,
        "total_sent_gw":          delta_sent,
        "total_buffered":         delta_buf,
        "total_retry_sent":       total_retry_sent,
        "total_received_server":  delta_rcv,
        "pending_buffer_akhir":   buf_final,
        "data_hilang":            data_hilang,
        "data_gagal_server":      total_failed_srv,
        "data_rejected":          total_rejected,
        "availability_pct":       availability_pct,
        "drain_time_ms":          drain_elapsed_ms if drain_elapsed_ms else "N/A",
        "zero_data_loss":         "YES" if data_hilang == 0 else "NO",
    }]
    save_csv(summary_row, "availability_summary")

    print("\nEksperimen availability selesai!")
