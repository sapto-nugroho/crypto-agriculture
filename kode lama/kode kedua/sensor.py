# sensor_simulator.py
# Jalankan SETELAH server dan gateway aktif.
# Menghasilkan data sensor JSON dan mengirim ke gateway.
# Mode enkripsi (RSA/ECC) dibaca dinamis dari server setiap pengiriman.
# Data plaintext disimpan ke sensor_logs/ untuk verifikasi historis.
#
# Jalankan: python sensor_simulator.py

import requests
import json
import time
import random
import os
from datetime import datetime

GATEWAY_URL = "http://localhost:5001/receive"
SERVER_URL  = "http://localhost:5002"
INTERVAL    = 2       # Kirim data tiap N detik
LOG_DIR     = "sensor_logs"

os.makedirs(LOG_DIR, exist_ok=True)

sequence_number = 0
current_mode    = "ECC"   # mode lokal, diperbarui dari server


def fetch_active_mode():
    """
    Fetch mode aktif dari server.
    Jika server tidak bisa dihubungi, gunakan mode lokal terakhir.
    """
    global current_mode
    try:
        resp = requests.get(f"{SERVER_URL}/api/mode", timeout=2)
        if resp.status_code == 200:
            new_mode = resp.json().get("mode", current_mode)
            if new_mode != current_mode:
                print(f"[MODE] Mode berubah: {current_mode} → {new_mode}")
                current_mode = new_mode
    except Exception:
        # Server tidak bisa dihubungi, pakai mode terakhir
        pass
    return current_mode


def generate_sensor_data():
    global sequence_number
    sequence_number += 1
    return {
        "sensor_id":       "FIELD-01-SENSOR-01",
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "temperature":     round(random.uniform(25.0, 35.0), 1),
        "air_humidity":    round(random.uniform(60.0, 85.0), 1),
        "soil_moisture":   round(random.uniform(30.0, 55.0), 1),
        "soil_ph":         round(random.uniform(5.5, 7.5), 1),
        "sequence_number": sequence_number
    }


def save_sensor_log(data, mode):
    """
    Simpan data sensor plaintext ke log harian.
    Format: sensor_logs/sensor_log_YYYY-MM-DD.json
    """
    today    = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(LOG_DIR, f"sensor_log_{today}.json")

    logs = []
    if os.path.exists(log_file):
        with open(log_file) as f:
            logs = json.load(f)

    # Simpan juga mode yang digunakan untuk referensi
    entry = {**data, "mode_used": mode}
    logs.append(entry)

    with open(log_file, "w") as f:
        json.dump(logs, f, indent=2)


def run():
    global current_mode

    print("=" * 55)
    print("  SENSOR SIMULATOR — Smart Agriculture")
    print("=" * 55)
    print(f"[INFO] Interval  : {INTERVAL} detik")
    print(f"[INFO] Log dir   : {LOG_DIR}/")
    print(f"[INFO] Mode awal : fetch dari server...")
    print("Tekan Ctrl+C untuk berhenti.\n")

    # Fetch mode awal dari server
    fetch_active_mode()
    print(f"[INFO] Mode aktif: {current_mode}\n")

    sent   = 0
    failed = 0

    while True:
        # Fetch mode terbaru dari server setiap pengiriman
        mode = fetch_active_mode()

        data = generate_sensor_data()

        # Simpan log plaintext sebelum dikirim
        save_sensor_log(data, mode)

        payload = {"sensor_data": data, "mode": mode}
        try:
            response = requests.post(GATEWAY_URL, json=payload, timeout=3)
            if response.status_code == 200:
                sent += 1
                print(f"[{data['timestamp']}] seq#{str(data['sequence_number']).zfill(5)} "
                      f"| mode={mode} "
                      f"| temp={data['temperature']}°C "
                      f"| humidity={data['air_humidity']}% "
                      f"| sent={sent}")
            else:
                print(f"[WARN] seq#{data['sequence_number']} "
                      f"Gateway response: {response.status_code}")
        except Exception as e:
            failed += 1
            print(f"[ERROR] seq#{data['sequence_number']} "
                  f"Gateway tidak bisa dihubungi: {e} (failed={failed})")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    run()
