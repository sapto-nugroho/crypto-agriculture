# sensor_simulator.py
# Jalankan: python sensor_simulator.py
# Kirim data sensor ke edge gateway secara berkala.
# Data plaintext juga disimpan ke sensor_logs/ untuk keperluan historis & verifikasi.

import requests
import json
import time
import random
import os
from datetime import datetime

GATEWAY_URL = "http://localhost:5001/receive"
MODE        = "ECC"   # Pilihan: "RSA", "ECC", "X25519"
INTERVAL    = 2       # Kirim data tiap N detik
LOG_DIR     = "sensor_logs"

os.makedirs(LOG_DIR, exist_ok=True)

sequence_number = 0


# ── generate data ───────────────────────────────────────────────────────────
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


# ── sensor log ───────────────────────────────────────────────────────────
def save_sensor_log(data):
    """
    Simpan data sensor plaintext ke file log harian.
    Format file: sensor_logs/sensor_log_YYYY-MM-DD.json
    Setiap file berisi list data sensor untuk hari itu.
    """
    today    = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(LOG_DIR, f"sensor_log_{today}.json")

    if os.path.exists(log_file):
        with open(log_file) as f:
            logs = json.load(f)
    else:
        logs = []

    logs.append(data)

    with open(log_file, "w") as f:
        json.dump(logs, f, indent=2)


# ── Run ───────────────────────────────────────────────────────────
def run():
    print(f"Sensor Simulator started | Mode: {MODE} | Interval: {INTERVAL}s")
    print(f"Log directory: {LOG_DIR}/")
    print("Tekan Ctrl+C untuk berhenti.\n")

    sent   = 0
    failed = 0

    while True:
        data = generate_sensor_data()

        # Simpan log plaintext sebelum dikirim
        save_sensor_log(data)

        payload = {"sensor_data": data, "mode": MODE}
        try:
            response = requests.post(GATEWAY_URL, json=payload, timeout=3)
            if response.status_code == 200:
                sent += 1
                print(f"[{data['timestamp']}] seq#{data['sequence_number']:05d} "
                      f"-> Gateway OK | temp={data['temperature']}°C "
                      f"(total sent: {sent})")
            else:
                print(f"[WARN] seq#{data['sequence_number']:05d} "
                      f"Gateway response: {response.status_code}")
        except Exception as e:
            failed += 1
            print(f"[ERROR] seq#{data['sequence_number']:05d} "
                  f"Gateway tidak bisa dihubungi: {e} (total failed: {failed})")

        time.sleep(INTERVAL)

# ── main ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    run()
