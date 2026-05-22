import json
import random
import requests
import time

GATEWAY_URL = "http://localhost:5001/receive"
MODE        = "ECC"   # Ganti ke "RSA" kalau mau RSA mode
INTERVAL    = 2       # Kirim data tiap N detik

# Load data json
with open("sensor_data_1000.json", "r") as f:
    dataset = json.load(f)

# Ambil 1 data random seolah sensor lagi mendeteksi
data = random.choice(dataset)
data_json = json.dumps(data)
print(json.dumps(data))

# Kalau dijalankan langsung (bukan diimport), kirim ke gateway terus-terusan
if __name__ == "__main__":
    print(f"\nSensor aktif | Mode: {MODE} | Interval: {INTERVAL}s")
    print("Tekan Ctrl+C untuk berhenti\n")
    sent   = 0
    failed = 0
    seq    = 0

    while True:
        seq += 1
        # Ambil 1 data yang sama
        data = random.choice(dataset)
        data["sequence_number"] = seq

        # Kirim dengan RSA
        try:
            response = requests.post(GATEWAY_URL, json={"sensor_data": data, "mode": "RSA"}, timeout=3)
            if response.status_code == 200:
                sent += 1
                print(f"seq#{seq:04d} → Gateway OK | RSA | temp={data['temperature']}°C")
        except Exception as e:
            failed += 1
            print(f"[ERROR] RSA seq#{seq:04d}: {e}")

        # Kirim data yang SAMA dengan ECC
        try:
            response = requests.post(GATEWAY_URL, json={"sensor_data": data, "mode": "ECC"}, timeout=3)
            if response.status_code == 200:
                sent += 1
                print(f"seq#{seq:04d} → Gateway OK | ECC | temp={data['temperature']}°C")
        except Exception as e:
            failed += 1
            print(f"[ERROR] ECC seq#{seq:04d}: {e}")

        time.sleep(INTERVAL)