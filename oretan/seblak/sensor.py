import json
import random
import requests
import time

GATEWAY_URL = "http://localhost:5001/receive"
MODE        = "ECC"   # Ganti ke "RSA" kalau mau RSA mode
INTERVAL    = 2       # Kirim data tiap N detik

#Load data json
with open("sensor_data_1000.json", "r") as f:
    dataset = json.load(f)

#Ambil 1 data random seolah sensor lagi mendeteksi
data = random.choice(dataset)
data_json = json.dumps(data)
print(json.dumps(data))

#Kalau dijalankan langsung (bukan diimport), kirim ke gateway terus-terusan
if __name__ == "__main__":
    print(f"\nSensor aktif | Mode: {MODE} | Interval: {INTERVAL}s")
    print("Tekan Ctrl+C untuk berhenti\n")

    sent   = 0
    failed = 0
    seq    = 0

    while True:
        seq += 1
        #Ambil 1 data random tiap iterasi
        data = random.choice(dataset)
        data["sequence_number"] = seq

        payload = {"sensor_data": data, "mode": MODE}

        try:
            response = requests.post(GATEWAY_URL, json=payload, timeout=3)
            if response.status_code == 200:
                sent += 1
                print(f"seq#{seq:04d} → Gateway OK | "
                      f"temp={data['temperature']}°C | "
                      f"pH={data['soil_ph']} | "
                      f"total_sent={sent}")
            else:
                print(f"[WARN] seq#{seq:04d} Gateway response: {response.status_code}")
        except Exception as e:
            failed += 1
            print(f"[ERROR] seq#{seq:04d} Gateway tidak bisa dihubungi: {e} "
                  f"(total_failed={failed})")

        time.sleep(INTERVAL)