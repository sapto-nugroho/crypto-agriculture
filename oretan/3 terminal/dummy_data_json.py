#Ga usah dirunning, data jsonnya udah jadi
import json
import random
from datetime import datetime, timedelta

#Variabel untuk menampung dummy data json
dataset = []

#Data dimulai dari 1 Mei 2026 pukul 8:00:00
start_time = datetime(2026, 5, 1, 8)

#Buat 1000 data, sehingga n = 1000
for i in range(1000):
    data = {
        "sensor_id": "FIELD-01-SENSOR-01",
        "timestamp": (start_time + timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S"),
        #Temperature dimulai dari 25 hingga 38 (desimal) lalu dibulatkan 1 angka di belakang koma
        #Berlaku hal yg sama dengan air humidity, soil_moisture, soil_ph
        "temperature": round(random.uniform(25.0, 38.0), 1),
        "air_humidity": round(random.uniform(50.0, 90.0), 1),
        "soil_moisture": round(random.uniform(20.0, 60.0), 1),
        "soil_ph": round(random.uniform(5.5, 7.5), 1),
        "sequence_number": i + 1
    }
    dataset.append(data)

#Simpan file json
with open("sensor_data_1000.json", "w") as f:
    json.dump(dataset, f, indent=2)

print(f"File sensor_data_1000.json berhasil dibuat")
#Tampilkan salah satu data json (urutan pertama)
print(json.dumps(dataset[0]))
