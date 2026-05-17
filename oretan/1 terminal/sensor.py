import json
import random

#Load data json
with open("sensor_data_1000.json", "r") as f:
    dataset = json.load(f)

#Ambil 1 data random seolah sensor lagi mendeteksi
data = random.choice(dataset)
data_json = json.dumps(data)
print(json.dumps(data))