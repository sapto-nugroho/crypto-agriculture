import json

#Load data json
with open("sensor_data_1000.json", "r") as f:
    data = json.load(f)

#Tampilkan 5 data pertama pada json
for i in range(5):
    print(data[i])
    #Supaya outputnya rapi aja sih WKWKWKW
    print(" ")