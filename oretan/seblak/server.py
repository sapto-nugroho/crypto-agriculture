import json
from aes import decrypt
from rsa import decrypt_session_key, private_key
from ecc import derive_session_key, public_key_from_bytes, server_private_key
from cryptography.exceptions import InvalidTag

class Server:
    def __init__(self):
        self.storage = []
        self.is_online = True
        print("Server aktif")

    def receive(self, packet):
        #Terima dan simpan ciphertext (bukan plaintext)
        self.storage.append(packet)
        print(f"[{packet['mode']}] Ciphertext diterima, sequence_number: {packet['sequence_number']}")

    def decrypt_packet(self, packet):
        mode = packet["mode"]

        if mode == "RSA":
            #Dekripsi session key pakai private key RSA
            session_key = decrypt_session_key(private_key, packet["encrypted_session_key"])

        elif mode == "ECC":
            #Derive session key dari ephemeral public key gateway
            ephem_pub_bytes = bytes.fromhex(packet["ephemeral_public_key"])
            ephem_pub = public_key_from_bytes(ephem_pub_bytes)
            session_key = derive_session_key(server_private_key, ephem_pub)

        #Dekripsi data sensor pakai AES-GCM
        #Tag diverifikasi otomatis, kalau invalid -> InvalidTag
        try:
            plaintext = decrypt(
                session_key,
                packet["nonce"],
                packet["ciphertext"],
                packet["tag"]
            )
            return json.loads(plaintext.decode())
        except InvalidTag:
            print("Ciphertext ditolak! Tag tidak valid.")
            return None

    def status(self):
        status = "ONLINE" if self.is_online else "OFFLINE"
        print(f"Server: {status} | Data tersimpan: {len(self.storage)} paket")

if __name__ == "__main__":
    from gateway import encrypt_rsa, encrypt_ecc, send_to_server, data_json
    from rsa import public_key
    from ecc import server_public_key
    server = Server()
    print("TEST MODE RSA")
    packet_rsa = encrypt_rsa(data_json, public_key)
    send_to_server(server, packet_rsa, "RSA")
    hasil_rsa = server.decrypt_packet(server.storage[-1])
    print(f"Dekripsi RSA berhasil:")
    print(f"sensor_id: {hasil_rsa['sensor_id']}")
    print(f"temperature: {hasil_rsa['temperature']}°C")
    print(f"soil_ph: {hasil_rsa['soil_ph']}")
    print()
    print("TEST MODE ECC")
    packet_ecc = encrypt_ecc(data_json, server_public_key)
    send_to_server(server, packet_ecc, "ECC")
    hasil_ecc = server.decrypt_packet(server.storage[-1])
    print(f"Dekripsi ECC berhasil:")
    print(f"sensor_id: {hasil_ecc['sensor_id']}")
    print(f"temperature: {hasil_ecc['temperature']}°C")
    print(f"soil_ph: {hasil_ecc['soil_ph']}")
    print()
    server.status()