#waaah ya Allah, beneran ga tau ini apa
#---NANTI DIPELAJARIN---#

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#Pasangan kunci ECC
server_private_key = X25519PrivateKey.generate()
server_public_key = server_private_key.public_key()

#Serialisasi public key ke bytes supaya bisa dikirim ke server
#Karna ini dalam bentuk memori Python doang
def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw
    )

#Deserialisasi public key dari bytes
#Soalnya hasil serialisasi itu cuma angka mentah yang belum bisa langsung dipakai ECDH
#Harus diubah balik ke objek, jadi nanti panggil aja objeknya yang udah disimpan
def public_key_from_bytes(key_bytes):
    return X25519PublicKey.from_public_bytes(key_bytes)

def derive_session_key(private_key, peer_public_key):
    #ECDH -> shared secret
    #X25519 = key agreement, bukan enkripsi
    shared_secret = private_key.exchange(peer_public_key)
    #HKDF -> session key AES
    #Proses shared secret supaya jadi key AES yang proper
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"smart-agriculture-session-key"
    ).derive(shared_secret)
    return session_key

#Ephemeral key
ephemeral_private = X25519PrivateKey.generate()
ephemeral_public = ephemeral_private.public_key()
session_key_gateway = derive_session_key(ephemeral_private, server_public_key)
ephemeral_public_bytes = public_key_to_bytes(ephemeral_public)
ephemeral_public_recovered = public_key_from_bytes(ephemeral_public_bytes)
session_key_server = derive_session_key(server_private_key, ephemeral_public_recovered)

#Cek sama atau engga untuk verifikasi session key
print(f"Session key sama: {session_key_gateway == session_key_server} ✅")
print(f"Panjang kunci: {len(session_key_gateway) * 8} bit")