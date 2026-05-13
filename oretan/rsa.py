import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

#Panjang key RSA minimal 2048
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 2048
)
public_key = private_key.public_key()

#Iseng lagi mau print ukuran kunci
print(f"Key size of RSA: {private_key.key_size} bit")
#Ngoghey udah 2048 bit

#Enkripsi key AES dengan RSA-OAEP (jesus christ)
#Kata claude konsepnya pakai random padding (what is f going on rn)
#Alhasil nanti hasil enkripsinya beda2 (IND-CPA secure, OH MY GODNESS I'M XOOOO TIRED RN, still in puskot, nevermind)
#Textbook RSA: deterministik sehingga tidak IND-CPA, imo
#Astaghfirullahaladzim 33x
def encrypt_session_key(public_key, session_key):
    encrypted = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #Return dalam bentuk heksa
    return encrypted.hex()

# Dekripsi session key pakai private key server (bwabwabwa - rabbids invasion, kelinci plenger)
def decrypt_session_key(private_key, encrypted_key_hex):
    encrypted = bytes.fromhex(encrypted_key_hex)
    session_key = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key