import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

#Panjang key RSA minimal 2048
#FIX: Keypair disimpan ke file .pem supaya gateway dan server pakai kunci yang SAMA
#Kalau generate ulang tiap import, gateway enkripsi pakai public key A, server dekripsi pakai private key B -> gagal
KEY_FILE = "rsa_private_key.pem"

if os.path.exists(KEY_FILE):
    #Load keypair yang sudah ada
    with open(KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
else:
    #Generate keypair baru, simpan ke file
    private_key = rsa.generate_private_key(
        public_exponent = 65537, #rumusnya rsa (katanya)
        key_size = 2048
    )
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

public_key = private_key.public_key()

#Enkripsi key AES dengan RSA-OAEP (jesus christ)
#Kata claude konsepnya pakai random padding (?)
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

if __name__ == "__main__":
    #Iseng lagi mau print ukuran kunci (Note: testing aja)
    print(f"Key size of RSA: {private_key.key_size} bit")
    #Ngoghey udah 2048 bit