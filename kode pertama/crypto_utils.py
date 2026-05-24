# crypto_utils.py
# Jalankan sekali untuk generate semua key: python crypto_utils.py

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os

os.makedirs("keys", exist_ok=True)


def generate_rsa_keys():
    """Generate dan simpan pasangan kunci RSA-2048"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    with open("keys/rsa_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("keys/rsa_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[OK] RSA keys generated -> keys/rsa_private.pem & keys/rsa_public.pem")


def generate_ecc_keys():
    """Generate dan simpan pasangan kunci ECC mode menggunakan X25519 (Curve25519)"""
    private_key = X25519PrivateKey.generate()
    with open("keys/ecc_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("keys/ecc_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[OK] ECC keys (X25519/Curve25519) generated -> keys/ecc_private.pem & keys/ecc_public.pem")


if __name__ == "__main__":
    generate_rsa_keys()
    generate_ecc_keys()
    print("\nSemua key berhasil di-generate!")
    print("Key yang dibuat:")
    print("  - RSA-2048              : keys/rsa_private.pem, keys/rsa_public.pem")
    print("  - ECC X25519/Curve25519 : keys/ecc_private.pem, keys/ecc_public.pem")
    print("\nPENTING: Jangan commit folder keys/ ke repository publik!")
