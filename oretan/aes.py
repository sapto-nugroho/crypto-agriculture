#ya Allah mau seblak

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

#Buat kunci secara random
#32 bytes = AES-256 bit
key = os.urandom(32)

#Iseng aja mau print hasil key randomnya mwehehe
print(key.hex())

#2 task AES-GCM:
#Enkripsi data - supaya plaintext ga bisa dibaca
#Buat tag - u/ cek apakah adversary ada ngubah ciphertext di tengah jalan atau engga (Man in The Middle)
#Karena ada tag, alhasil jadi IND-CCA 
# IND-CCA: walaupun adversary dikasih fungsi u/ dekrip, tetap ga bisa bedain mana plaintext(?)

#Enkripsi
def encrypt(key, plaintext):
    #Number used ONCE, untuk memastikan ciphertext yang dihasil beda2
    #IND-CPA secure: adversary bingung mana yg plaintext asli
    #Intinya nanti si nonce ini bakal diconcate (gabung) dengan key
    #IGO MWOYAAAAA AAAAA
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    #Tag: untuk cek apakah data diutak-atik oleh adversary
    #Hasil ciphertext_tag = ct + tag, sheesh idk, lemme check later
    #but claude said that the result of aesgcm will be the combination of ciphertext + tag
    ciphertext_tag = aesgcm.encrypt(nonce, plaintext, None)
    #Pisahkan ciphertext dan tag
    ciphertext = ciphertext_tag[:-16] #buang yg 16 terakhir karna itu tag
    tag = ciphertext_tag[-16:]
    #Return dalam bentuk heksa
    return{
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }

#Dekripsi
def decrypt(key, nonce_decrypt, ciphertext_decrypt, tag_decrypt):
    nonce = bytes.fromhex(nonce_decrypt)
    ciphertext = bytes.fromhex(ciphertext_decrypt)
    tag = bytes.fromhex(tag_decrypt)
    aesgcm = AESGCM(key)
    #Di dalam dekripsi ada verifikasi tag
    #Kalau tag tidak valid, nanti InvalidTag (oh god, wait a minute...)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return plaintext