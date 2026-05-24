# Smart Agriculture Monitoring — Sistem Kriptografi
**Tugas Proyek Akhir Kriptologi**
Implementasi Hybrid Encryption: RSA-OAEP + AES-GCM dan X25519-HKDF + AES-GCM

---

## Arsitektur Sistem

```
Sensor Simulator → Edge Gateway → Server
                        ↕
                  gateway_buffer/  (saat server mati)
```

### Alur Key Distribution (Lebih Realistis)

```
1. Server start → generate RSA & ECC keys → simpan di keys/
2. Server expose public key via:
     GET /public-key/rsa
     GET /public-key/ecc
3. Gateway start → fetch public key dari server → simpan di gateway_keys/
4. Gateway gunakan public key untuk enkripsi
5. Server gunakan private key untuk dekripsi
```

Private key **tidak pernah meninggalkan server**.

---

## Struktur Folder

```
smart_agriculture/
├── server.py             # Server: generate key, expose public key, dekripsi
├── gateway.py            # Gateway: fetch key, enkripsi, buffer
├── sensor.py             # Sensor: generate & kirim data JSON
├── experiment.py         # Eksperimen kinerja end-to-end
├── security_analysis.py  # Analisis IND-CPA & IND-CCA
├── decrypt_storage.py    # Dekripsi manual server_storage/
├── verify_integrity.py   # Cocokkan sensor_logs/ vs server_storage/
├── requirements.txt
├── .gitignore
├── keys/                 # Private key server (auto-generate, JANGAN commit)
├── gateway_keys/         # Public key hasil fetch (auto-fetch)
├── server_storage/       # Ciphertext diterima server (runtime)
├── gateway_buffer/       # Buffer ciphertext saat server mati (runtime)
├── sensor_logs/          # Log plaintext sensor harian (runtime)
└── decrypted_output/     # Hasil dekripsi manual (runtime)
```

---

## Instalasi

```bash
#pakai bash
python -m venv venv #buat virtual env
source venv/scripts/activate #aktivasi virtual env dulu
pip install -r requirements.txt #install packages
```

---

## Cara Menjalankan

### Urutan WAJIB diikuti:

**Terminal 1 — Server (jalankan PERTAMA):**
```bash
python server.py
```
Server akan otomatis generate key RSA & ECC saat pertama kali dijalankan.

**Terminal 2 — Gateway (jalankan SETELAH server):**
```bash
python gateway.py
```
Gateway akan otomatis fetch public key dari server.

**Terminal 3 — Sensor:**
```bash
python sensor.py
```

### Mengganti Mode:
Edit `sensor.py`:
```python
MODE = "ECC"   # atau "RSA"
```

---

## Eksperimen

```bash
# Terminal 1: python server.py
# Terminal 2: python gateway.py
# Terminal 3:
python experiment.py         # kinerja end-to-end (~10 menit)
python security_analysis.py  # IND-CPA & IND-CCA
python verify_integrity.py   # cocokkan historis
python decrypt_storage.py    # dekripsi manual semua file
python decrypt_storage.py server_storage/packet_xxx.json  # satu file
```

---

## Konstruksi Kriptografi

### RSA Mode
```
K  ← random(256-bit)
CK = RSA-OAEP(pkServer, K)
CM, tag = AES-256-GCM(K, nonce, M)
Paket = (CK, nonce, CM, tag)
```

### ECC Mode (X25519)
```
(epk, esk) ← X25519.generate()
S  = X25519(esk, pkServer)
K  = HKDF-SHA256(S)
CM, tag = AES-256-GCM(K, nonce, M)
Paket = (epk, nonce, CM, tag)
```

---

## Requirements Terpenuhi

| Kode | Status |
|------|--------|
| REQ-F1 ~ REQ-F7 | ✓ |
| REQ-S1 ~ REQ-S5 | ✓ |
| REQ-R1 ~ REQ-R6 | ✓ |
| REQ-E1 ~ REQ-E7 | ✓ |
| REQ-A1 ~ REQ-A4 | ✓ |


| Kode | Status | Deskripsi |
|------|--------|-----------|
| REQ-F1 | ✓ | Sensor simulator menghasilkan data JSON |
| REQ-F2 | ✓ | Gateway mengenkripsi sebelum kirim |
| REQ-F3 | ✓ | Server menerima dan menyimpan ciphertext |
| REQ-F4 | ✓ | Dua mode: RSA dan ECC |
| REQ-F5 | ✓ | Server menyimpan ciphertext, bukan plaintext |
| REQ-F6 | ✓ | Dapat dekripsi ciphertext valid |
| REQ-F7 | ✓ | Ciphertext dimodifikasi → ditolak (InvalidTag) |
| REQ-S1 | ✓ | AES-GCM untuk enkripsi data sensor |
| REQ-S2 | ✓ | AES-256-GCM (256-bit key) |
| REQ-S3 | ✓ | Nonce 96-bit random unik tiap enkripsi |
| REQ-S4 | ✓ | Tag diverifikasi sebelum plaintext dikeluarkan |
| REQ-S5 | ✓ | Tag tidak valid → plaintext tidak dikeluarkan |
| REQ-R1 | ✓ | Server memiliki pasangan kunci RSA |
| REQ-R2 | ✓ | RSA-2048 bit |
| REQ-R3 | ✓ | RSA-OAEP digunakan (bukan textbook RSA) |
| REQ-R4 | ✓ | Session key dilindungi RSA-OAEP |
| REQ-R5 | ✓ | Data sensor tidak dienkripsi langsung RSA |
| REQ-R6 | ✓ | RSA hanya untuk enkripsi session key |
| REQ-E1 | ✓ | Server memiliki pasangan kunci ECC |
| REQ-E2 | ✓ | ECDH (SECP256R1) untuk shared secret |
| REQ-E3 | ✓ | Gateway menggunakan ephemeral key |
| REQ-E4 | ✓ | Shared secret tidak langsung jadi kunci AES |
| REQ-E5 | ✓ | HKDF-SHA256 untuk turunkan session key |
| REQ-E6 | ✓ | Kunci hasil HKDF digunakan sebagai kunci AES-GCM |
| REQ-A1 | ✓ | Server aktif → langsung kirim |
| REQ-A2 | ✓ | Server mati → simpan ke file lokal |
| REQ-A3 | ✓ | Server aktif lagi → kirim ulang buffer |
| REQ-A4 | ✓ | Laporan: sent, buffered, retry_sent |

---
