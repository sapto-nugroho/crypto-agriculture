# Smart Agriculture Monitoring — Sistem Kriptografi
**Tugas Proyek Akhir Kriptologi**  
Implementasi Hybrid Encryption (RSA-OAEP + AES-GCM) dan (ECDH + HKDF + AES-GCM)

---

## Struktur Folder

```
crypto agriculture/
├── crypto_utils.py       # Generate RSA & ECC key pair
├── sensor.py             # Simulasi data sensor (JSON) generate secara random
├── gateway.py            # Enkripsi + pengiriman ke server
├── server.py             # Terima, simpan, dan dekripsi ciphertext
├── experiment.py         # Eksperimen kinerja (30 runs)
├── security_analysis.py  # Analisis IND-CPA & IND-CCA
├── verify_integrity.py   # membandingkan data asli sensor dengan hasil dekripsi server untuk membuktikan data tidak berubah
├── decrypt_storage.py    # Dekripsi file pada folder server_storage
├── requirements.txt      # versi package/library
├── keys/                 # Key pair (JANGAN di-commit ke repo publik)
├── server_storage/       # Ciphertext yang diterima server
└── gateway_buffer/       # Buffer ciphertext saat server mati
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

### Langkah 1 — Generate Key (hanya sekali)
```bash
python crypto_utils.py
```

### Langkah 2 — Jalankan di 3 terminal terpisah

**Terminal 1 — Server:**
```bash
python server.py
```

**Terminal 2 — Edge Gateway:**
```bash
python gateway.py
```

**Terminal 3 — Sensor Simulator:**
```bash
python sensor.py
```

### Mengganti Mode (RSA / ECC)
Edit baris berikut di `sensor.py`:
```python
MODE = "ECC"   # atau "RSA"
```

---

## Cara Menjalankan Eksperimen

```bash
# Eksperimen kinerja (enkripsi/dekripsi/throughput)
python experiment.py
# Output: experiment_results.csv, throughput_results.csv

# Analisis keamanan IND-CPA & IND-CCA
python security_analysis.py
```

---

## Eksperimen Availability (Local Buffering)

1. Jalankan server, gateway, dan sensor simulator
2. Biarkan berjalan 30 detik (data langsung terkirim)
3. **Stop server** (Ctrl+C di terminal server)
4. Biarkan berjalan 30 detik (data masuk buffer)
5. **Jalankan kembali** server
6. Gateway otomatis mengirim ulang buffer
7. Cek statistik:
   - Gateway: `http://localhost:5001/stats`
   - Server: `http://localhost:5002/stats`

---

## Dekripsi file pada folder server_storage

### Langsung semua file
```bash
python decrypt_storage.py 
```

### satu file
```bash
python decrypt_storage.py server_storage/packet_1234567.json
```

---

## Konstruksi Kriptografi

### RSA Mode
```
Session Key K ← random(256 bit)
CK = RSA-OAEP(pkServer, K)
CM, tag = AES-256-GCM(K, nonce, M)
Paket = (mode, CK, nonce, CM, tag)
```

### ECC Mode
```
(epk, esk) ← ECC.generate_ephemeral()
S = ECDH(esk, pkServer)
K = HKDF-SHA256(S)
CM, tag = AES-256-GCM(K, nonce, M)
Paket = (mode, epk, nonce, CM, tag)
```

---

## Requirements yang Dipenuhi

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

<!-- ## Anggota Kelompok

| Mahasiswa | Fokus |
|-----------|-------|
| Mahasiswa 1 | RSA-OAEP + Analisis IND-CPA |
| Mahasiswa 2 | ECC (ECDH/HKDF) + Hybrid Encryption |
| Mahasiswa 3 | AES-GCM + Integrity + Availability | -->
