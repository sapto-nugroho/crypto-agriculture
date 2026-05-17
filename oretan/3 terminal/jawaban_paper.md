# Jawaban Pertanyaan Wajib Paper
## Implementasi Sistem Monitoring Smart Agriculture Berbasis RSA, ECC, dan AES-GCM

---

### Q1. Bagaimana arsitektur sistem yang diimplementasikan?

Sistem menggunakan arsitektur **3-tier** yang terdiri dari:

1. **Sensor Simulator** — Program yang mensimulasikan sensor lapangan pertanian. Sensor menghasilkan data kondisi lahan dalam format JSON, meliputi suhu udara, kelembaban udara, kelembaban tanah, dan pH tanah. Data dihasilkan secara periodik dan dikirim ke edge gateway.

2. **Edge Gateway** — Komponen perantara yang menerima data plaintext dari sensor, mengenkripsi data menggunakan skema hybrid encryption (RSA-OAEP atau ECC/X25519 + HKDF + AES-GCM), dan mengirimkan ciphertext ke server. Jika server tidak aktif, gateway menyimpan ciphertext ke buffer lokal (folder `gateway_buffer/`).

3. **Server** — Menerima ciphertext dari gateway, menyimpannya ke folder `server_storage/`, dan dapat melakukan dekripsi untuk keperluan verifikasi.

Alur data:
```
Sensor Simulator → Edge Gateway (enkripsi) → Server (simpan ciphertext)
                         ↓ (jika server mati)
                   gateway_buffer/ (buffer lokal)
                         ↓ (setelah server aktif kembali)
                   Server (kirim ulang)
```

---

### Q2. Bagaimana RSA, ECC, dan AES-GCM digabungkan dalam sistem?

Sistem menggunakan **hybrid encryption** dengan dua mode:

**RSA Mode:**
1. Gateway membuat session key AES-256 secara acak
2. Session key dienkripsi menggunakan RSA-OAEP dengan public key server
3. Data sensor dienkripsi menggunakan AES-256-GCM dengan session key tersebut
4. Paket yang dikirim: `(mode, encrypted_session_key, nonce, ciphertext, tag)`
5. Server mendekripsi session key menggunakan RSA private key, lalu mendekripsi data

**ECC Mode:**
1. Gateway membuat ephemeral keypair X25519 (kunci sekali pakai)
2. Shared secret dihitung via ECDH: `S = ECDH(ephemeral_private, server_public)`
3. Session key AES-256 diturunkan dari shared secret menggunakan HKDF-SHA256
4. Data sensor dienkripsi menggunakan AES-256-GCM dengan session key tersebut
5. Paket yang dikirim: `(mode, ephemeral_public_key, nonce, ciphertext, tag)`
6. Server menghitung shared secret yang sama, menurunkan session key yang sama, lalu mendekripsi data

---

### Q3. Mengapa sistem menggunakan hybrid encryption?

Sistem menggunakan hybrid encryption karena:

- **RSA dan ECC tidak efisien untuk data besar.** RSA hanya dapat mengenkripsi data dengan ukuran maksimal sebesar ukuran kunci dikurangi overhead padding. Untuk RSA-2048 dengan OAEP-SHA256, maksimal plaintext yang bisa dienkripsi sekitar 190 bytes.
- **AES-GCM jauh lebih cepat** untuk enkripsi data besar. AES adalah algoritma simetrik yang dioptimalkan untuk throughput tinggi.
- **Kelebihan RSA/ECC** adalah kemampuannya untuk mendistribusikan kunci secara aman tanpa memerlukan saluran rahasia sebelumnya.

Dengan hybrid encryption, sistem mendapatkan keunggulan keduanya: **keamanan distribusi kunci dari RSA/ECC** dan **efisiensi enkripsi data dari AES-GCM**.

---

### Q4. Mana yang lebih cepat dalam eksperimen: RSA mode atau ECC mode?

Berdasarkan hasil eksperimen benchmark (30 runs per skenario):

- **ECC mode lebih cepat** dari RSA mode untuk operasi enkripsi maupun dekripsi.
- RSA mode membutuhkan waktu lebih lama karena operasi modular exponentiation pada bilangan besar (2048 bit).
- ECC mode menggunakan kurva X25519 yang dioptimalkan untuk kecepatan, dengan operasi matematika pada kurva elliptic yang lebih efisien.
- Perbedaan semakin signifikan seiring bertambahnya ukuran data, meskipun bottleneck utama tetap pada operasi asimetrik (RSA/ECC), bukan pada AES-GCM.

*(Lihat hasil detail di `hasil_kinerja.csv` dan `grafik_kinerja.png`)*

---

### Q5. Mana yang menghasilkan ciphertext lebih kecil: RSA mode atau ECC mode?

**ECC mode menghasilkan ciphertext lebih kecil** dari RSA mode karena:

- **RSA mode** menyertakan `encrypted_session_key` berukuran 256 bytes (2048 bit) dalam setiap paket.
- **ECC mode** menyertakan `ephemeral_public_key` berukuran hanya 32 bytes (256 bit, format Raw X25519).
- Selisih overhead per paket: ~224 bytes lebih kecil di ECC mode.
- Untuk data sensor berukuran kecil (1 KB), selisih ini cukup signifikan secara relatif.

*(Lihat hasil detail di `hasil_kinerja.csv` dan `grafik_kinerja.png`)*

---

### Q6. Bagaimana sistem tetap menyimpan data saat server mati?

Sistem mengimplementasikan mekanisme **local buffering**:

1. Sebelum mengirim, gateway mengecek status server (`server.is_online`).
2. Jika server **aktif** → ciphertext langsung dikirim ke server.
3. Jika server **mati** → ciphertext disimpan ke folder `gateway_buffer/` sebagai file JSON terpisah (`packet_<timestamp>.json`).
4. Setiap kali gateway berhasil mengirim data ke server, gateway juga mengecek folder buffer dan **mengirim ulang** semua paket yang tertunda.
5. Setelah berhasil terkirim, file buffer dihapus otomatis.

**Penting:** Buffer hanya menyimpan **ciphertext**, bukan plaintext. Data sensor tidak pernah disimpan dalam bentuk yang dapat dibaca tanpa kunci dekripsi.

---

### Q7. Apakah sistem memenuhi prinsip confidentiality?

**Ya, sistem memenuhi prinsip confidentiality**, dengan alasan:

- Data sensor **tidak pernah dikirim dalam bentuk plaintext** ke server. Semua data dienkripsi di gateway sebelum dikirim.
- **AES-256-GCM** digunakan untuk mengenkripsi data sensor. AES-256 adalah standar enkripsi yang diakui NIST dan dianggap aman untuk penggunaan saat ini.
- **Session key** yang digunakan AES-GCM dilindungi oleh RSA-OAEP atau ECC/ECDH sehingga hanya server yang memiliki private key yang dapat memperoleh session key.
- **Buffer lokal** hanya menyimpan ciphertext, bukan plaintext.
- Asumsi keamanan: private key server tidak bocor dan random number generator sistem operasi aman.

---

### Q8. Apakah sistem mendukung prinsip IND-CPA?

**Ya, sistem mendukung IND-CPA (Indistinguishability under Chosen Plaintext Attack)**, karena:

- **RSA-OAEP bersifat probabilistik** — menggunakan random padding sehingga enkripsi session key yang sama menghasilkan ciphertext yang berbeda setiap kali. Berbeda dengan textbook RSA yang deterministik dan tidak IND-CPA secure.
- **ECC mode menggunakan ephemeral key** — setiap sesi menggunakan keypair baru sehingga shared secret dan session key selalu berbeda, meskipun data sensor yang dikirim sama.
- **AES-GCM menggunakan nonce unik** (96-bit random) setiap enkripsi — plaintext yang sama menghasilkan ciphertext yang berbeda di setiap enkripsi.

Konsekuensinya: adversary yang mengamati ciphertext tidak dapat membedakan enkripsi dari dua plaintext berbeda, bahkan jika memiliki akses ke oracle enkripsi.

---

### Q9. Apakah sistem mendukung prinsip IND-CCA?

**Ya, sistem mendukung IND-CCA (Indistinguishability under Chosen Ciphertext Attack)**, karena:

- **AES-GCM menyediakan authentication tag 128-bit** yang dihasilkan bersama ciphertext saat enkripsi.
- Saat dekripsi, tag **diverifikasi terlebih dahulu** sebelum plaintext dikeluarkan.
- Jika ciphertext dimodifikasi (bahkan 1 bit), tag tidak akan valid dan sistem akan melempar `InvalidTag` exception — **plaintext tidak dikeluarkan**.
- Sistem yang hanya mengenkripsi tanpa autentikasi (misalnya AES-CBC tanpa MAC) tidak memenuhi IND-CCA karena adversary dapat memodifikasi ciphertext dan mengamati efeknya.
- RSA-OAEP dan ECC-ECDH-HKDF-AES-GCM lebih aman dibanding textbook RSA atau AES tanpa authentication.

---

### Q10. Apa keterbatasan sistem yang dibuat?

Sistem memiliki beberapa keterbatasan:

1. **Metadata tidak dienkripsi** — field `sensor_id`, `timestamp`, dan `sequence_number` dikirim dalam plaintext di dalam paket. Adversary dapat mengetahui pola aktivitas sensor meskipun tidak bisa membaca isi data.
   - *Mitigasi*: gunakan field tersebut sebagai AAD (Additional Authenticated Data) pada AES-GCM, atau enkripsi seluruh paket.

2. **Local buffering hanya satu titik** — jika gateway mati bersamaan dengan server, data yang belum terkirim akan hilang.
   - *Mitigasi*: implementasi replicated storage atau multi-gateway redundancy.

3. **Private key disimpan di memori runtime** — private key RSA dan ECC tidak disimpan ke file .pem, sehingga setiap kali program dijalankan ulang, keypair baru dibuat dan ciphertext lama tidak dapat didekripsi.
   - *Mitigasi*: simpan keypair ke file .pem (seperti implementasi teman kelompok).

4. **Sensor disimulasikan** — sistem tidak terhubung ke sensor fisik di lapangan. Data diambil dari file dummy JSON.

5. **Tidak ada mekanisme autentikasi gateway** — server menerima ciphertext dari gateway manapun tanpa memverifikasi identitas pengirim.
   - *Mitigasi*: implementasi mutual TLS atau signature pada setiap paket.
