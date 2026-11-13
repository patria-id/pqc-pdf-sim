# pqc-pdf-sim

Simulasi untuk membandingkan tanda tangan elektronik pada dokumen PDF antara RSA dan algoritma
post-quantum: **RSA-2048, RSA-3072, ML-DSA-44, ML-DSA-65, SLH-DSA-SHA2-128s, dan SLH-DSA-SHA2-128f**.
Script mengukur waktu, CPU, dan memori untuk operasi kriptografi, penandatanganan PDF, dan verifikasi
PDF, serta pertambahan ukuran berkas setelah ditandatangani. Semua hasil ditulis ke CSV.

Profil sertifikat meniru pola umum PKI tanda tangan elektronik: CA dua tingkat (CA + pemilik),
SHA-256, keyUsage *digitalSignature* + *nonRepudiation*. Semua berjalan lokal dengan kunci dan CA
simulasi, tanpa koneksi ke layanan mana pun.

> **Kunci dan sertifikat di sini hanya untuk simulasi.** Jangan dipakai untuk menandatangani dokumen
> sungguhan.

## Kebutuhan

- **Python 3.11+** (dikembangkan dengan Python 3.13).
- **OpenSSL 3.5 atau lebih baru**, lengkap dengan CLI `openssl` dan pustaka `libcrypto`. Versi 3.5
  adalah versi pertama yang mendukung ML-DSA dan SLH-DSA secara native.
  - Windows: misalnya *Win64 OpenSSL* dari Shining Light Productions (edisi *Light* sudah cukup),
    terpasang di `C:\Program Files\OpenSSL-Win64`.
  - Linux/macOS: OpenSSL 3.5+ dari paket distribusi atau hasil build sendiri. Atur
    `tools.libcrypto_path` di `config.yaml` bila `libcrypto` tidak berada di folder yang sama dengan
    `openssl`.
- Diuji di Windows 11 (Intel Core i7-10510U, OpenSSL 3.5.9). Platform lain belum diuji.

## Instalasi

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt     # Windows
# .venv/bin/python -m pip install -r requirements.txt       # Linux/macOS
```

Sesuaikan `tools.openssl_bin` (dan bila perlu `tools.libcrypto_path`) di `config.yaml`, lalu cek
lingkungan:

```bash
.venv/Scripts/python -m src.common.env_check --config config.yaml
```

Status `OK` berarti keenam algoritma bisa dijalankan dengan satu backend (`openssl-ctypes`) dan jalur
CMS-nya sudah teruji. Laporan lengkapnya ditulis ke `results/env_report.json`. Kode keluar 2 berarti
ada yang belum siap; alasannya tercantum di bagian `blockers`.

Contoh perintah di bawah memakai `.venv/Scripts/python` (Windows). Di Linux/macOS, ganti dengan
`.venv/bin/python`.

## Menjalankan

### Uji cepat (sekitar 2 menit)

```bash
.venv/Scripts/python -m src.run_all --config config.yaml --smoke
```

Mode `--smoke` memakai 5 iterasi dan PDF 100 KB saja. Hasilnya ditulis ke `results/smoke/` dan
`signed/smoke/`, terpisah dari hasil run penuh.

### Run penuh

```bash
.venv/Scripts/python -m src.run_all --config config.yaml
.venv/Scripts/python -m src.analyze --config config.yaml
```

`run_all` menjalankan tahap berikut secara berurutan:

| Tahap | Script | Isi |
|---|---|---|
| 0 | `src.common.env_check` | Cek OpenSSL, backend, dan jalur CMS untuk setiap algoritma |
| – | `src.generate_pdfs` | Membuat PDF sampel (dilewati bila sudah ada di `pdf/`) |
| – | `src.build_pki` | Membuat CA dan sertifikat pemilik per algoritma di `certs/` (dilewati bila sudah ada) |
| S1 | `src.bench_crypto` | Waktu keygen, sign, dan verify murni (pesan 32 byte) |
| S2 | `src.sign_pdf` | Waktu tanda tangan PDF end-to-end, CPU%, dan RSS puncak |
| S3 | `src.verify_pdf` | Waktu verifikasi PDF end-to-end, CPU%, RSS puncak, dan status valid |
| S4 | `src.measure_size` | Pertambahan ukuran PDF setelah ditandatangani |

Dengan `iterations: 1000`, run penuh memakan sekitar **2,2 jam** di laptop uji (S1 sekitar 31 menit,
S2 sekitar 85 menit, S3 sekitar 11 menit). Sebagian besar waktunya habis untuk SLH-DSA-SHA2-128s,
yang butuh sekitar 1,2 detik untuk satu tanda tangan.

Setiap script juga bisa dijalankan sendiri, misalnya untuk mengulang satu skenario saja:

```bash
.venv/Scripts/python -m src.generate_pdfs --config config.yaml
.venv/Scripts/python -m src.build_pki --config config.yaml
.venv/Scripts/python -m src.bench_crypto --config config.yaml
.venv/Scripts/python -m src.sign_pdf --config config.yaml
.venv/Scripts/python -m src.verify_pdf --config config.yaml
.venv/Scripts/python -m src.measure_size --config config.yaml
```

Opsi yang tersedia:

| Opsi | Berlaku untuk | Arti |
|---|---|---|
| `--smoke` | semua kecuali `build_pki` | Iterasi sedikit, PDF terkecil saja, hasil ke subfolder `smoke/` |
| `--only <id>` | semua kecuali `generate_pdfs`, `analyze` | Hanya satu algoritma, misalnya `--only mldsa44` |
| `--force` | semua kecuali `analyze` | Ukur atau buat ulang walau hasilnya sudah ada. Di `run_all`, hanya S1–S4 yang diulang |
| `--allow-noisy` | `run_all`, S1–S3 | Tetap jalan walau pemeriksaan pra-run gagal (tercatat di metadata) |
| `--check` | `verify_pdf` | Verifikasi sekali semua PDF di `signed/`, tanpa pengukuran |

Hasil yang sudah ada tidak ditimpa tanpa `--force`. Algoritma atau ukuran yang belum ada akan diukur
dan digabungkan ke CSV yang sama.

Kode keluar `run_all`: 0 berhasil, 2 `env_check` gagal, 3 pemeriksaan pra-run gagal, 4 ada tanda
tangan yang tidak valid di S3.

### Sebelum run penuh

Pengukuran waktu sensitif terhadap kondisi laptop. Sebelum run penuh:

1. Colok laptop ke listrik dan pilih mode daya performa tertinggi (Windows 11: *Settings → System →
   Power & battery → Power mode → Best performance*).
2. Tutup aplikasi lain dan jangan pakai laptop selama run berlangsung.
3. Jangan tutup layar laptop, dan pastikan laptop tidak masuk mode tidur selama run.

S1–S3 memeriksa kondisi ini sendiri sebelum mulai: daya listrik, mode daya, dan beban CPU latar
(batasnya `bench.max_background_load_pct`). Bila belum memenuhi syarat, run berhenti dengan kode 3.
Selama pengukuran, proses dijalankan dengan prioritas tinggi dan dipasang ke satu inti CPU
(`bench.cpu_affinity`). Iterasi juga dibagi ke beberapa ronde dengan urutan algoritma yang diacak,
supaya gangguan sesaat tersebar merata ke semua algoritma. Beban CPU dan frekuensi per potongan ronde
dicatat di berkas `*_meta.json`.

### Analisis

```bash
.venv/Scripts/python -m src.analyze --config config.yaml            # hasil penuh
.venv/Scripts/python -m src.analyze --config config.yaml --smoke    # hasil smoke
```

`analyze` membaca CSV yang ada, lalu menulis statistik deskriptif, uji signifikansi, tabel Markdown,
dan grafik PNG. Skenario yang CSV-nya belum ada akan dilewati.

## Keluaran

Semua berkas keluaran dibuat ulang oleh script dan tidak disimpan di repo.

| Berkas | Dibuat oleh | Kolom / isi |
|---|---|---|
| `results/env_report.json` | `env_check` | Versi OpenSSL, backend per algoritma, hasil uji CMS |
| `results/system_info.json` | `run_all` | OS, CPU, RAM, mode daya, versi Python, OpenSSL, dan library |
| `results/pdf_inventory.csv` | `generate_pdfs` | `pdf_name, target_kb, actual_bytes, pages, sha256` |
| `results/cert_sizes.csv` | `build_pki` | `alg, ca_alg, ca_cert_der_bytes, user_cert_der_bytes, chain_der_bytes, user_pubkey_bytes, ca_pubkey_bytes` |
| `results/s1_crypto.csv` | `bench_crypto` | `alg, operation, iteration, time_ns, signature_bytes` |
| `results/s2_sign.csv` | `sign_pdf` | `alg, pdf_name, iteration, time_ns, cpu_percent_peak, rss_peak_bytes` |
| `results/s3_verify.csv` | `verify_pdf` | `alg, pdf_name, iteration, time_ns, cpu_percent_peak, rss_peak_bytes, valid` |
| `results/s4_size.csv` | `measure_size` | `alg, pdf_name, original_bytes, signed_bytes, delta_bytes, delta_percent, cms_bytes, signature_bytes, chain_bytes, placeholder_bytes, placeholder_used_percent` |
| `results/s*_meta.json` | S1–S4 | Pengaturan run, kondisi lingkungan sebelum/sesudah, beban per potongan ronde |
| `results/summary.csv` | `analyze` | Per skenario, algoritma, dan kelompok: n, median, mean, std, p25/p75/p95 (ms), rasio terhadap RSA-2048, CPU%, RSS |
| `results/significance.csv` | `analyze` | Kruskal–Wallis antar algoritma, lalu Mann–Whitney terhadap RSA-2048 dengan koreksi Holm dan ukuran efek |
| `results/tables_for_paper.md` | `analyze` | Tabel ringkasan dalam bahasa Indonesia |
| `figures/*.png` | `analyze` | 5 grafik (300 dpi) |
| `signed/<alg>_<ukuran>.pdf` | `sign_pdf` | Contoh PDF bertanda tangan dari S2 |
| `signed/fit/<alg>_<ukuran>.pdf` | `measure_size` | PDF bertanda tangan dengan placeholder seukuran CMS (S4) |
| `logs/run_<YYYYMMDD_HHMM>.log` | `run_all` | Log lengkap satu kali run |

Keterangan kolom:

- `time_ns`: waktu satu iterasi dalam nanodetik, diukur di dalam proses dengan
  `time.perf_counter_ns()`. Iterasi warm-up tidak dicatat.
- `operation` (S1): `keygen`, `sign`, atau `verify`. Untuk `keygen`, kolom `signature_bytes` kosong.
- `cpu_percent_peak`: CPU% proses relatif terhadap satu inti logis, nilai puncak pada sub-jendela
  minimal 250 ms. Di Windows, waktu CPU dihitung per sekitar 15,6 ms, sehingga angka per iterasi
  untuk operasi singkat hanya bermakna sebagai rata-rata banyak iterasi.
- `rss_peak_bytes`: RSS puncak seluruh proses Python (termasuk library dan PDF yang dimuat).
- `valid` (S3): `True` bila ByteRange, `messageDigest`, rantai sertifikat ke CA simulasi, dan
  signature CMS semuanya benar.
- `placeholder_bytes` (S4): kapasitas `/Contents` dalam byte DER. String heksadesimal di berkas
  panjangnya dua kali lipat.
- `chain_bytes` (S4): ukuran DER semua sertifikat di dalam CMS (pemilik + CA).

## Metode singkat

- **Backend tunggal.** Semua operasi kunci publik untuk keenam algoritma, baik pemilik maupun CA,
  dipanggil lewat `libcrypto` OpenSSL 3.5+ dengan `ctypes` (`EVP_DigestSign`/`EVP_DigestVerify`).
  RSA memakai PKCS#1 v1.5 + SHA-256. ML-DSA dan SLH-DSA memakai mode murni dengan konteks kosong.
  CLI `openssl` hanya dipakai untuk membuat kunci dan sertifikat, tidak untuk pengukuran.
- **CMS.** Tanda tangan PDF berupa CMS SignedData *detached* (`adbe.pkcs7.detached`). Isinya
  signedAttrs (contentType, messageDigest SHA-256, signingTime) dan sertifikat pemilik + CA,
  disusun dengan `asn1crypto`. OID algoritma mengikuti RFC 9882 (ML-DSA) dan RFC 9814 (SLH-DSA).
  pyHanko menyiapkan PDF (field, placeholder, ByteRange). Jalur yang sama dipakai untuk RSA dan
  post-quantum, sehingga waktunya sebanding.
- **S2** memakai placeholder tetap (`signature_placeholder_bytes`) untuk semua algoritma. **S4**
  menandatangani ulang setiap PDF dengan placeholder seukuran CMS + 256 byte
  (`measure_size.placeholder_mode: fit`), sehingga pertambahan ukuran berkas mencerminkan
  algoritmanya.
- **Verifikasi PDF.** PDF RSA bisa diverifikasi di pyHanko maupun pembaca PDF umum (CA-nya akan
  tampil tidak tepercaya). PDF ML-DSA dan SLH-DSA belum tentu dikenali pembaca PDF umum. Gunakan
  `python -m src.verify_pdf --check` untuk memverifikasinya.

## PDF sampel

Folder `pdf/` berisi tiga PDF sampel tanpa tanda tangan: dokumen fiktif berisi kop surat, data
identitas, paragraf teks, dan tabel nilai, ditambah gambar acak untuk mencapai ukuran target.

| Berkas | Ukuran | Halaman | SHA-256 |
|---|---:|---:|---|
| `sample_100kb.pdf` | 103.130 B | 4 | `6aebc54a9d19b230b39b6e0e1df5cf9478782c6aa6ad5bc1f591fb7dde8624c8` |
| `sample_1mb.pdf` | 1.041.513 B | 4 | `76f1be43cd0e101d741498b1c86159fd982a09d5f5500e3c1cbbfc69df0baed8` |
| `sample_10mb.pdf` | 10.419.748 B | 10 | `2ca178531fac5786b7c8b02e0585fed46a6a1e27f2202bd8aa8c6aad2369f184` |

PDF dibuat secara deterministik (`seed: 42`) dengan `src.generate_pdfs`. Untuk membuatnya ulang:

```bash
.venv/Scripts/python -m src.generate_pdfs --config config.yaml --force
```

Versi reportlab atau Pillow yang berbeda bisa menghasilkan byte yang sedikit berbeda. Untuk hasil
yang sebanding, pakai PDF yang disertakan di repo.

## Konfigurasi

Semua parameter ada di `config.yaml`; script tidak berisi path, nama algoritma, atau jumlah iterasi
yang ditanam di kode.

| Kunci | Isi |
|---|---|
| `seed`, `iterations`, `warmup`, `smoke_iterations` | Seed acak dan jumlah iterasi run penuh / smoke |
| `pdf_sizes_kb` | Ukuran PDF sampel (KB) |
| `algorithms` | ID algoritma → algoritma pemilik, algoritma CA, dan keluarga |
| `cert_profile` | Negara, organisasi, masa berlaku CA dan pemilik |
| `paths` | Folder `pdf`, `certs`, `signed`, `results`, `figures`, `logs` |
| `crypto_backend` | Backend pengukuran (`openssl-ctypes`; alternatif `cryptography` atau `liboqs-python`) |
| `tools` | Lokasi CLI `openssl`, `libcrypto`, dan liboqs |
| `bench` | Ronde, warm-up per potongan, GC, prioritas proses, afinitas CPU, batas beban latar |
| `sign_pdf`, `verify_pdf` | Nama field tanda tangan, interval sampler CPU/RSS |
| `measure_size` | Mode placeholder S4 (`fit` atau `fixed`) dan marginnya |
| `analyze` | Algoritma pembanding, α, dpi, warna grafik |

## Struktur

```
pqc-pdf-sim/
├── config.yaml
├── requirements.txt
├── pdf/                 # PDF sampel tanpa tanda tangan
├── src/
│   ├── common/          # config, backend kripto (ctypes OpenSSL), CMS, PKI, monitor, CSV
│   ├── generate_pdfs.py
│   ├── build_pki.py
│   ├── bench_crypto.py  # S1
│   ├── sign_pdf.py      # S2
│   ├── verify_pdf.py    # S3
│   ├── measure_size.py  # S4
│   ├── run_all.py
│   └── analyze.py
└── tests/               # pytest
```

Folder `certs/`, `results/`, `signed/`, `figures/`, dan `logs/` dibuat saat script dijalankan.
`certs/` berisi kunci privat simulasi dan tidak boleh di-commit.

## Pengujian

```bash
.venv/Scripts/python -m pytest -q
```

Sekitar 3 menit. Tes membuat PDF, PKI, dan hasil di folder sementara, sehingga tidak menyentuh
`results/`. Termasuk di dalamnya uji negatif: PDF yang diubah 1 byte, signature yang diubah, CA yang
salah, atau algoritma yang salah harus menghasilkan `valid=False`.
