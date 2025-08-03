# 🔥 CyberGuard v9.1 - Pro Gratis Edition 🔥

**Created by:** Ibar - The Pro Free Cyber Legend  
**Warning:** Power tool gratis, gunakan dengan bijak dan bertanggung jawab!

---

## 🧠 Tentang CyberGuard

CyberGuard adalah tool pentest khusus untuk WordPress yang dirancang dengan kekuatan penuh namun tetap gratis. Tool ini mampu melakukan **enumerasi username**, **smart brute-force login**, **XSS testing**, **vulnerability scan**, **fuzzing otomatis**, hingga **generasi laporan PDF** — semua dilakukan secara otomatis dan efisien.

⚠️ **CyberGuard ditujukan untuk edukasi dan pengujian keamanan dengan izin pemilik situs. Jangan gunakan untuk tujuan ilegal.**

---

## 🛠️ Fitur Unggulan

| Fitur | Deskripsi |
|------|-----------|
| 🧾 **WordPress Detector** | Mendeteksi apakah target menggunakan WordPress dan versinya. |
| 👤 **Username Enumeration** | Ekstraksi username lewat `/?author=` dan REST API. |
| 🧠 **Smart Wordlist Generator** | Buat wordlist berbasis domain, meta tag, username, dan data dinamis. |
| 🧠 **Smart Fuzzing Payload** | Payload otomatis untuk uji SQLi, LFI, XSS, dll. |
| 🧪 **Brute Force Login** | Serangan brute-force dengan deteksi CSRF, rate-limit, dan CAPTCHA aware. |
| 🔐 **Sensitive File Scanner** | Cek file penting seperti `wp-config.php`, `.htaccess`, dll. |
| 🔥 **XSS Tester** | Uji titik-titik XSS pada URL umum secara otomatis. |
| 🛡️ **WPScan API Support** | Integrasi dengan WPScan untuk cek CVE & plugin rentan. |
| 📦 **Local Vulnerability DB** | Cek plugin populer yang rentan (offline DB built-in). |
| 🧨 **Zero-Day Fuzzer** | Uji param URL dengan payload pintar untuk celah tersembunyi. |
| 📄 **PDF Report Generator** | Hasil scan disimpan otomatis ke laporan `.pdf` profesional. |
| 🔁 **Multi-target Support** | Bisa scan satu URL atau banyak target sekaligus. |
| 📜 **Log System** | Semua aksi tercatat di file `cyberguard.log`. |

---

## 📦 Instalasi

1. **Clone repository:**

```bash
git clone https://github.com/username/CyberGuard.git
cd CyberGuard
```

2. **Install dependencies:**

Pastikan kamu pakai Python 3.7 atau lebih baru.

```bash
pip install -r requirements.txt
```

### Jika `requirements.txt` tidak tersedia, install manual:

```bash
pip install requests colorama beautifulsoup4 tqdm ratelimit reportlab
```

---

## 🚀 Cara Menjalankan

### Scan 1 Target

```bash
python cyberguard.py https://targetwordpress.com
```

### Scan Banyak Target (dari file txt)

```bash
python cyberguard.py targets.txt
```

**Format `targets.txt`:**
```
https://target1.com
https://target2.com
```

### Dengan Wordlist Eksternal & Payload Fuzzing

```bash
python cyberguard.py https://target.com custom_wordlist.txt custom_fuzz.txt
```

### Tambahkan WPScan API Token (opsional):

```bash
python cyberguard.py https://target.com wordlist.txt fuzz.txt your_wpscan_api_token
```

---

## 📂 Output

- `cyberguard_report_YYYYMMDD_HHMMSS.txt`: Hasil scan lengkap.
- `cyberguard_report_YYYYMMDD_HHMMSS.pdf`: Laporan dalam format PDF.
- `cyberguard.log`: Semua aktivitas dicatat di sini.

---

## 🔐 Legal Disclaimer

CyberGuard hanya boleh digunakan untuk:

- Penetration Testing dengan izin dari pemilik situs.
- Keperluan edukasi dan pembelajaran keamanan siber.
- Bug bounty dan analisis keamanan internal.

**⚠️ Penggunaan tanpa izin adalah pelanggaran hukum. Gunakan dengan penuh tanggung jawab.**

---

## ❤️ Dukungan

Jika kamu suka tool ini, beri bintang ⭐ di GitHub dan bagikan ke sesama bug hunter pro gratis lainnya!