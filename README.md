# ⚔️ CyberGuard v10.0 — Advanced WordPress Pentest & Recon Toolkit

**Created by:** Ibar — CyberGuard Developer ✨  
**Warning:** Gunakan hanya untuk edukasi & pengujian berizin ⚠️

---

## 🧠 Apa itu CyberGuard?
CyberGuard adalah framework **penetration testing & reconnaissance** khusus untuk WordPress dengan fitur modern yang lebih lengkap dibanding versi sebelumnya. Tool ini dibuat untuk membantu:
- 🔍 **Bug Hunter** dalam menemukan celah keamanan.
- 🛡️ **Pentester** dalam mengaudit keamanan WordPress.
- 🎓 **Pembelajar** dalam memahami teknik ofensif & defensif.

⚠️ **Catatan:** CyberGuard **bukan untuk aktivitas ilegal.** Hanya gunakan pada sistem yang Anda miliki atau telah diberi izin eksplisit.

---

## ✨ Fitur Terbaru di CyberGuard v10.0

| Fitur | Deskripsi |
|-------|-----------|
| 🧾 **WordPress Fingerprinting 2.0** | Deteksi otomatis versi WordPress, tema, & plugin aktif. |
| 👤 **Advanced Username Enumeration** | Ekstraksi username via `/?author=`, REST API, feed RSS, & sitemap. |
| 🧠 **AI-Powered Wordlist Generator** | Membuat wordlist dinamis dari metadata situs (judul, tag, author, keywords). |
| 🔐 **Credential Stuffing Engine** | Pengujian login dengan kombinasi wordlist eksternal & data hasil enumeration. |
| 🛡️ **Smart Brute Force** | Cek CSRF token, login nonce, rate-limit, hingga CAPTCHA aware. |
| 📂 **Sensitive File & Endpoint Hunter** | Pendeteksian `wp-config.php`, `.git`, backup zip, `.env`, `debug.log`, dsb. |
| 🧪 **XSS & Injection Tester** | Payload otomatis untuk XSS, SQLi, LFI, RFI, dan command injection. |
| 📡 **Plugin & Theme Vulnerability DB** | Database internal + integrasi WPScan API untuk cek CVE terbaru. |
| 🧨 **Zero-Day Payload Fuzzer** | Fuzzing parameter URL dengan payload cerdas berbasis pola terbaru. |
| 🔥 **HTTP Method & Header Fuzzer** | Uji PUT, DELETE, TRACE serta manipulasi header `X-Forwarded-For`, dll. |
| 🧾 **Report Generator Multi-format** | TXT, JSON, CSV, HTML, dan PDF profesional. |
| 📊 **Risk Scoring System** | Skor risiko otomatis (Minimal–Critical) berdasarkan temuan. |
| 🪪 **Session & Cookie Analyzer** | Analisis cookie target (flag HttpOnly, Secure, SameSite). |
| 🧭 **Multi-target Mode** | Scan 1 domain atau list domain dari file. |
| 📜 **Logging System** | Semua aksi tercatat di `cyberguard.log`. |

---

## 📦 Instalasi

### 1. Clone Repository
```bash
git clone https://github.com/r00tH3x/CyberGuard.git
cd CyberGuard
```

### 2. Install Dependencies
Pastikan Python 3.8+ sudah terpasang. Kemudian:
```bash
pip install -r requirements.txt
```

Jika file `requirements.txt` tidak ada, install manual:
```bash
pip install requests colorama beautifulsoup4 tqdm ratelimit reportlab tabulate
```

---

## 🚀 Cara Menggunakan

### Scan 1 Target
```bash
python CyberGuard1.py https://targetwordpress.com
```

### Scan Banyak Target (dari file)
```bash
python CyberGuard1.py targets.txt
```
Format `targets.txt`:
```
https://site1.com
https://site2.com
```

### Custom Wordlist & Fuzz Payload
```bash
python CyberGuard1.py https://target.com wordlist.txt fuzz_payloads.txt
```

### Dengan API Token (Opsional)
Gunakan WPScan API atau API eksternal lainnya untuk hasil lebih akurat:
```bash
python CyberGuard1.py https://target.com wordlist.txt fuzz.txt your_wpscan_api_token
```

---

## 📂 Output
- `cyberguard_report_YYYYMMDD_HHMMSS.txt` → Ringkasan hasil scan.  
- `cyberguard_report_YYYYMMDD_HHMMSS.pdf` → Laporan profesional siap presentasi.  
- `cyberguard_report_YYYYMMDD_HHMMSS.json/csv/html` → Format lain untuk analisis lanjut.  
- `cyberguard.log` → Semua aktivitas terekam otomatis.  

---

## ⚖️ Legal Disclaimer
CyberGuard hanya boleh digunakan untuk:
- ✅ Pentesting dengan izin tertulis pemilik sistem.
- ✅ Edukasi & pembelajaran keamanan siber.
- ✅ Bug bounty & audit internal organisasi.

🚫 **Penggunaan tanpa izin adalah tindakan ilegal.** Pengembang tidak bertanggung jawab atas penyalahgunaan.

---

## ❤️ Dukungan
Jika tool ini bermanfaat:
- ⭐ Beri bintang repo GitHub.
- 🫂 Share dengan komunitas bug hunter.
- 🛠️ Berkontribusi lewat pull request & issue.

---

🔥 **CyberGuard v10.0 — “Protect & Test Smarter, Not Harder!”** 🔥

