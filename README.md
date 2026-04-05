# 🛡️ AegisRDP: Lightweight RDP Brute-Force Defender

[![Version](https://img.shields.io/badge/version-0.3.0--rc-orange.svg)](https://github.com/hoatran2k11/aegis-rdp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20Server-lightgrey.svg)](https://microsoft.com/windowsserver)

**AegisRDP** is a lightweight, high-performance security tool written in **C**, designed to detect and mitigate RDP brute-force attacks in real-time using Windows Event Logs and Firewall integration.

> "Guard your RDP before attackers do."

---

## 🚀 Features

### ✅ Implemented

* **Event Log Monitoring:** Reads Windows Security Event Logs (Event ID 4625)
* **IP Extraction:** Parses and extracts source IP addresses
* **Brute-Force Detection:** Threshold-based detection (fast & slow brute patterns)
* **Automatic IP Blocking:** Blocks malicious IPs via Windows Firewall
* **Whitelist System:** Prevents trusted IPs from being blocked
* **INI Configuration:** External `config.ini` for thresholds and behavior
* **Windows Service Mode:** Runs silently in background
* **Modular Architecture:** Clean separation (event, parser, detector, firewall, logger)
* **High Performance:** Native Win32, minimal CPU/RAM usage

---

### 🧪 Planned

* [ ] Secure agent ↔ server communication (TLS + HMAC)
* [ ] Web-based control panel
* [ ] RDP port management
* [ ] Security recommendations (password, username)
* [ ] 🌍 IP intelligence lookup (GeoIP, ISP, ASN) via IPinfo API

---

## 🛠️ Project Status (v0.3.0-rc)

This is a **release candidate (RC)** version.

* Core detection + response pipeline is functional
* Firewall auto-blocking is active
* Service mode and config system are implemented
* Currently focusing on stability and advanced features

---

## ⚙️ How It Works

AegisRDP monitors failed RDP login attempts (Event ID 4625). When an IP exceeds defined thresholds, it is automatically blocked via Windows Firewall.

### Logic Flow:

```text
[FAIL] IP=192.168.1.100 COUNT=1 (Tracking)
...
[FAIL] IP=192.168.1.100 COUNT=5 (Threshold reached)
>>> BRUTE DETECTED: 192.168.1.100 <<<
[+] BLOCKED via Firewall
```

---

## 🌍 Planned: IP Intelligence (IPinfo API)

Future versions will enrich detected IPs with:

* Country / City 🌎
* ISP / Organization 🏢
* ASN / Network 📡

Example:

```text
[ALERT] 45.133.x.x
Country: RU
ISP: Example Hosting Ltd
ASN: AS12345
```

---

## 📝 Configuration (`config.ini`)

Generated automatically on first run:

```ini
[Detection]
threshold=5
time_window=60
long_threshold=15
long_window=300

[Action]
block_duration=600
dry_run=0

[Whitelist]
ips=127.0.0.1,192.168.1.1
```

---

## 💻 Build Instructions

```cmd
cl src\*.c /I src\include /Fe:aegisrdp.exe wevtapi.lib /O2
```

---

## 🧩 Requirements

* **OS:** Windows Server 2012 → 2025 / Windows 10/11
* **Privileges:** Administrator

---

## ⚠️ Disclaimer

This is a **pre-release (RC)** version. Use with caution in production.

---

## 🚀 Author & Contributing

* **Author:** Hoa Tran
* Contributions are welcome!

---

## 📜 License

MIT License