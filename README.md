# 🛡️ AegisRDP: Lightweight RDP Brute-Force Defender

[![Version](https://img.shields.io/badge/version-0.4.0--alpha-blue.svg)](https://github.com/hoatran2k11/aegis-rdp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20Server-lightgrey.svg)](https://microsoft.com/windowsserver)

**AegisRDP** is a high-performance, lightweight security tool written in **C**. It is designed to protect Windows Servers from RDP brute-force attacks in real-time by integrating directly with the Windows Event Log and Advanced Firewall.

> "Guard your RDP before attackers do."

---

## 🚀 Key Features

* **Real-Time Monitoring:** Directly hooks into Windows Security Event Logs (Event ID 4625) for zero-latency detection.
* **Dual-Threshold Logic:** Sophisticated detection for both high-frequency (Fast Brute) and low-and-slow (Slow Brute) attacks.
* **Native Firewall Integration:** Automatically creates blocking rules via the Windows Advanced Firewall (`netsh`) API.
* **Zero Dependencies:** No .NET, Python, or Java required. A standalone native Win32 binary.
* **Smart Auto-Config:** Automatically generates a `config.ini` on the first run for easy customization.
* **High Performance:** Minimal CPU and RAM footprint, optimized for high-traffic server environments.
* **Whitelist Support:** Prevent accidental lockouts by whitelisting trusted administrative IPs.

---

## 🛠️ Project Status (v0.3.0-alpha)

This project is currently under active development.

- [x] **Modular Architecture:** Clean separation of concerns (detector, event, firewall, logger, parser).
- [x] **INI Configuration:** External configuration support for thresholds and windows.
- [x] **Auto-Blocking:** Instant IP banning upon reaching thresholds.
- [x] **Log Optimization:** Silent mode for already-blocked IPs to prevent console spam.
- [ ] **Windows Service:** Implementation as a background system service.
- [ ] **Web Dashboard:** Centralized management UI for monitoring multiple agents.

---

## ⚙️ How It Works

AegisRDP subscribes to failed login events. When a specific IP address exceeds the allowed failure count within a defined timeframe, AegisRDP immediately executes a block command at the firewall level.

### Logic Flow:
```text
[FAIL] IP=192.168.1.100 COUNT=1 (Tracking initiated)
...
[FAIL] IP=192.168.1.100 COUNT=5 (Threshold reached!)
>>> FAST BRUTE DETECTED: 192.168.1.100 <<<
[+] BLOCK APPLIED: 192.168.1.100 (Inbound Rule created)
````

-----

## 💻 Build Instructions

Built using the **MSVC** (Microsoft Visual C++) compiler for maximum Windows compatibility.

```cmd
# Use the Developer Command Prompt for Visual Studio
cl src\*.c /I src\include /Fe:aegisrdp.exe wevtapi.lib /O2
```

-----

## 📝 Configuration (`config.ini`)

AegisRDP generates this file automatically on its first execution:

```ini
[Detection]
threshold=5             ; Attempts for fast brute detection
time_window=60          ; Time window (seconds) for fast brute
long_threshold=15       ; Attempts for slow brute detection
long_window=300         ; Time window (seconds) for slow brute

[Action]
block_duration=600      ; Ban duration in seconds
dry_run=0               ; Set to 1 to simulate blocks without active rules

[Whitelist]
ips=127.0.0.1,192.168.1.1
```

-----

## 🧩 Requirements

  * **OS:** Windows Server 2012/2016/2019/2022 or Windows 10/11.
  * **Privileges:** Must be executed as **Administrator** (Required for Firewall and Event Log access).

-----

## ⚠️ Disclaimer

This is an **Alpha** version. Use it in production environments at your own risk. The author is not responsible for any accidental lockouts or connectivity issues resulting from improper configuration.

-----

## 🚀 Author & Contributing

  * **Author:** [Hoa Tran](https://www.google.com/search?q=https://github.com/hoatran2k11)
  * **Year:** 2026
  * **Contributions:** Pull requests, issues, and feature requests are welcome\! If you find this project useful, please give it a ⭐ **Star**.

-----

## 📜 License

This project is licensed under the **MIT License**.