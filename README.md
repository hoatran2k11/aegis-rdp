# 🛡️ AegisRDP

> Guard your RDP before attackers do.

AegisRDP is a lightweight security system designed to protect Windows servers from RDP brute-force attacks.

It monitors login attempts in real time, detects suspicious behavior, and (in upcoming versions) automatically blocks malicious IP addresses.

---

## 🚧 Project Status

⚠️ This project is currently under active development.

Current version: `0.1.0-alpha`

Implemented:
- [x] Read Windows Security Event Logs (Event ID 4625)
- [x] Extract source IP address
- [x] Detect brute-force attempts (basic threshold logic)
- [x] Automatic IP blocking via Windows Firewall
- [x] Whitelist system
- [x] Configuration file support

Planned:
- [ ] Run as Windows Service
- [ ] Secure agent ↔ server communication (TLS + HMAC)
- [ ] Web-based control panel
- [ ] RDP port management
- [ ] Security recommendations (password, username)

---

## ⚙️ How It Works

AegisRDP monitors failed login attempts from Windows Event Logs.

When multiple failed attempts are detected from the same IP within a short time window, the system flags it as a potential brute-force attack.

---

## 🧪 Current Behavior (Alpha)

Example output:

```

[FAIL] IP: 1.2.3.4 | Count: 1
[FAIL] IP: 1.2.3.4 | Count: 2
...

> > > BRUTE DETECTED: 1.2.3.4 <<<

````

---

## 🛠️ Build Instructions

### Using MinGW:

```bash
gcc main.c -o aegisrdp.exe -lwevtapi
````

---

## 🧩 Requirements

* Windows (tested on Windows Server environments)
* Administrator privileges (required for Event Log access)

---

## ⚠️ Disclaimer

This is an early alpha version and should NOT be used in production environments yet.

---

## 📜 License

This project is licensed under the MIT License.

Copyright (c) 2026 Hòa Trần

---

## ⭐ Attribution

If you use this project, please give credit to the original author.

---

## 💡 Future Vision

AegisRDP aims to become a full-featured RDP defense platform, similar to Fail2Ban but designed specifically for Windows, with a modern web-based management interface.

---

## 🤝 Contributing

Contributions, ideas, and feedback are welcome!

---

## 🚀 Author

**Hòa Trần**