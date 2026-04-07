# ScanXSS v1.3.1

**Автоматизований сканер вразливостей веб-застосунків**

© 2026 root_bsd · root_bsd@itprof.net.ua  
https://github.com/ROOT-BSD/scanxss · GPL-2.0

---

## Структура архіву

```
scanxss-1.3.1/
├── linux/     ← CLI сканер (Linux / BSD)
├── macos/     ← CLI + GUI для macOS
├── windows/   ← GUI для Windows 11
└── docs/      ← документація, зразок звіту
```

## Встановлення

**Linux:**
```bash
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
cd linux && make && ./scanxss -u https://target.com/
```

**macOS (GUI + CLI):**
```bash
cd macos && sudo bash INSTALL.sh
```

**Windows:**
```
windows/installer/scanxss-setup.exe
```
