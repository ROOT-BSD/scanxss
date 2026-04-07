# ScanXSS v1.3.1

> **Автоматизований сканер вразливостей веб-застосунків**  
> Linux · macOS · BSD · **Windows 11 (GUI)**  
> © 2026 root_bsd · [root_bsd@itprof.net.ua](mailto:root_bsd@itprof.net.ua)  
> [https://github.com/ROOT-BSD/scanxss](https://github.com/ROOT-BSD/scanxss)

---

## Можливості

| | |
|---|---|
| 🕷 **Crawling** | BFS по всіх субдоменах, gzip/br, Chrome UA |
| 🔍 **7 модулів атак** | XSS · SQLi · LFI · RCE · SSRF · Redirect · CRLF |
| 📋 **4 режими** | Full · Resume · Rescan · Retarget |
| 🗄 **SQLite БД** | Вся історія сканувань, повторні перевірки |
| 📄 **3 формати звітів** | HTML · JSON · TXT |
| 📚 **Пояснення** | Critical/High: опис + вплив + виправлення + OWASP/CWE посилання |
| 🖥 **macOS GUI** | Нативний Cocoa застосунок з вбудованим терміналом |
| 🪟 **Windows GUI** | Win32 інтерфейс, WinHttp, NSIS інсталятор |

---

## Структура репозиторію

```
scanxss/
├── linux-macos/          ← CLI сканер (Linux / macOS / BSD)
│   ├── src/              — 10 модулів C99
│   ├── include/          — scanxss.h, vuln_info.h (OWASP/CWE база)
│   ├── modules/          — mod_xss, mod_sqli, mod_misc, mod_ssrf
│   ├── vendor/           — sqlite3.h (bundled, без libsqlite3-dev)
│   ├── tests/            — 26 інтеграційних тестів
│   ├── Makefile
│   └── README.md
│
├── macos-gui/            ← macOS Cocoa GUI
│   ├── src/              — AppDelegate.m, AppDelegate.h, main.m
│   ├── resources/        — AppIcon.icns (всі розміри), AppIcon.iconset
│   ├── Info.plist
│   ├── Makefile
│   └── INSTALL.sh        — автоматичний інсталятор
│
├── windows/              ← Windows 11 GUI
│   ├── src/              — gui.c, scanner.c, db.c, export.c
│   ├── resources/        — app.ico, app.rc
│   ├── installer/        — NSIS скрипт, scanxss-setup.exe
│   ├── vendor/           — sqlite3.h
│   └── Makefile.win      — cross-compile з Linux
│
└── docs/
    ├── scanxss_documentation.docx
    ├── README.md
    └── sample_report.html
```

---

## Швидкий старт

### Linux / macOS (CLI)
```bash
# Debian/Ubuntu
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
cd linux-macos && make && ./scanxss -u https://site.com/

# macOS
brew install openssl curl
cd linux-macos && make && ./scanxss -u https://site.com/
```

### macOS (GUI — повне встановлення)
```bash
tar xf scanxss-1.3.1-macos.tar.gz
cd scanxss-1.3.1-macos
sudo bash INSTALL.sh
# Відкриється /Applications/ScanXSS.app
```

### Windows
Запустіть `windows/scanxss-setup.exe` → встановлення в `C:\Program Files\ScanXSS\`

---

## CLI — використання

```
scanxss -u URL [опції]
```

| Параметр | За замовч. | Опис |
|---|---|---|
| `-u URL` | — | Ціль (обов'язково) |
| `-d N` | 3 | Глибина crawling |
| `-r N` | 10 | Rate limit (req/s) |
| `-t N` | 15 | HTTP timeout (сек) |
| `-s SCOPE` | subdomain | subdomain\|domain\|folder\|url |
| `-m MODULES` | всі | xss,sqli,lfi,rce,ssrf,redirect,crlf |
| `-c COOKIES` | — | Cookies для авторизації |
| `-p PROXY` | — | HTTP проксі |
| `-v` | — | Детальний вивід |
| `--resume` | — | Продовжити перерване |
| `--rescan` | — | Нова атака на збережений crawl |
| `--retarget` | — | Перевірка виправлень |
| `--list-scans` | — | Список сканувань з БД |

---

## Режими сканування

| Режим | Прапор | Опис |
|---|---|---|
| Full | *(без прапора)* | Повний crawl + всі модулі |
| Resume | `--resume` | Продовжити перерване |
| Rescan | `--rescan` | Нові атаки на збережений crawl |
| Retarget | `--retarget` | Тільки раніше вразливі URL |

```bash
# Retarget — перевірка що вразливості виправлені:
./scanxss -u https://site.com/ --retarget
# [ACTIVE] sqli  .../login  id  ← не виправлено
# [ FIXED] xss   .../search q   ← виправлено ✅
```

---

## Модулі атак

| Модуль | Severity | CWE | CVSS |
|---|---|---|---|
| `rce` | Critical 5 | CWE-78, CWE-94 | 9.8 |
| `sqli` | Critical 5 | CWE-89 | 9.8 |
| `lfi` | Critical 5 | CWE-22 | 8.6 |
| `ssrf` | High 4 | CWE-918 | 8.6 |
| `xss` | High 4 | CWE-79 | 7.4 |
| `redirect` | Medium 3 | CWE-601 | 6.1 |
| `crlf` | Medium 3 | CWE-93 | 6.1 |

---

## HTML-звіт

Для Critical та High вразливостей:
- **🔎 Що це таке** — пояснення українською
- **💥 Можливий вплив** — конкретні наслідки
- **🛡 Як виправити** — кроки усунення
- **CVSS score**
- **Клікабельні посилання** → OWASP, CWE, PortSwigger, Cheat Sheet

---

## Шляхи файлів

| ОС | БД | Звіти |
|---|---|---|
| Linux/BSD | `../DB_SCAN/scan.db` | `../report/<host>/` |
| macOS | `~/.scanxss/scan.db` | `~/.scanxss/report/<host>/` |
| Windows | поряд з .exe | поряд з .exe |

---

## macOS GUI

Нативний Cocoa застосунок з чорним темним інтерфейсом:

- **Ліва панель:** URL, Depth/Rate/Timeout, Режим сканування, Scope, Cookies, 7 модулів атак, прогрес
- **Права панель:** вбудований термінал з кольоровим виводом
- **Режими:** Full / Rescan / Resume / Retarget
- **Прогрес:** 20 зелених прямокутників
- **Після сканування:** браузер відкривається автоматично (один раз)

---

## Windows GUI

- **WinHttp** — без зовнішніх DLL (~1 MB)
- **DPI-aware** — коректно на 125%/150%
- **AV bypass** — XOR-шифрування payload-рядків
- **NSIS інсталятор** — ярлик на робочому столі

---

## Збірка

```bash
# Linux/macOS CLI
make && make test   # 26/26 тестів

# macOS GUI (на Mac)
sudo bash INSTALL.sh

# Windows GUI (cross-compile з Linux)
sudo apt install mingw-w64 nsis
cd windows && make -f Makefile.win installer
```

---

## Ліцензія

**GPL-2.0** · [github.com/ROOT-BSD/scanxss](https://github.com/ROOT-BSD/scanxss)  
© 2026 root_bsd · [root_bsd@itprof.net.ua](mailto:root_bsd@itprof.net.ua)

Тільки для авторизованого тестування безпеки.
