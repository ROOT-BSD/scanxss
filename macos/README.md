<div align="center">

# 🔍 ScanXSS

**Автоматизований сканер вразливостей веб-застосунків**

[![Version](https://img.shields.io/badge/version-1.3.1-blue.svg)](https://github.com/ROOT-BSD/scanxss/releases)
[![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/ROOT-BSD/scanxss)
[![Tests](https://img.shields.io/badge/tests-26%2F26%20✅-brightgreen.svg)](https://github.com/ROOT-BSD/scanxss)

*© 2026 root_bsd · [root_bsd@itprof.net.ua](mailto:root_bsd@itprof.net.ua)*

</div>

---

## Про проект

ScanXSS — CLI та GUI сканер вразливостей веб-застосунків написаний на мові **C99**.  
Підтримує **Linux**, **macOS** (нативний Cocoa GUI) та **Windows 11** (Win32 GUI).  
Без зовнішніх рантайм-залежностей — SQLite входить до проекту.

---

## ✨ Можливості

| | |
|---|---|
| 🕷 **Crawling** | BFS по всіх субдоменах, gzip/deflate, Chrome User-Agent |
| 🔍 **7 модулів атак** | XSS · SQLi · LFI · RCE · SSRF · Open Redirect · CRLF |
| 📋 **4 режими** | Full · Resume · Rescan · Retarget |
| 🗄 **SQLite БД** | Повна історія сканувань, повторні перевірки |
| 📄 **3 формати звітів** | HTML (інтерактивний) · JSON · TXT |
| 📚 **Пояснення** | Critical/High: опис + вплив + виправлення + OWASP/CWE посилання |
| 🖥 **macOS GUI** | Нативний Cocoa, темна тема, вбудований термінал, зелений прогрес |
| 🪟 **Windows GUI** | Win32 + WinHttp, ~1MB без DLL, DPI-aware, NSIS інсталятор |

---

## 📦 Структура репозиторію

```
scanxss/
├── linux/                ← CLI сканер (Linux / BSD)
│   ├── src/              — 10 модулів C99
│   ├── include/          — scanxss.h, vuln_info.h (OWASP/CWE база)
│   ├── modules/          — mod_xss, mod_sqli, mod_misc, mod_ssrf
│   ├── vendor/           — sqlite3.h (bundled)
│   ├── tests/            — 26 інтеграційних тестів
│   └── Makefile
│
├── macos/                ← CLI + GUI для macOS
│   ├── src/              — CLI вихідний код
│   ├── gui/              — Cocoa GUI (AppDelegate.m, Info.plist)
│   │   └── resources/    — AppIcon.icns (всі розміри)
│   └── INSTALL.sh        — повний автоматичний інсталятор
│
├── windows/              ← GUI для Windows 11
│   ├── src/              — gui.c, scanner.c, db.c, export.c
│   ├── resources/        — app.ico, app.rc
│   ├── installer/        — NSIS скрипт + scanxss-setup.exe
│   └── Makefile.win      — cross-compile з Linux
│
└── docs/
    ├── scanxss_documentation.docx
    └── sample_report.html
```

---

## 🚀 Швидкий старт

### Linux

```bash
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
cd linux && make
./scanxss -u https://target.com/
```

### macOS (CLI + GUI)

```bash
tar xf scanxss-1.3.1-macos.tar.gz
cd scanxss-1.3.1-macos
sudo bash INSTALL.sh
```

Інсталятор автоматично:
- встановить Homebrew (якщо немає)
- встановить `openssl` та `curl`
- скомпілює нативний **arm64/x86_64** бінарник
- встановить `/Applications/ScanXSS.app`
- додасть `scanxss` до `PATH`

### Windows

Запустити `windows/installer/scanxss-setup.exe` → встановлення в `C:\Program Files\ScanXSS\`

---

## 🖥 macOS GUI

<div align="center">

| Ліва панель | Права панель |
|---|---|
| URL, Depth, Rate, Timeout | Термінальний вивід |
| Режим сканування | Кольоровий лог (ANSI) |
| Scope, Cookies | Авто-прокрутка |
| 7 модулів (зелені чекбокси) | |
| Прогрес — 20 зелених блоків | |
| Start / Stop / Open Report | |

</div>

**Режими** (dropdown): Full · Rescan · Resume · Retarget  
**Після завершення**: браузер відкривається автоматично з HTML-звітом  
**Шляхи**: `~/.scanxss/scan.db` · `~/Desctop/report/<host>/`

---

## 📟 CLI — використання

```
scanxss -u URL [опції]
```

| Параметр | За замовч. | Опис |
|---|---|---|
| `-u URL` | — | Ціль сканування (обов'язково) |
| `-d N` | 3 | Глибина crawling |
| `-r N` | 10 | Rate limit (req/s) |
| `-t N` | 15 | HTTP timeout (сек) |
| `-s SCOPE` | subdomain | `subdomain` · `domain` · `folder` · `url` |
| `-m MODULES` | всі | `xss,sqli,lfi,rce,ssrf,redirect,crlf` |
| `-c COOKIES` | — | Cookies для авторизованих сканувань |
| `-p PROXY` | — | HTTP проксі (`http://host:port`) |
| `-v` | — | Детальний вивід |
| `--resume` | — | Продовжити перерване сканування |
| `--rescan` | — | Нова атака на збережений crawl |
| `--retarget` | — | Перевірка чи виправлені вразливості |
| `--list-scans` | — | Список сканувань з БД |
| `--wipe` | — | Видалити всі дані цілі |

---

## 🔄 Режими сканування

| Режим | Прапор | Опис |
|---|---|---|
| **Full** | *(без прапора)* | Повний crawl + всі модулі атак |
| **Resume** | `--resume` | Продовжити перерване |
| **Rescan** | `--rescan` | Нові атаки на збережений crawl (без повторного crawl) |
| **Retarget** | `--retarget` | Тільки раніше вразливі URL/форми |

```
$ ./scanxss -u https://site.com/ --retarget

[ACTIVE] sqli  https://site.com/login  param=id    ← не виправлено
[ FIXED] xss   https://site.com/search param=q     ← виправлено ✅
```

---

## 🎯 Модулі атак

| Модуль | Тип | Severity | CWE | CVSS |
|---|---|---|---|---|
| `rce` | Remote Code Execution | Critical | CWE-78, CWE-94 | 9.8 |
| `sqli` | SQL Injection | Critical | CWE-89 | 9.8 |
| `lfi` | Local File Inclusion | Critical | CWE-22, CWE-98 | 8.6 |
| `ssrf` | Server-Side Request Forgery | High | CWE-918 | 8.6 |
| `xss` | Cross-Site Scripting | High | CWE-79 | 7.4 |
| `redirect` | Open Redirect | Medium | CWE-601 | 6.1 |
| `crlf` | CRLF Injection | Medium | CWE-93 | 6.1 |

---

## 📄 HTML-звіт

Для **Critical** та **High** вразливостей кожна картка містить:

```
┌─ ● SQL Injection  site.com/login → id  [Critical CVSS 9.8] ▶
│
│  🔎 Що це таке       — опис вразливості українською
│  💥 Можливий вплив   — наслідки для системи
│  🛡 Як виправити     — конкретні кроки усунення
│
│  [🔗 OWASP A03:2021] [🔗 CWE-89] [🔗 PortSwigger] [🔗 Cheat Sheet]
└─
```

---

## 🗄 Шляхи файлів

| ОС | База даних | Звіти |
|---|---|---|
| Linux / BSD | `../DB_SCAN/scan.db` | `../report/<host>/` |
| macOS | `~/.scanxss/scan.db` | `~/Desctop/report/<host>/` |
| Windows | поряд з `.exe` | поряд з `.exe` |

---

## 🔧 Збірка з вихідного коду

```bash
# Linux / macOS CLI
cd linux && make && make test     # 26/26 тестів ✅

# macOS GUI (запускати на Mac)
cd macos && sudo bash INSTALL.sh

# Windows GUI (cross-compile з Linux)
sudo apt install mingw-w64 nsis tcl
cd windows && make -f Makefile.win installer
```

---

## 📋 Приклади

```bash
# Базове сканування
./scanxss -u https://site.com/

# З авторизацією, глибина 5
./scanxss -u https://site.com/ -d 5 -c "session=abc123" -v

# Тільки критичні модулі через Burp
./scanxss -u https://site.com/ -m sqli,lfi,rce -p http://127.0.0.1:8080

# Повільне сканування (обхід rate limiting)
./scanxss -u https://site.com/ -r 2 -t 30

# Перевірка що вразливості виправлені
./scanxss -u https://site.com/ --retarget

# Переглянути всі сканування
./scanxss -u https://site.com/ --list-scans
```

---

## ⚖️ Ліцензія

**GPL-2.0** — тільки для авторизованого тестування безпеки.

> Несанкціоноване сканування є незаконним та переслідується відповідно до законодавства.

---

<div align="center">

© 2026 **root_bsd** · [root_bsd@itprof.net.ua](mailto:root_bsd@itprof.net.ua)  
[https://github.com/ROOT-BSD/scanxss](https://github.com/ROOT-BSD/scanxss)

</div>
