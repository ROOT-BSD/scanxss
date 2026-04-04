# ScanXSS v1.3.0

> **Автоматизований сканер вразливостей веб-застосунків**  
> Linux · macOS · BSD · **Windows 11 (GUI)**

---

## Можливості

| | |
|---|---|
| 🕷 **Crawling** | BFS по всіх субдоменах, gzip/br, Chrome UA |
| 🔍 **7 модулів атак** | XSS · SQLi · LFI · RCE · SSRF · Redirect · CRLF |
| 📋 **4 режими** | Full · Resume · Rescan · Retarget |
| 🗄 **SQLite БД** | Вся історія сканувань, повторні перевірки |
| 📄 **3 формати звітів** | HTML · JSON · TXT |
| 📚 **Пояснення** | Для Critical/High: опис + вплив + виправлення + посилання |
| 🖥 **Windows GUI** | Win32 інтерфейс, WinHttp, інсталятор NSIS |

---

## Швидкий старт

```bash
# Ubuntu/Debian
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
make
./scanxss -u https://site.com/
```

```bash
# macOS
brew install openssl curl
make
./scanxss -u https://site.com/
```

Після запуску:
```
../DB_SCAN/scan.db                           ← база даних
../report/site.com/site.com_20250401_*.html  ← HTML-звіт
```

```bash
# Windows 11 — інсталятор
# Запустіть scanxss-setup.exe і слідуйте інструкціям
# Встановлюється в C:\Program Files\ScanXSS\
```

---

## Використання

```
scanxss -u URL [опції]
```

### Основні параметри

```
-u URL              Ціль сканування (обов'язково)
-d N                Глибина crawling [3]
-t N                HTTP timeout, секунди [15]
-l N                Макс. кількість URL [256]
-r N                Rate limit, запитів/сек [10]
-s SCOPE            Зона: subdomain|domain|folder|url [subdomain]
-m MODULES          Модулі через кому: xss,sqli,lfi,rce,ssrf,redirect,crlf
-v                  Детальний вивід
```

### Мережа

```
-c COOKIES          Cookies (для авторизованих сканувань)
-a USER_AGENT       Кастомний User-Agent
-p PROXY            HTTP проксі: http://host:port
```

### База даних

```
--list-scans        Список попередніх сканувань
--show-scan ID      Деталі сканування
--delete-scan ID    Видалити сканування
--wipe              Видалити всі дані цілі
--db FILE           Кастомний шлях до БД
--report-dir DIR    Кастомна директорія звітів
```

---

## Режими сканування

### FULL (за замовчуванням)
Повний crawl + всі модулі.

```bash
./scanxss -u https://site.com/
```

### RESUME — продовження
Відновлює перерване сканування.

```bash
./scanxss -u https://site.com/ --resume
```

### RESCAN — нова атака на збережений crawl
Не витрачає час на повторний crawl — атакує з нових payload-ів.

```bash
./scanxss -u https://site.com/ --rescan
```

### RETARGET — перевірка виправлень
Тестує **тільки** раніше вразливі ендпоінти. Показує статус кожної вразливості:

```bash
./scanxss -u https://site.com/ --retarget
```
```
[ACTIVE] sqli  https://site.com/login  param=id    ← ще не виправлено
[ FIXED] xss   https://site.com/search param=q     ← виправлено ✅
```

---

## Модулі атак

| Модуль | Severity | CWE | CVSS |
|---|---|---|---|
| `sqli` — SQL Injection | Critical (5) | CWE-89 | 9.8 |
| `lfi` — Local File Inclusion | Critical (5) | CWE-22 | 8.6 |
| `rce` — Remote Code Execution | Critical (5) | CWE-78 | 9.8 |
| `ssrf` — Server-Side Request Forgery | High (4) | CWE-918 | 8.6 |
| `xss` — Cross-Site Scripting | High (4) | CWE-79 | 7.4 |
| `redirect` — Open Redirect | Medium (3) | CWE-601 | 6.1 |
| `crlf` — CRLF Injection | Medium (3) | CWE-93 | 6.1 |

```bash
# Тільки критичні
./scanxss -u https://site.com/ -m sqli,lfi,rce
```

---

## HTML-звіт

Для кожної Critical/High вразливості автоматично вставляються:

- **🔎 Що це таке** — пояснення українською
- **💥 Можливий вплив** — що може зробити зловмисник
- **🛡 Як виправити** — конкретні кроки
- **CVSS score**
- **Інтерактивні посилання** — клікабельні кнопки на:
  - OWASP Top 10 / Testing Guide
  - CWE (Common Weakness Enumeration)
  - PortSwigger Web Security Academy
  - OWASP Cheat Sheet Series

---

## Шляхи файлів

| Ресурс | Шлях (відносно бінарника) |
|---|---|
| База даних | `../DB_SCAN/scan.db` |
| HTML-звіт | `../report/<hostname>/<hostname>_<timestamp>.html` |
| JSON-звіт | `../report/<hostname>/<hostname>_<timestamp>.json` |
| TXT-звіт | `../report/<hostname>/<hostname>_<timestamp>.txt` |

---

## Приклади

```bash
# З авторизацією
./scanxss -u https://site.com/ \
    -c "session=abc123; csrf=xyz" \
    -d 5 -l 512 -v

# Тільки SQLi через проксі Burp
./scanxss -u https://site.com/ -m sqli \
    -p http://127.0.0.1:8080

# Перевірка що вразливості виправлені
./scanxss -u https://site.com/ --retarget

# Переглянути всі сканування
./scanxss -u https://site.com/ --list-scans

# Переглянути знахідки сканування #3
./scanxss -u https://site.com/ --show-scan 3
```

---

---

## Windows GUI

### Інтерфейс

Графічний застосунок для Windows 11 з повним функціоналом CLI-сканера.

| Елемент | Опис |
|---|---|
| **Вкладка Vulnerabilities** | Кольорові рядки по severity, розгортаються по кліку |
| **Вкладка Scan Log** | Повний лог з timestamp у кожному рядку |
| **Progress bar** | Відображає прогрес crawl та attack фаз |
| **Export** | HTML · JSON · CSV через діалог збереження |
| **History** | Перегляд попередніх сканувань з БД |

### Встановлення (готовий інсталятор)

1. Завантажити `scanxss-setup.exe`
2. Запустити від імені адміністратора
3. Слідувати інструкціям майстра встановлення
4. Ярлик з'явиться на робочому столі та в меню Пуск

Встановлюється в `C:\Program Files\ScanXSS\`  
БД зберігається поряд з виконуваним файлом: `scan.db`

### Збірка Windows GUI з вихідного коду (на Linux)

```bash
# Залежності
sudo apt install mingw-w64 nsis tcl

# Збірка
cd windows/
make -f Makefile.win           # → scanxss-gui.exe
make -f Makefile.win installer # → installer/scanxss-setup.exe
```

Якщо `vendor/sqlite3.c` відсутній — `make` завантажить автоматично.

### Технічний стек Windows GUI

| Компонент | Реалізація |
|---|---|
| HTTP | WinHttp.dll (вбудований у Windows, без libcurl) |
| БД | SQLite 3.45.1 amalgamation (статично в .exe) |
| GUI | Win32 API + comctl32 |
| DPI | PerMonitorV2 aware (коректно на 125%/150%) |
| Розмір | ~1 MB (без зовнішніх DLL) |
| AV | XOR-шифрування payload-рядків (обхід false positive) |

## Збірка (Linux / macOS)

```bash
make           # збірка
make test      # 26 інтеграційних тестів
make clean     # очистити
make help      # довідка
```

**Залежності (Debian/Ubuntu):** `build-essential libcurl4-openssl-dev libssl-dev`  
**Залежності (macOS):** `brew install openssl curl`  
**SQLite:** входить до проекту (`vendor/sqlite3.h`) — `libsqlite3-dev` не потрібен

---

## Ліцензія

**GPL-2.0** — тільки для авторизованого тестування безпеки.

&copy; 2025 root_bsd — [mglushak@gmail.com](mailto:mglushak@gmail.com)
