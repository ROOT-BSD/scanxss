# ScanXSS v1.3.3 — Web Vulnerability Scanner

> Автоматизований сканер вразливостей веб-застосунків з відкритим кодом.  
> © 2026 root_bsd \<root_bsd@itprof.net.ua\> | GPL-2.0  
> https://github.com/ROOT-BSD/scanxss

[![Build](https://github.com/ROOT-BSD/scanxss/actions/workflows/ci.yml/badge.svg)](https://github.com/ROOT-BSD/scanxss/actions)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.3.3-green.svg)](CHANGELOG.md)

---

## Можливості

| Функція | Опис |
|---|---|
| **7 модулів атак** | XSS, SQLi, LFI, RCE, SSRF, Open Redirect, CRLF |
| **Паралельне сканування** | pthread worker pool, автовизначення потоків (nproc × 4) |
| **Зовнішня БД payload-ів** | SQLite `payloads.db`, оновлення без перекомпіляції |
| **Автооновлення** | PayloadsAllTheThings, SecLists, NVD CVE Feed |
| **BFS crawler** | O(1) hash-set, пропуск бінарних ресурсів через HEAD preflight |
| **Email-звіти** | STARTTLS, будь-який SMTP сервер, без зовнішніх бібліотек |
| **3 платформи** | Linux CLI, macOS (Cocoa GUI), Windows 11 (Win32 GUI) |
| **SQLite БД** | збереження сканувань, resume, history, retarget |
| **Звіти** | HTML (інтерактивний, OWASP/CWE) + TXT |
| **CI/CD** | коди повернення 0/1/2, GitHub Actions ready |

---

## Швидкий старт

### Linux

```bash
git clone https://github.com/ROOT-BSD/scanxss.git
cd scanxss/linux
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
make -j$(nproc)
./scanxss -u https://target.com/
```

### macOS

```bash
cd scanxss/macos
brew install curl openssl sqlite3 pkg-config
make -j$(sysctl -n hw.logicalcpu)
./scanxss -u https://target.com/
```

### macOS GUI

```bash
cd scanxss/macos && sudo bash INSTALL.sh
# Відкриється /Applications/ScanXSS.app
```

### Windows

Запустити `windows/installer/scanxss-setup.exe` від **Адміністратора**.

---

## Використання

```bash
# Базове сканування
./scanxss -u https://target.com/

# З параметрами продуктивності
./scanxss -u https://target.com/ -d 5 -r 20 --threads 8

# Вибіркові модулі
./scanxss -u https://target.com/ -m xss,sqli,lfi

# Продовжити перерване сканування
./scanxss -u https://target.com/ --resume

# Перевірити тільки раніше знайдені вразливості
./scanxss -u https://target.com/ --retarget

# Оновити базу payload-ів
./scanxss --update

# Налаштування email-звітів
./scanxss --setup-email

# Довідка
./scanxss --help
```

---

## Параметри

### Сканування

| Параметр | Опис | За замовч. |
|---|---|---|
| `-u URL` | Ціль сканування | — |
| `-d N` | Глибина crawl | 3 |
| `-r N` | Запитів на секунду | 10 |
| `-t N` | HTTP таймаут (сек) | 10 |
| `-l N` | Макс. кількість URL | 256 |
| `-s SCOPE` | `url` / `page` / `folder` / `domain` / `subdomain` | subdomain |
| `-m MODULES` | `xss,sqli,lfi,rce,ssrf,redirect,crlf` | всі |
| `-c COOKIE` | Cookies для автентифікації | — |
| `-a UA` | User-Agent | Chrome |
| `-p URL` | Проксі | — |
| `--threads N` | Потоків атак (авто: nproc×4, макс. 16) | auto |
| `--endpoint URL` | SSRF callback endpoint | — |

### Режими

| Параметр | Опис |
|---|---|
| `--resume` | Продовжити перерване сканування |
| `--rescan` | Нові атаки на збережений crawl |
| `--retarget` | Перевірити тільки раніше знайдені вразливості |
| `--rescan-from ID` | Rescan від конкретного scan_id |

### База даних сканувань

| Параметр | Опис |
|---|---|
| `--list-scans` | Список сканувань цілі |
| `--show-scan ID` | Деталі сканування |
| `--delete-scan ID` | Видалити сканування |
| `--wipe` | Видалити всі дані цілі |
| `--db FILE` | Шлях до scan.db |

### База payload-ів

| Параметр | Опис |
|---|---|
| `--update` | Оновити payload-и з мережі (PATT, SecLists, NVD) |
| `--update-source S` | Джерело: `patt`, `seclists`, `nvd` |
| `--payloads-db FILE` | Власний шлях до `payloads.db` |
| `--payloads-stats` | Статистика бази по модулях |

### Email

| Параметр | Опис |
|---|---|
| `--setup-email` | Майстер налаштування SMTP |
| `--email-history` | Відправка архівних звітів |

---

## Модулі атак

| Модуль | Тип | Severity | CWE | CVSS |
|---|---|---|---|---|
| `rce` | Remote Code Execution | Critical | CWE-78, CWE-94 | 9.8 |
| `sqli` | SQL Injection | Critical | CWE-89 | 9.8 |
| `lfi` | Local File Inclusion | Critical | CWE-22 | 8.6 |
| `ssrf` | Server-Side Request Forgery | High | CWE-918 | 8.6 |
| `xss` | Cross-Site Scripting | High | CWE-79 | 7.4 |
| `redirect` | Open Redirect | Medium | CWE-601 | 6.1 |
| `crlf` | CRLF Injection | Medium | CWE-93 | 6.1 |

---

## База payload-ів

Payload-и зберігаються у `~/.scanxss/payloads.db` (SQLite).  
При першому запуску БД створюється автоматично з вбудованими даними.

```bash
./scanxss --payloads-stats            # статистика
./scanxss --update                    # оновити з усіх джерел
./scanxss --update --update-source patt      # тільки PayloadsAllTheThings
./scanxss --update --update-source seclists  # тільки SecLists
./scanxss --update --update-source nvd       # тільки NVD CVE
```

Джерела: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) · [SecLists](https://github.com/danielmiessler/SecLists) · [NVD](https://nvd.nist.gov/)

---

## Продуктивність

```
CPU ядер  →  Автопотоки (nproc × 4)
1         →  4   (мінімум)
2         →  8
4         →  16
8+        →  32  (максимум)
```

| Оптимізація | Ефект |
|---|---|
| Паралельні атаки (4 потоки) | ~4–6x прискорення фази атак |
| HEAD preflight у crawler | ~30–60% менше трафіку на медіа-сайтах |
| SQLi baseline кеш | −1 HTTP-запит на форму |

---

## Архітектура

```
src/
  main.c       — CLI, --setup-email, --update, --payloads-stats
  crawler.c    — BFS, O(1) hash-set, HEAD preflight
  attack.c     — pthread worker pool, оркестрація модулів
  http.c       — libcurl (http_get, http_head, http_multi_get)
  worker.c     — pthread worker pool (до 16 потоків)
  payloads.c   — SQLite БД payload-ів, кеш у пам'яті
  update.c     — синхронізація з PATT / SecLists / NVD
  email.c      — SMTP клієнт з STARTTLS (OpenSSL)
  progress.c   — thread-safe progress bar, EWMA ETA
  rate.c       — rate limiter (nanosleep + spinner)
  report.c     — HTML + TXT звіти (OWASP/CWE)
  db.c         — SQLite: scans, findings, forms, urls
modules/
  mod_xss.c    — probe-reflect + payload-и з БД
  mod_sqli.c   — error-based + differential, baseline кеш
  mod_misc.c   — LFI, RCE, CRLF, Open Redirect
  mod_ssrf.c   — internal addresses + callback endpoint
```

---

## Шляхи файлів

| ОС | scan.db | payloads.db | Звіти |
|---|---|---|---|
| Linux | `../DB_SCAN/scan.db` | `~/.scanxss/payloads.db` | `../report/<host>/` |
| macOS | `~/.scanxss/scan.db` | `~/.scanxss/payloads.db` | `~/Desktop/report/<host>/` |
| Windows | поряд з .exe | поряд з .exe | `Desktop\REPORT\<host>\` |

---

## CI/CD

```bash
./scanxss -u https://staging.example.com/ -m xss,sqli --threads 4 -r 5
EXIT=$?
[ $EXIT -eq 2 ] && echo "ВРАЗЛИВОСТІ ЗНАЙДЕНО" && exit 1
[ $EXIT -eq 1 ] && echo "ПОМИЛКА" && exit 1
echo "Чисто" && exit 0
```

Коди: `0` — чисто · `1` — помилка · `2` — знайдено вразливості

---

## Зміни v1.3.3 — 2026-04-24

### Security — виправлення безпеки (v1.3.2)

- **Shell injection через `popen()`** — hostname вставлявся у shell-команду. Замінено на `find_newest_file()` через POSIX `opendir`/`readdir`/`stat`.
- **RCE через `system()` (macOS)** — шлях до звіту передавався у `system("open...")`. Замінено на `fork()` + `execve()`.
- **SMTP пароль з небезпечними правами** — конфіг тепер створюється з `open(..., 0600)`.

### Added — нові можливості (v1.3.3)

- **pthread worker pool** (`--threads N`, авто: nproc × 4) — фаза атак паралельна, прискорення 4–6x.
- **`--update`** — завантаження payload-ів з PayloadsAllTheThings, SecLists, NVD без перекомпіляції.
- **`--payloads-stats`** — статистика бази по модулях.
- **HEAD preflight у crawler** — пропуск бінарних ресурсів, економія трафіку ~30–60%.
- **SQLi baseline кеш** — `Form.baseline_len`, −1 запит на форму.
- **Thread-safe progress bar** — `pthread_mutex` у `draw()`, EWMA ETA, живий spinner.
- **Автовизначення `--threads`** — `sysconf(_SC_NPROCESSORS_ONLN) × 4`, діапазон [4, 32].
- **Виправлено `--retarget`** — `db_load_findings()` до `run_modules()`, правильний merge.
- **`--get-report <ID>`** — нова CLI команда: виводить абсолютний шлях до HTML звіту по scan_id.
- **`html_path` у БД** — колонка `scans.html_path` зберігає точний шлях після кожного сканування. Міграція існуючих БД автоматична (`ALTER TABLE` при старті).

### macOS GUI — нові функції

- **Збільшено шрифти скрізь** — термінал Menlo 12→15pt, UI шрифт 13→16pt, підписи полів 10→13pt, заголовок вікна 18→22pt, кнопки 13→16pt. Читабельність суттєво покращена.
- **Збільшено міжрядковий інтервал у терміналі** — `lineSpacing=6.0`, `paragraphSpacing=2.0` у `NSMutableParagraphStyle`. Рядки більше не зливаються при великому обсязі виводу.

- **Menu Bar → Сканування → Історія сканувань** (`⌘⇧H`) — окреме вікно зі списком всіх сканувань: кольорова таблиця (ID, режим, статус, URLs, Forms, Vulns, запити, час), деталі у нижній панелі, кнопки **📄 Відкрити звіт** / **🔍 Показати деталі** / **🗑 Видалити** / **🔄 Оновити**.
- **Кнопка "Відкрити звіт"** — знаходить HTML по точному `scan_id` через `--get-report` (з fallback на пошук у директорії для старих сканів).
- **Menu Bar → Payload-и → Завантажити payload-и** (`⌘⇧U`) — завантаження з мережі прямо з GUI, окремо по джерелах (PATT / SecLists / NVD).
- **Menu Bar → Payload-и → Статистика бази** — перегляд поточного стану `payloads.db`.
- **SSL CA bundle** — автовизначення шляху до CA-сертифікатів на macOS Homebrew; усуває проблему `CURLE_SSL_CACERT` при `--update`.

### Fixed — виправлення помилок

- Hash-таблиця `visited[]`: нескінченний цикл при переповненні → лічильник `vis_count`.
- Queue crawler: URL зникав після `visited_add()` → перевірка черги перенесена.
- `get_attr()`: некоректний `memchr()` size → перевірка `val >= te`.
- `parse_modules()`: `strncpy` без `'\0'` → `snprintf`.
- SSRF: `rate_wait()` після запиту замість до.
- Progress bar: подвійний рядок при паралельних потоках → `g_draw_mutex`.
- `--update`: подвійний банер при запуску → прибрано зайвий `print_banner()`.
- `--update` macOS: `CURLE_SSL_CACERT` через відсутній CA bundle → `set_ca_bundle()`.
- `--update`: всі URL PayloadsAllTheThings повертали HTTP 404 → оновлено актуальні шляхи (`Intruders/JHADDIX_XSS.txt`, `Intruder/Auth_Bypass.txt` тощо).
- GUI: вікно "Історія сканувань" неможливо було закрити → замінено `beginSheet` на `makeKeyAndOrderFront`, додано системні кнопки та кнопку `✕ Закрити`.
- GUI: кнопка "Відкрити звіт" не знаходила файл → тепер використовує `--get-report <scan_id>` з точним шляхом з БД.

### Нові CLI команди

| Команда | Опис |
|---|---|
| `--get-report <ID>` | Вивести шлях до HTML звіту сканування #ID |
| `--threads N` | Потоків для фази атак (авто: nproc×4, макс. 16) |
| `--update` | Оновити payload-и (PATT, SecLists, NVD) |
| `--update-source S` | Джерело: `patt`, `seclists`, `nvd` |
| `--payloads-db FILE` | Власний шлях до `payloads.db` |
| `--payloads-stats` | Статистика бази payload-ів по модулях |

---

## Документація

| Документ | Опис |
|---|---|
| [Посібник адміністратора](docs/admin-guide.md) | Встановлення, конфігурація, CI/CD, обслуговування |
| [Посібник користувача](docs/user-guide.md) | Сканування, інтерпретація результатів, email-звіти |
| [CHANGELOG](CHANGELOG.md) | Повна історія змін по версіях |
| [INSTALL](INSTALL.md) | Швидке встановлення |
| [CONTRIBUTING](CONTRIBUTING.md) | Як зробити внесок |
| [SECURITY](SECURITY.md) | Повідомлення про вразливості безпеки |

---

## Ліцензія

**GPL-2.0** © 2026 root_bsd \<root_bsd@itprof.net.ua\>

> ⚠️ Цей інструмент призначений **ТІЛЬКИ** для авторизованого тестування безпеки.  
> Несанкціоноване сканування є незаконним.
