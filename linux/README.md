# ScanXSS v1.3.1.1 — Web Vulnerability Scanner

> Автоматизований сканер вразливостей веб-застосунків з відкритим кодом.
> © 2026 root_bsd \<root_bsd@itprof.net.ua\> | GPL-2.0
> https://github.com/ROOT-BSD/scanxss

---

## Можливості

- **7 модулів атак:** XSS, SQLi, LFI, RCE, SSRF, Open Redirect, CRLF
- **BFS crawler** з O(1) visited hash-set, витягування посилань з non-HTML
- **Email-звіти** через STARTTLS — будь-який SMTP сервер, без зовнішніх бібліотек
- **Три платформи:** Linux, macOS (Cocoa GUI), Windows 11 (Win32 GUI)
- **SQLite БД** — збереження сканувань, resume, history
- **Звіти:** HTML (інтерактивний, OWASP/CWE) + TXT
- **AV bypass** — split-string payload-и, складаються в runtime
- **Цифровий підпис** EXE (self-signed, NSIS встановлює CA)

---

## Швидкий старт

### Linux / macOS CLI
```bash
cd linux
sudo apt install build-essential libcurl4-openssl-dev libssl-dev
make && make test
./scanxss -u https://target.com/
```

### macOS GUI
```bash
cd macos && sudo bash INSTALL.sh
# Відкриється /Applications/ScanXSS.app
```

### Windows
Запустити `windows/installer/scanxss-setup.exe` від **Адміністратора**.

Якщо Defender блокує до запуску:
```powershell
certutil -addstore -f "Root" "windows\installer\RootBSD-CA.cer"
```

---

## Використання CLI

```bash
# Базове сканування
./scanxss -u https://target.com/

# З параметрами
./scanxss -u https://target.com/ -d 3 -r 10 -m xss,sqli,lfi

# Налаштування SMTP для email-звітів
./scanxss --setup-email

# Список модулів
./scanxss --list-modules

# Повторити сканування з того ж місця
./scanxss -u https://target.com/ --resume

# Довідка
./scanxss --help
```

### Основні параметри

| Параметр | Опис | За замовчуванням |
|---|---|---|
| `-u URL` | Ціль сканування | — |
| `-d N` | Глибина crawl | 3 |
| `-r N` | Запитів на секунду | 10 |
| `-t N` | Таймаут (сек) | 10 |
| `-s SCOPE` | subdomain/domain/folder/url | subdomain |
| `-m MODULES` | xss,sqli,lfi,rce,ssrf,redirect,crlf | всі |
| `-c COOKIES` | Cookies для автентифікації | — |
| `-a UA` | User-Agent | Chrome |
| `--setup-email` | Майстер налаштування SMTP | — |

---

## Конфігураційний файл

Файл `scanxss.conf` шукається автоматично:
1. `./scanxss.conf`
2. `~/.scanxss/scanxss.conf`
3. `/etc/scanxss/scanxss.conf`

```ini
# Email-відправка звітів
email_enabled    = true
smtp_host        = mail.company.com
smtp_port        = 587
smtp_tls         = true
smtp_user        = scanxss@company.com
smtp_pass        = password
email_to         = security@company.com, ciso@company.com
email_from       = scanxss@company.com
email_only_vulns = true
email_attach_html = true
email_subject    = [ScanXSS] Report: %h — %v vuln(s) found (%d)

# Параметри сканування за замовчуванням
default_depth    = 3
default_rate     = 10
default_timeout  = 10
default_scope    = subdomain
default_modules  = xss,sqli,lfi,rce,ssrf
```

### Підтримувані SMTP сервери

| Сервер | smtp_host | smtp_port | smtp_tls |
|---|---|---|---|
| Postfix / Dovecot | mail.company.ua | 587 | true |
| Office 365 | smtp.office365.com | 587 | true |
| SendGrid | smtp.sendgrid.net | 587 | true |
| Локальний relay | localhost | 25 | false |

---

## Email-звіти після сканування

При знайдених вразливостях з'являється інтерактивне меню:

```
╔══════════════════════════════════════════════╗
║           Відправка звіту на e-mail          ║
╚══════════════════════════════════════════════╝
  Знайдено 3 вразливість(ей) на target.com

  [1] Відправити звіт на e-mail
  [2] Налаштувати поштовий сервер
  [3] Пропустити
```

---

## Модулі атак

| Модуль | Тип | Severity | CWE | CVSS |
|---|---|---|---|---|
| rce | Remote Code Execution | Critical | CWE-78, CWE-94 | 9.8 |
| sqli | SQL Injection | Critical | CWE-89 | 9.8 |
| lfi | Local File Inclusion | Critical | CWE-22 | 8.6 |
| ssrf | Server-Side Request Forgery | High | CWE-918 | 8.6 |
| xss | Cross-Site Scripting | High | CWE-79 | 7.4 |
| redirect | Open Redirect | Medium | CWE-601 | 6.1 |
| crlf | CRLF Injection | Medium | CWE-93 | 6.1 |

---

## Архітектура

```
src/
  main.c       — CLI, інтерактивне email-меню, --setup-email
  crawler.c    — BFS, O(1) hash-set, non-HTML link extraction
  attack.c     — оркестрація модулів
  http.c       — libcurl (gzip, SSL, redirects)
  email.c      — SMTP клієнт з STARTTLS (OpenSSL)
  config.c     — парсер scanxss.conf
  session.c    — SQLite сесії (per scan_id)
  report.c     — HTML + TXT звіти
  db.c         — база даних
modules/
  mod_xss.c    — probe-reflect + 8 payload-ів
  mod_sqli.c   — error-based, 6 payload-ів, 8 патернів
  mod_misc.c   — LFI, RCE, CRLF, Open Redirect
  mod_ssrf.c   — SSRF з baseline comparison
```

---

## Шляхи файлів

| ОС | БД | Звіти |
|---|---|---|
| Linux/BSD | `../DB_SCAN/scan.db` | `../report/<host>/` |
| macOS | `~/.scanxss/scan.db` | `~/Desktop/report/<host>/` |
| Windows | поряд з .exe | `Desktop\REPORT\<host>\` |

---

## Коди повернення (CI/CD)

| Код | Значення |
|---|---|
| `0` | Вразливостей не знайдено |
| `1` | Помилка |
| `2` | Знайдено вразливості |

```bash
# GitHub Actions / GitLab CI
./scanxss -u https://staging.example.com/ -m xss,sqli
[ $? -eq 2 ] && echo "VULNERABILITIES FOUND" && exit 1
```

---

## Збірка Windows (cross-compile на Linux)

```bash
sudo apt install mingw-w64 nsis osslsigncode
cd windows
make -f Makefile.win all
make -f Makefile.win installer
```

Підписання EXE:
```bash
osslsigncode sign \
    -pkcs12 installer/codesign.pfx -pass scanxss2026 \
    -n "ScanXSS Web Vulnerability Scanner" \
    -i "https://github.com/ROOT-BSD/scanxss" \
    -in scanxss-gui.exe -out scanxss-gui-signed.exe
```

---

## Зміни v1.3.1.1

- Нативний SMTP клієнт з STARTTLS (email.c + config.c)
- Інтерактивне меню email після сканування
- `--setup-email` — майстер налаштування SMTP
- Виправлено crawler: O(1) hash, session_url_visited по scan_id
- Windows: автозбереження звітів на Desktop\REPORT\
- Makefile: target `all` першим, session.c в OBJ
- JSON звіти видалено (HTML + TXT)
- macOS звіти: ~/Desktop/report/<host>/
- Банер з правильним вирівнюванням

---

## Ліцензія

**GPL-2.0** © 2026 root_bsd \<root_bsd@itprof.net.ua\>

> ⚠️ Цей інструмент призначений ТІЛЬКИ для авторизованого тестування безпеки.
> Несанкціоноване сканування є незаконним.
