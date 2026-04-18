# Changelog — ScanXSS

Всі значущі зміни до цього проєкту документуються тут.
Формат базується на [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.3.2] — 2026-04-18

### Security (критичні виправлення безпеки)

- **[CVE-class] Shell injection через `popen()` з мережевих даних** (`main.c`)
  Hostname, отриманий з `target_url`, вставлявся напряму в shell-команду
  `ls -t ".../*.html" | head -1` через `popen()`. Зловмисний hostname
  (наприклад `$(rm -rf ~)`) виконував довільний код на машині оператора.
  **Замінено** на `find_newest_file()` — чистий POSIX `opendir`/`readdir`/`stat`
  без жодного виклику shell.

- **[CVE-class] RCE через `system()` при відкритті браузера (macOS)** (`main.c`)
  Шлях до HTML-звіту, отриманий з `popen("ls ...")`, передавався в
  `system("open \"<path>\" &")`. Підконтрольний шлях → виконання коду.
  **Замінено** на `open_in_browser()` — `fork()` + `execve("/usr/bin/open", argv, NULL)`
  без shell-інтерпретації.

- **SMTP-пароль зберігався з небезпечними правами доступу** (`main.c`)
  `~/.scanxss/scanxss.conf` відкривався через `fopen(path, "w")`, права
  файлу успадковувались від `umask` процесу (зазвичай `0644` — читабельно
  для всіх). **Замінено** на `open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600)` +
  `fdopen()` — файл тепер завжди створюється з правами `rw-------`.

### Fixed (виправлення помилок)

- **Hash-таблиця `visited[]`: нескінченний цикл при переповненні** (`crawler.c`)
  При повній таблиці `visited_check()` обходила всі 8192 слоти перед
  поверненням `true`. `visited_add()` додатково викликав `visited_check()`
  — подвійний повний обхід. Додано лічильник `vis_count` і поріг
  `VIS_MAX_FILL` (75% = 6144 слоти): перевірка переповнення — O(1),
  пошук вільного слота і дедуплікація об'єднані в один прохід.

- **Circular queue crawler: URL зникав після `visited_add()`** (`crawler.c`)
  Перевірка повноти черги виконувалась після `visited_add()`: URL
  позначався відвіданим, але в чергу не потрапляв і ніколи не сканувався.
  **Виправлено**: перевірка черги перенесена до `visited_add()`.

- **`get_attr()`: некоректний розмір у `memchr()`** (`crawler.c`)
  `memchr(val, q, (size_t)(te - val + 128))` — якщо `val > te`,
  від'ємна різниця після касту до `size_t` давала величезне число →
  читання за межами буфера. **Виправлено**: додана перевірка
  `if (val >= te) return 0` перед `memchr`.

- **`parse_modules()`: `strncpy` без гарантованого нуль-термінатора** (`main.c`)
  `strncpy(buf, s, 511)` не додає `'\0'` якщо рядок довший за 511 байт.
  Подальший `strtok()` міг читати за межами буфера.
  **Замінено** на `snprintf(buf, sizeof(buf), "%s", s)`.

- **`mod_ssrf.c`: `rate_wait()` викликався після HTTP-запиту** (`mod_ssrf.c`)
  В усіх інших модулях rate limiter спрацьовував до запиту. У SSRF —
  після, що повністю нейтралізувало `-r` обмеження для цього модуля.
  Порядок виправлено у рефакторингу спільної функції `fire()`.

### Changed

- Додано `#include <dirent.h>` та `<fcntl.h>` в `main.c` (потрібні для
  `opendir`, `open` з `O_CREAT`).
- Функція `find_newest_file()` та `open_in_browser()` додані як статичні
  хелпери на початку `main.c` — доступні для всіх платформ.

---

## [1.3.1.1] — 2026-04-17

### Added
- Нативний SMTP клієнт з STARTTLS (`email.c` + `config.c`) — без зовнішніх бібліотек
- Інтерактивне меню email після сканування при знайдених вразливостях
- `--setup-email` — майстер налаштування SMTP
- `--email-history` — відправка архівних звітів на e-mail

### Fixed
- Crawler: O(1) hash-set, `session_url_visited` прив'язаний до `scan_id`
- Windows: автозбереження звітів у `Desktop\REPORT\`
- macOS: звіти зберігаються у `~/Desktop/report/<host>/`
- Makefile: `target all` першим, `session.c` в `OBJ`
- Банер: правильне вирівнювання рамки

### Removed
- JSON звіти (залишено HTML + TXT)

---

## [1.3.1] — 2026-02-10

### Added
- SQLite БД — збереження сканувань, resume, history
- `--resume`, `--rescan`, `--retarget`, `--rescan-from` режими
- `--list-scans`, `--show-scan`, `--delete-scan`, `--wipe` команди
- Звіти: HTML (інтерактивний, OWASP/CWE) + TXT + JSON

### Changed
- BFS crawler з глобальним O(1) hash-set для visited URL
- Email-звіти через STARTTLS

---

## [1.3.0] — 2026-01-15

### Added
- 7 модулів атак: XSS, SQLi, LFI, RCE, SSRF, Open Redirect, CRLF
- macOS Cocoa GUI (`macos/gui/`)
- Windows 11 Win32 GUI (`windows/`)
- Rate limiter (`-r N` запитів/сек)
- Proxy підтримка (`-p URL`)
- Cookie автентифікація (`-c COOKIE`)
- SSRF callback endpoint (`--endpoint URL`)
- Коди повернення для CI/CD (0 / 1 / 2)

---

*© 2026 root_bsd <root_bsd@itprof.net.ua> | GPL-2.0*
