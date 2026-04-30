# ScanXSS v1.3.3 — Посібник користувача

> Повсякденне використання: сканування, інтерпретація результатів, email-звіти.  
> Для встановлення і адміністрування дивіться [Посібник адміністратора](admin-guide.md).

---

## Зміст

1. [Перший запуск](#перший-запуск)
2. [Базове сканування](#базове-сканування)
3. [Параметри сканування](#параметри-сканування)
4. [Режими роботи](#режими-роботи)
5. [Модулі атак](#модулі-атак)
6. [Результати і звіти](#результати-і-звіти)
7. [Email-сповіщення](#email-сповіщення)
8. [Оновлення payload-ів](#оновлення-payload-ів)
9. [Робота з базою сканувань](#робота-з-базою-сканувань)
10. [Типові сценарії](#типові-сценарії)
11. [Часті питання](#часті-питання)

---

## Перший запуск

### Перевірка встановлення

```bash
./scanxss --version
# ScanXSS 1.3.3

./scanxss --payloads-stats
# Виводить таблицю payload-ів по модулях
```

### Перше сканування

```bash
./scanxss -u https://target.com/
```

ScanXSS автоматично:
1. Створить `~/.scanxss/payloads.db` з вбудованими payload-ами
2. Запустить BFS crawler — обходить сайт у ширину
3. Запустить модулі атак у паралельному режимі
4. Збереже результати у SQLite та згенерує HTML + TXT звіт
5. Запропонує надіслати звіт на email (при знайдених вразливостях)

### Структура виводу

```
Target: https://target.com/
Mode:   FULL  |  depth:3  timeout:10s  rate:10/s  threads:8 (auto)

⠴ Crawling   [████████████░░░░░░░░░░░░░░░░░░░]  38% 3/8  ETA:0:42  0:26  2.1req/s
✓ Crawling   [████████████████████████████████] 100% 8/8  0:51  1.9req/s

[Crawler] Done. pages=8  forms=3  reqs=16  skip(non-html)=4

⠴ Attacking  [████████▌░░░░░░░░░░░░░░░░░░░░░░]  27% 4/15  ETA:1:23  0:31  1.8req/s
✓ Attacking  [████████████████████████████████] 100% 15/15  2:14  1.9req/s

[Attack] Done. Vulnerabilities: 2

╔══════════════════════════════════════╗
║           ПІДСУМОК СКАНУВАННЯ        ║
╚══════════════════════════════════════╝
  Ціль:         https://target.com/
  Scan ID:      #28
  HTTP запитів: 127
  URL:          8
  Форм:         3
  Вразливості:  2 знайдено!
    • XSS          1
    • SQLi         1

  Тривалість:  3хв 5с  (0.7 req/s  |  127 req  |  185 сек)
```

---

## Базове сканування

### Мінімальна команда

```bash
./scanxss -u https://target.com/
```

### З автентифікацією (cookie)

```bash
# Отримайте cookie з браузера (DevTools → Application → Cookies)
./scanxss -u https://app.target.com/ \
  -c "session=eyJhbGci...; csrf_token=abc123"
```

### З проксі (Burp Suite, ZAP)

```bash
./scanxss -u https://target.com/ -p http://127.0.0.1:8080
```

### Повільне сканування (щоб не перевантажувати сервер)

```bash
./scanxss -u https://target.com/ -r 2 -t 30
```

---

## Параметри сканування

### Основні параметри

| Параметр | Опис | Приклад |
|---|---|---|
| `-u URL` | **Обов'язково.** Ціль сканування | `-u https://target.com/` |
| `-d N` | Глибина обходу (за замовч. 3) | `-d 5` |
| `-r N` | Запитів на секунду (за замовч. 10) | `-r 5` |
| `-t N` | HTTP таймаут у секундах (за замовч. 10) | `-t 30` |
| `-l N` | Макс. кількість URL (за замовч. 256) | `-l 512` |
| `-m MODULES` | Вибір модулів | `-m xss,sqli` |
| `--threads N` | Потоків атак (авто: nproc×4) | `--threads 4` |

### Область сканування (`-s SCOPE`)

| Значення | Поведінка | Коли використовувати |
|---|---|---|
| `url` | Тільки вказаний URL | Перевірка одної сторінки |
| `page` | URL і всі підшляхи | Розділ сайту |
| `folder` | Поточна директорія URL | Локальне тестування |
| `domain` | Тільки точний домен | `example.com` без піддоменів |
| `subdomain` | Усі піддомени (за замовч.) | `*.example.com` |

```bash
# Сканувати тільки один домен (без sub.target.com)
./scanxss -u https://target.com/ -s domain

# Сканувати тільки конкретний розділ
./scanxss -u https://target.com/app/ -s page
```

### Вибір User-Agent

```bash
# Chrome (за замовчуванням)
./scanxss -u https://target.com/

# Власний UA для обходу блокування
./scanxss -u https://target.com/ \
  -a "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15"

# Googlebot
./scanxss -u https://target.com/ \
  -a "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
```

---

## Режими роботи

### FULL — повне сканування (за замовчуванням)

```bash
./scanxss -u https://target.com/
```

Повний цикл: crawl → атаки → звіт.

### RESUME — продовжити перерване

```bash
./scanxss -u https://target.com/ --resume
```

Якщо сканування було перервано (Ctrl+C, збій), RESUME завантажує вже зібрані URL і форми і продовжує з того місця.

### RESCAN — нові атаки на збережений crawl

```bash
./scanxss -u https://target.com/ --rescan
```

Пропускає фазу crawl, запускає атаки на вже зібрані форми. Корисно коли хочете перевірити нові модулі або нові payload-и після `--update`.

```bash
# Rescan конкретного попереднього сканування
./scanxss -u https://target.com/ --rescan-from 25
```

### RETARGET — перевірка знайдених вразливостей

```bash
./scanxss -u https://target.com/ --retarget
```

Перевіряє чи досі присутні вразливості знайдені у попередньому скануванні. Корисно після виправлень розробниками:

```
[Retarget] Результати верифікації:
  [ACTIVE] xss      https://target.com/search  param=q
  [ FIXED] sqli     https://target.com/login   param=username
```

- `ACTIVE` — вразливість досі присутня
- `FIXED` — вразливість усунена
- `NEW` — знайдена нова вразливість

---

## Модулі атак

### Вибір модулів

```bash
# Тільки XSS і SQLi
./scanxss -u https://target.com/ -m xss,sqli

# Тільки критичні
./scanxss -u https://target.com/ -m rce,sqli,lfi

# Всі модулі (за замовчуванням)
./scanxss -u https://target.com/
```

### Опис модулів

| Модуль | Що шукає | Метод виявлення |
|---|---|---|
| `xss` | Cross-Site Scripting | Відбиття payload-у у відповіді |
| `sqli` | SQL Injection | DB-помилки + диференціальний аналіз |
| `lfi` | Local File Inclusion | Вміст системних файлів у відповіді |
| `rce` | Remote Code Execution | Вивід команд (`id`, `whoami`) |
| `ssrf` | Server-Side Request Forgery | Внутрішні адреси у відповіді |
| `redirect` | Open Redirect | Location-заголовок на зовнішній домен |
| `crlf` | CRLF Injection | Впроваджений заголовок у відповіді |

### SSRF з callback endpoint

Для виявлення blind SSRF (де відповідь не видно):

```bash
# Запустіть власний receiver (наприклад, requestbin.com або ngrok)
./scanxss -u https://target.com/ -m ssrf \
  --endpoint https://your-receiver.example.com/ssrf
```

---

## Результати і звіти

### Де знаходяться звіти

| ОС | Шлях |
|---|---|
| Linux | `../report/<hostname>/` відносно бінарника |
| macOS | `~/Desktop/report/<hostname>/` |
| Windows | `%USERPROFILE%\Desktop\REPORT\<hostname>\` |

### Формати звітів

**HTML звіт** — інтерактивний, з фільтрацією по severity:
- Зведена таблиця вразливостей
- OWASP/CWE класифікація
- Деталі кожної знахідки: URL, параметр, payload, evidence
- Рекомендації по виправленню

**TXT звіт** — для автоматизованої обробки і логування.

### Власний шлях звіту

```bash
# Конкретний файл
./scanxss -u https://target.com/ -o /tmp/report.html -f html
./scanxss -u https://target.com/ -o /tmp/report.txt  -f txt

# Власна директорія (авто-генерація імені)
./scanxss -u https://target.com/ --report-dir /var/reports/
```

### Інтерпретація результатів

**Severity рівні:**

| Рівень | Модулі | Що робити |
|---|---|---|
| Critical (5) | RCE, SQLi, LFI | Негайне виправлення |
| High (4) | XSS, SSRF | Виправити у поточному спринті |
| Medium (3) | Redirect, CRLF | Виправити у наступному спринті |

**Evidence — що означають записи:**

```
Reflected payload in response  → XSS: payload знайдено у відповіді
DB error or differential (...)  → SQLi: помилка БД або зміна розміру
File content in response        → LFI: вміст /etc/passwd у відповіді
Internal response indicator:... → SSRF: маркер внутрішньої мережі
Redirect to: https://evil.com  → Open Redirect: перенаправлення
CRLF header injected            → CRLF: впроваджений HTTP заголовок
```

---

## Email-сповіщення

### Налаштування

```bash
./scanxss --setup-email
```

Майстер запитає:
1. SMTP сервер і порт
2. Логін і пароль
3. Email відправника
4. Збереже у `~/.scanxss/scanxss.conf` з правами `0600`

### Відправка після сканування

При знайдених вразливостях ScanXSS автоматично пропонує:

```
╔══════════════════════════════════════════════╗
║           Відправка звіту на e-mail          ║
╚══════════════════════════════════════════════╝
  Знайдено 2 вразливість(ей) на target.com

  [1] Відправити звіт на e-mail
  [2] Налаштувати поштовий сервер
  [3] Пропустити

  Вибір [1-3]:
```

Оберіть `[1]`, введіть email отримувача — і звіт буде надіслано з HTML вкладенням.

### Відправка архівних звітів

```bash
./scanxss --email-history
```

Показує список всіх сканувань з вразливостями і дозволяє надіслати будь-який з них.

---

## Оновлення payload-ів

### Переглянути поточну базу

```bash
./scanxss --payloads-stats

# Приклад виводу:
# [Payloads DB] /Users/user/.scanxss/payloads.db
#   Модуль  Payloads   Markers     Hints
#   xss          972         6         0
#   sqli           3        10         0
#   ...
#   Останнє оновлення: 2026-04-19 07:50:38
```

### Оновлення з публічних джерел

```bash
# Оновити все (PayloadsAllTheThings + SecLists + NVD)
./scanxss --update

# Тільки PayloadsAllTheThings
./scanxss --update --update-source patt

# Тільки SecLists
./scanxss --update --update-source seclists

# Тільки NVD CVE Feed (аналіз останніх 30 днів)
./scanxss --update --update-source nvd
```

Дублі ігноруються — можна запускати повторно без наслідків.

---

## Робота з базою сканувань

### Переглянути список сканувань

```bash
./scanxss -u https://target.com/ --list-scans

# Виводить:
# ID     Mode       Status       URLs     Forms    Vulns    Reqs     Started
# 28     full       done         8        3        2        127      2026-04-19 07:30
# 27     full       done         8        3        0        124      2026-04-18 15:10
```

### Переглянути деталі сканування

```bash
./scanxss -u https://target.com/ --show-scan 28
```

### Отримати шлях до звіту по scan_id

```bash
./scanxss -u https://target.com/ --get-report 28
# /Users/user/Desktop/report/target.com/target.com_20260419_073012.html
```

Шлях зберігається у БД (`scans.html_path`) після кожного успішного сканування.
Для старих сканувань (до v1.3.3) поле може бути порожнім — шукайте файл у `~/Desktop/report/<hostname>/`.

### macOS GUI — Історія сканувань

У Menu Bar: **Сканування → 🗄 Історія сканувань...** (`⌘⇧H`)

Вікно з кольоровою таблицею всіх сканувань:

| Кнопка | Дія |
|---|---|
| 📄 Відкрити звіт | Знаходить HTML по scan_id через `--get-report`, відкриває у браузері |
| 🔍 Показати деталі | Виводить знахідки у термінальну панель |
| 🗑 Видалити | Видаляє сканування (з підтвердженням) |
| 🔄 Оновити | Перечитує список з БД |

### Retarget після виправлень

Типовий workflow після того як розробники зафіксували вразливості:

```bash
# 1. Перевіряємо що виправлено
./scanxss -u https://target.com/ --retarget

# 2. Якщо потрібно — повне повторне сканування
./scanxss -u https://target.com/ --rescan
```

---

## Типові сценарії

### Швидка перевірка нового сайту

```bash
./scanxss -u https://target.com/ -d 2 -r 15 -m xss,sqli
```

### Глибоке сканування з автентифікацією

```bash
./scanxss -u https://app.target.com/ \
  -d 5 \
  -r 10 \
  -l 512 \
  -c "sessionid=abc123; csrftoken=xyz" \
  -s domain \
  --threads 8
```

### Сканування через Burp Suite

```bash
# Burp Suite повинен бути запущений на 127.0.0.1:8080
./scanxss -u https://target.com/ \
  -p http://127.0.0.1:8080 \
  -r 3
# Всі запити ScanXSS будуть видні у Burp HTTP history
```

### Перевірка після хотфіксу

```bash
# Спочатку дивимось що було знайдено раніше
./scanxss -u https://target.com/ --list-scans

# Retarget — перевіряємо чи виправлено
./scanxss -u https://target.com/ --retarget

# Якщо є нові форми — rescan
./scanxss -u https://target.com/ --rescan
```

### Масове сканування (bash скрипт)

```bash
#!/bin/bash
TARGETS=(
  "https://site1.company.com"
  "https://site2.company.com"
  "https://api.company.com"
)

for target in "${TARGETS[@]}"; do
  echo "=== Scanning: $target ==="
  ./scanxss -u "$target" -m xss,sqli -r 5 --threads 4
  EXIT=$?
  if [ $EXIT -eq 2 ]; then
    echo "ВРАЗЛИВОСТІ ЗНАЙДЕНО на $target"
  fi
done
```

---

## Часті питання

**Q: Сайт блокує сканування (HTTP 403)?**

```bash
./scanxss -u https://target.com/ \
  -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**Q: Сайт на JavaScript (SPA React/Vue/Angular)?**

ScanXSS не виконує JavaScript. Для SPA-сайтів рекомендується:
1. Вручну зібрати список API-ендпоінтів
2. Використати `-u` з конкретними URL і `-s url`
3. Або використати headless браузер (Playwright/Puppeteer) для отримання sitemap

**Q: Як сканувати тільки один конкретний параметр?**

Поки що ScanXSS не підтримує фільтрацію по параметру. Використайте `-s url` для обмеження scope і `-m` для вибору модулів.

**Q: Що означає "ETA: --:--" у progress bar?**

Оцінка часу недоступна поки не виконано мінімум 2 HTTP-запити. Зазвичай з'являється через 5–10 секунд.

**Q: Як переглянути вже знайдені вразливості без нового сканування?**

```bash
./scanxss -u https://target.com/ --show-scan 28
```

**Q: Чи можна запускати кілька сканувань одночасно?**

Так, але вкажіть різні `--db` файли і обмежте `--threads` щоб не перевантажувати ціль:

```bash
# Термінал 1
./scanxss -u https://site1.com/ --db /tmp/scan1.db --threads 2 -r 5

# Термінал 2
./scanxss -u https://site2.com/ --db /tmp/scan2.db --threads 2 -r 5
```

**Q: Чому lfi знайшов 934 payload-и але xss тільки 9?**

При `--update` з SecLists завантажується великий список LFI payload-ів (~930 рядків). Це нормально — ширше покриття для LFI. Кількість payload-ів не впливає на швидкість якщо ціль їх не відбиває (для XSS є probe_reflects оптимізація).

**Q: Як додати власні payload-и?**

Payload-и зберігаються у `~/.scanxss/payloads.db` (SQLite). Можна додати через будь-який SQLite клієнт:

```bash
sqlite3 ~/.scanxss/payloads.db \
  "INSERT OR IGNORE INTO payloads(module,payload,source,priority)
   VALUES('xss','<script>alert(document.domain)</script>','custom',50);"
```

Пріоритет `50` означає що цей payload буде перевірений раніше вбудованих (`100`).

---

## 11. macOS GUI — покращення інтерфейсу v1.3.3

### Збільшені шрифти

Всі шрифти у macOS GUI збільшено для зручності читання:

- **Термінал** — Menlo 15pt (було 12pt)
- **Поля і кнопки** — 16pt (було 13pt)
- **Підписи полів** — 13pt (було 10pt)
- **Заголовок вікна** — 22pt (було 18pt)
- **Вікно "Історія сканувань"** — всі елементи збільшено на 3–4pt

### Міжрядковий інтервал у вікні сканування

Рядки у терміналі тепер мають збільшений інтервал — вивід сканера читається значно зручніше при великій кількості знайдених URL і вразливостей.

> Якщо текст виводиться занадто великим — зменшіть вікно або зменшіть кількість активних модулів (`-m xss,sqli`).
