# ScanXSS v1.3.3 — Посібник адміністратора

> Встановлення, конфігурація, обслуговування, CI/CD інтеграція.  
> Для повсякденного використання дивіться [Посібник користувача](user-guide.md).

---

## Зміст

1. [Системні вимоги](#системні-вимоги)
2. [Встановлення](#встановлення)
3. [Конфігурація](#конфігурація)
4. [Управління базою payload-ів](#управління-базою-payload-ів)
5. [База даних сканувань](#база-даних-сканувань)
6. [Email-сповіщення](#email-сповіщення)
7. [CI/CD інтеграція](#cicd-інтеграція)
8. [Безпека](#безпека)
9. [Обслуговування](#обслуговування)
10. [Діагностика](#діагностика)

---

## Системні вимоги

### Linux

| Компонент | Мінімум | Рекомендовано |
|---|---|---|
| ОС | Ubuntu 20.04 / Debian 11 / RHEL 8 | Ubuntu 22.04 LTS |
| CPU | 1 ядро | 4+ ядра (для `--threads`) |
| RAM | 128 МБ | 512 МБ |
| Диск | 50 МБ | 500 МБ (для звітів та БД) |
| libcurl | 7.68+ | 8.0+ |
| OpenSSL | 1.1.1+ | 3.0+ |
| SQLite | 3.31+ | 3.40+ |

```bash
# Перевірка версій залежностей
curl --version | head -1
openssl version
sqlite3 --version
```

### macOS

- macOS 12 Monterey або новіше
- Xcode Command Line Tools: `xcode-select --install`
- Homebrew: https://brew.sh

### Windows

- Windows 10 22H2 / Windows 11
- Права адміністратора для встановлення

---

## Встановлення

### Linux — збірка з вихідного коду

```bash
# Встановлення залежностей
# Ubuntu / Debian
sudo apt update && sudo apt install -y \
  build-essential libcurl4-openssl-dev libssl-dev

# RHEL / CentOS / Fedora
sudo dnf install -y gcc make libcurl-devel openssl-devel sqlite-devel

# Arch Linux
sudo pacman -S base-devel curl openssl sqlite

# Клонування та збірка
git clone https://github.com/ROOT-BSD/scanxss.git
cd scanxss/linux
make -j$(nproc)

# Перевірка
./scanxss --version
./scanxss --payloads-stats
```

### Linux — системна установка (опціонально)

```bash
sudo cp scanxss /usr/local/bin/
sudo mkdir -p /etc/scanxss
sudo cp scanxss.conf /etc/scanxss/scanxss.conf
sudo chmod 644 /etc/scanxss/scanxss.conf
```

### macOS — збірка

```bash
brew install curl openssl sqlite3 pkg-config
cd scanxss/macos
make -j$(sysctl -n hw.logicalcpu)
./scanxss --version
```

### macOS GUI

```bash
cd scanxss/macos
sudo bash INSTALL.sh
# Після встановлення відкривається /Applications/ScanXSS.app
```

### Windows

1. Запустити `windows/installer/scanxss-setup.exe` від Адміністратора
2. Якщо Windows Defender блокує:
```powershell
certutil -addstore -f "Root" "windows\installer\RootBSD-CA.cer"
```
3. Перезапустити `scanxss-setup.exe`

### Windows — cross-compile на Linux

```bash
sudo apt install mingw-w64 nsis osslsigncode
cd scanxss/windows
make -f Makefile.win all
make -f Makefile.win installer

# Підписання EXE (потребує codesign.pfx)
osslsigncode sign \
    -pkcs12 installer/codesign.pfx -pass YOUR_PASSWORD \
    -n "ScanXSS Web Vulnerability Scanner" \
    -i "https://github.com/ROOT-BSD/scanxss" \
    -in scanxss-gui.exe -out scanxss-gui-signed.exe
```

---

## Конфігурація

### Пріоритет файлів конфігурації

ScanXSS шукає `scanxss.conf` у такому порядку:

1. `./scanxss.conf` — поточна директорія (найвищий пріоритет)
2. `~/.scanxss/scanxss.conf` — домашня директорія користувача
3. `/etc/scanxss/scanxss.conf` — системна конфігурація

### Повний опис параметрів

```ini
# ── Email-сповіщення ─────────────────────────────────────────
email_enabled     = false          # true — відправляти звіти
smtp_host         = mail.company.com
smtp_port         = 587            # 587=STARTTLS, 25=plain, 465=SSL
smtp_tls          = true           # STARTTLS (рекомендовано для 587)
smtp_user         = scanxss@company.com
smtp_pass         = password       # Файл зберігається з правами 0600
email_from        = scanxss@company.com
email_to          = security@company.com, ciso@company.com
email_only_vulns  = true           # Відправляти тільки при вразливостях
email_attach_html = true           # Прикріпити HTML звіт
email_subject     = [ScanXSS] Report: %h — %v vuln(s) found (%d)
                    # %h = hostname, %v = кількість вразливостей, %d = дата

# ── Параметри сканування за замовчуванням ────────────────────
default_depth    = 3               # Глибина BFS crawl
default_rate     = 10              # Запитів/сек (rate limit)
default_timeout  = 10              # HTTP таймаут (сек)
default_scope    = subdomain       # url/page/folder/domain/subdomain
default_modules  = xss,sqli,lfi,rce,ssrf  # Активні модулі атак

# ── Шляхи (опціонально) ──────────────────────────────────────
# report_dir = /var/log/scanxss/reports
```

### Підтримувані SMTP сервери

| Сервер | smtp_host | smtp_port | smtp_tls |
|---|---|---|---|
| Postfix / Dovecot | mail.company.ua | 587 | true |
| Office 365 | smtp.office365.com | 587 | true |
| Gmail | smtp.gmail.com | 587 | true |
| SendGrid | smtp.sendgrid.net | 587 | true |
| Локальний relay | localhost | 25 | false |

### Налаштування SMTP через майстер

```bash
./scanxss --setup-email
# Майстер збереже ~/.scanxss/scanxss.conf з правами 0600
```

---

## Управління базою payload-ів

### Структура бази `~/.scanxss/payloads.db`

| Таблиця | Вміст |
|---|---|
| `payloads` | Рядки атак: payload, module, priority, source |
| `markers` | Маркери виявлення вразливості у відповіді |
| `hints` | Підказки по назвах параметрів (SSRF, Redirect) |
| `meta` | Метадані: версія схеми, час останнього оновлення |

### Команди управління

```bash
# Переглянути статистику
./scanxss --payloads-stats

# Оновлення з усіх джерел
./scanxss --update

# Вибіркове оновлення
./scanxss --update --update-source patt      # PayloadsAllTheThings
./scanxss --update --update-source seclists  # SecLists
./scanxss --update --update-source nvd       # NVD CVE Feed

# Власна БД для конкретного сканування
./scanxss -u https://target.com/ --payloads-db /path/to/payloads.db
```

### Корпоративна спільна БД

Для централізованого управління payload-ами у команді:

```bash
# Адміністратор: створює і наповнює спільну БД
mkdir -p /shared/security/scanxss
./scanxss --payloads-db /shared/security/scanxss/payloads.db --update
chmod 664 /shared/security/scanxss/payloads.db
chgrp security /shared/security/scanxss/payloads.db

# Користувачі: вказують спільну БД при скануванні
./scanxss -u https://target.com/ \
  --payloads-db /shared/security/scanxss/payloads.db
```

### Автоматичне оновлення (cron)

```bash
# Щотижневе оновлення payload-ів щопонеділка о 03:00
crontab -e
# Додати:
0 3 * * 1 /usr/local/bin/scanxss --update >> /var/log/scanxss-update.log 2>&1
```

---

## База даних сканувань

### Розташування

| ОС | Шлях до scan.db |
|---|---|
| Linux | `../DB_SCAN/scan.db` (відносно бінарника) |
| macOS | `~/.scanxss/scan.db` |
| Windows | поряд з .exe |

### Команди управління

```bash
# Список сканувань для цілі
./scanxss -u https://target.com/ --list-scans

# Деталі конкретного сканування (знахідки)
./scanxss -u https://target.com/ --show-scan 28

# Отримати шлях до HTML звіту по scan_id
./scanxss -u https://target.com/ --get-report 28
# Виводить: /Users/user/Desktop/report/target.com/target.com_20260419_073012.html

# Видалити одне сканування
./scanxss -u https://target.com/ --delete-scan 28

# Видалити всі дані цілі (з підтвердженням)
./scanxss -u https://target.com/ --wipe

# Власний шлях до БД
./scanxss -u https://target.com/ --db /var/lib/scanxss/scans.db
```

### Схема таблиці scans (v1.3.3+)

| Колонка | Тип | Опис |
|---|---|---|
| `id` | INTEGER PK | Унікальний ідентифікатор сканування |
| `target_id` | INTEGER FK | Посилання на таблицю targets |
| `mode` | TEXT | `full` / `resume` / `rescan` / `retarget` |
| `modules` | INTEGER | Bitmask активних модулів |
| `started_at` | INTEGER | Unix timestamp початку |
| `finished_at` | INTEGER | Unix timestamp завершення |
| `requests` | INTEGER | Кількість HTTP запитів |
| `urls_found` | INTEGER | Знайдено URL |
| `forms_found` | INTEGER | Знайдено форм |
| `vulns_found` | INTEGER | Знайдено вразливостей |
| `status` | TEXT | `running` / `done` / `interrupted` |
| `html_path` | TEXT | **Новий v1.3.3** — абсолютний шлях до HTML звіту |

> При оновленні з попередніх версій: `html_path` додається автоматично через `ALTER TABLE` при першому запуску. Для старих сканувань поле порожнє.

### Резервне копіювання

```bash
# Ручне резервне копіювання
cp ~/.scanxss/scan.db     ~/.scanxss/scan.db.bak.$(date +%Y%m%d)
cp ~/.scanxss/payloads.db ~/.scanxss/payloads.db.bak.$(date +%Y%m%d)

# Автоматичне через cron
0 2 * * * cp ~/.scanxss/scan.db ~/.scanxss/scan.db.bak.$(date +\%Y\%m\%d) 2>/dev/null
```

---

## CI/CD інтеграція

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * 1'   # Щопонеділка о 02:00
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install ScanXSS
        run: |
          sudo apt install -y libcurl4-openssl-dev libssl-dev
          git clone https://github.com/ROOT-BSD/scanxss.git
          cd scanxss/linux && make -j$(nproc)
          sudo cp scanxss /usr/local/bin/

      - name: Update payloads
        run: scanxss --update

      - name: Scan staging
        run: |
          scanxss -u ${{ secrets.STAGING_URL }} \
            -m xss,sqli,lfi \
            --threads 4 \
            -r 5
          EXIT=$?
          if [ $EXIT -eq 2 ]; then
            echo "::error::Знайдено вразливості!"
            exit 1
          fi
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - apt install -y libcurl4-openssl-dev libssl-dev
    - git clone https://github.com/ROOT-BSD/scanxss.git
    - cd scanxss/linux && make -j$(nproc)
    - ./scanxss -u $STAGING_URL -m xss,sqli -r 5
    - '[ $? -ne 2 ] || (echo "Вразливості знайдено" && exit 1)'
  only:
    - main
    - merge_requests
```

### Jenkins (Groovy)

```groovy
stage('Security Scan') {
    steps {
        sh '''
            cd scanxss/linux
            ./scanxss -u ${STAGING_URL} -m xss,sqli,lfi --threads 4 -r 5
            if [ $? -eq 2 ]; then
                echo "SECURITY: Вразливості знайдено!"
                exit 1
            fi
        '''
    }
}
```

### Коди повернення

| Код | Значення | Дія в CI |
|---|---|---|
| `0` | Вразливостей не знайдено | ✅ Pipeline успішний |
| `1` | Помилка (мережа, конфіг) | ⚠️ Investigate |
| `2` | Знайдено вразливості | ❌ Pipeline провалений |

---

## Безпека

### Права доступу до файлів

```bash
# Конфіг зі SMTP паролем — тільки власник (автоматично при --setup-email)
ls -la ~/.scanxss/scanxss.conf
# Має бути: -rw------- (0600)

# Виправити вручну якщо потрібно
chmod 0600 ~/.scanxss/scanxss.conf
chmod 0700 ~/.scanxss/
```

### Рекомендації для CI/CD середовища

```bash
# Обмежити scope — тільки конкретний домен
./scanxss -u https://staging.example.com/ -s domain

# Обмежити rate — не перевантажувати staging
./scanxss -u https://staging.example.com/ -r 5

# НЕ скануйте production без явного дозволу
```

### Зберігання credentials

Не зберігайте SMTP пароль у відкритому тексті у `.env` або скриптах.  
Використовуйте GitHub Secrets, Vault або інший secrets менеджер:

```bash
# GitHub Actions: Settings → Secrets → SMTP_PASS
# Потім у workflow:
- run: echo "smtp_pass = ${{ secrets.SMTP_PASS }}" >> ~/.scanxss/scanxss.conf
```

---

## Обслуговування

### Очищення старих звітів

```bash
# Видалити звіти старші 30 днів
find ~/Desktop/report/ -name "*.html" -mtime +30 -delete
find ~/Desktop/report/ -name "*.txt"  -mtime +30 -delete

# Через cron (щодня о 04:00)
0 4 * * * find ~/Desktop/report -mtime +30 -delete 2>/dev/null
```

### Оновлення ScanXSS

```bash
cd scanxss
git pull origin main
cd linux && make clean && make -j$(nproc)
./scanxss --version
# Оновити payload-и після оновлення коду
./scanxss --update
```

---

## Діагностика

### Crawler нічого не знайшов

```
[!] Zero pages crawled.
```

| Симптом | Причина | Рішення |
|---|---|---|
| HTTP 403/503 | Сайт блокує сканер | `-a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'` |
| HTTP 401 | Потрібна авторизація | `-c 'session=YOUR_TOKEN'` |
| HTTP 429 | Rate limit сервера | `-r 2` або `-r 1` |
| 0 scope | Посилання за межами домену | `-v` для деталей, перевірте `-s` |
| SPA сайт | JS-рендеринг на клієнті | Потрібен headless браузер |

### Email не надсилається

```bash
# Запустити майстер для перевірки налаштувань
./scanxss --setup-email

# Перевірити права файлу конфігу
ls -la ~/.scanxss/scanxss.conf   # має бути -rw------- (0600)
```

### `--update` повертає "недоступно"

```
xss → [HTTP 403] недоступно
```

| HTTP-код | Причина | Рішення |
|---|---|---|
| 403 | GitHub блокує IP/User-Agent | Перевірте мережу, спробуйте VPN |
| 404 | URL застарів | Оновіть ScanXSS (`git pull`) |
| Без коду | DNS або мережева помилка | `curl -v https://raw.githubusercontent.com` |

```bash
# Діагностика вручну
curl -v -A "Mozilla/5.0" \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt" \
  | head -5
```

### Збірка провалюється

```bash
# Перевірте залежності
pkg-config --libs libcurl
pkg-config --libs openssl
sqlite3 --version

# Детальний вивід компілятора
make VERBOSE=1 2>&1 | head -30
```

---

## 9. macOS GUI — адміністрування

### Встановлення

```bash
cd scanxss/macos
sudo bash INSTALL.sh
# Встановлює /Applications/ScanXSS.app
```

### Menu Bar — нові пункти (v1.3.3)

| Меню | Пункт | Дія |
|---|---|---|
| Сканування | 🗄 Історія сканувань... `⌘⇧H` | Таблиця всіх сканувань з БД |
| Payload-и | ⬇ Завантажити payload-и `⌘⇧U` | Оновлення з PATT/SecLists/NVD |
| Payload-и | Джерела: PATT / SecLists / NVD | Вибіркове оновлення |
| Payload-и | 📊 Статистика бази | Поточний стан payloads.db |

### Вікно "Історія сканувань"

- Кольорова таблиця: ID (синій), статус done/running, Vulns > 0 (червоний)
- Деталь-рядок: при виборі рядка показує повну інформацію по скануванню
- **📄 Відкрити звіт** — використовує `--get-report <scan_id>` → точний HTML по ID
- **🗑 Видалити** — підтвердження перед видаленням

### Проблема SSL при --update на macOS

Якщо `--update` повертає `[curl err 60: SSL certificate problem]`:

```bash
# Перевірте наявність CA bundle
ls /etc/ssl/cert.pem
ls /opt/homebrew/etc/ca-certificates/cert.pem

# Або встановіть через Homebrew:
brew install ca-certificates
```

ScanXSS автоматично знаходить CA bundle за стандартними шляхами (перевіряється у порядку пріоритету при кожному `--update`).

---

## 10. macOS GUI — типографіка v1.3.3

### Збільшені шрифти

У версії 1.3.3 всі шрифти у macOS GUI збільшено для кращої читабельності:

| Елемент | Було | Стало |
|---|---|---|
| Термінал (Menlo, AppDelegate) | 12pt | 15pt |
| Термінал (Menlo, ScanHistoryHelper) | 11pt | 14pt |
| UI шрифт (_ui) | 13pt | 16pt |
| Підписи полів (_label) | 10pt | 13pt |
| Заголовок вікна | 18pt | 22pt |
| Підзаголовок header | 11pt | 14pt |
| Labels у панелях | 11pt | 14pt |
| Кнопки дій | 13pt | 16pt |
| History: заголовок | 15pt | 18pt |
| History: лічильник | 11pt | 14pt |
| History: заголовки колонок | 11pt | 14pt |
| History: detail text | 11pt | 14pt |
| History: кнопки | 12pt | 15pt |
| History: висота рядків | 28px | 34px |

### Міжрядковий інтервал у терміналі

Додано `NSMutableParagraphStyle` у метод `appendLine:color:`:

```objc
NSMutableParagraphStyle *ps = [[NSMutableParagraphStyle alloc] init];
ps.lineSpacing      = 6.0;   // відстань між рядками
ps.paragraphSpacing = 2.0;   // відступ після кожного рядка
ps.lineBreakMode    = NSLineBreakByCharWrapping;
```

Це усуває ефект "злиття рядків" при великому обсязі виводу під час сканування.
