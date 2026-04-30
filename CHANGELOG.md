# Changelog — ScanXSS

Всі значущі зміни до цього проєкту документуються тут.
Формат базується на [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.3.3] — 2026-04-24

### Changed — macOS GUI типографіка (2026-04-30)

- **Збільшено розміри шрифтів** у всіх елементах інтерфейсу:
  - Термінал (Menlo): 12pt → 15pt (AppDelegate), 11pt → 14pt (ScanHistoryHelper)
  - UI шрифт (`_ui`): 13pt → 16pt
  - Підписи полів (`_label`): 10pt → 13pt
  - Заголовок вікна: 18pt → 22pt
  - Підзаголовок у header: 11pt → 14pt
  - Labels у панелях: 11pt → 14pt
  - Кнопки дій: 13pt → 16pt
  - History: заголовок 15pt → 18pt, лічильник 11pt → 14pt, заголовки колонок 11pt → 14pt, detail text 11pt → 14pt, кнопки 12pt → 15pt, висота рядків 28px → 34px
- **Збільшено міжрядковий інтервал у терміналі** через `NSMutableParagraphStyle`:
  - `lineSpacing = 6.0` — відстань між рядками
  - `paragraphSpacing = 2.0` — відступ після кожного рядка


### Added — зовнішня БД payload-ів та прискорення сканування

- **`src/payloads.c`** — SQLite-база `~/.scanxss/payloads.db` замість жорстко
  закодованих масивів. Таблиці: `payloads`, `markers`, `hints`, `meta`.
  Fallback на вбудовані дані якщо файл відсутній. Кеш в пам'яті.

- **`src/update.c`** — синхронізація payload-ів з мережі (`--update`):
  PayloadsAllTheThings, SecLists, NVD CVE Feed (останні 30 днів).

- **`src/worker.c`** — pthread worker pool для паралельних атак:
  до 16 потоків, кожна пара (form × module) — окрема задача,
  `attack_add_vuln()` захищено `pthread_mutex`.

- **`http_head()`** — HEAD-запит без тіла. Crawler перевіряє Content-Type
  перед GET і пропускає `image/*`, `audio/*`, `video/*`, `font/*`,
  `application/pdf`, `application/zip`, `application/octet-stream`.

- **`http_multi_get()`** — curl Multi API, до 8 паралельних GET без потоків.

- **Кешування baseline у `Form.baseline_len`**: SQLi читає baseline з кешу
  замість окремого HTTP-запиту — 1 запит на форму замість N.

### Changed

- Всі модулі атак (`mod_xss.c`, `mod_sqli.c`, `mod_misc.c`, `mod_ssrf.c`)
  переписані: статичні масиви → `payloads_get()` / `payloads_markers()`.
- `attack.c`: паралельне виконання через worker pool.
- `Makefile`: `-lpthread`, нові об'єкти `src_payloads.o`, `src_update.o`,
  `src_worker.o`.

### Нові CLI опції

| Опція | Опис |
|---|---|
| `--threads N` | Потоків для фази атак (за замовч. 4, макс. 16) |
| `--update` | Оновити payload-и з PayloadsAllTheThings, SecLists, NVD |
| `--update-source S` | Вибіркове джерело: `patt`, `seclists`, `nvd` |
| `--payloads-db FILE` | Власний шлях до `payloads.db` |
| `--payloads-stats` | Статистика бази по модулях |

### Очікуване прискорення

| Сценарій | Було | Стало |
|---|---|---|
| Сайт з медіа (50% бінарних URL) | 100% часу | ~60% |
| Фаза атак (4 потоки) | 100% часу | ~25–30% |
| SQLi baseline (кеш) | N req/форму | 1 req/форму |


### Added — macOS GUI та БД звітів

- **macOS GUI: Menu Bar → Сканування → Історія сканувань** (`⌘⇧H`) — таблиця всіх сканувань з кнопками відкриття звіту, показу деталей, видалення, оновлення.
- **macOS GUI: Menu Bar → Payload-и** — завантаження з PATT/SecLists/NVD прямо з GUI.
- **`scans.html_path`** — нова колонка у БД. Зберігає абсолютний шлях до HTML звіту після кожного сканування. Автоматична міграція існуючих БД через `ALTER TABLE`.
- **`--get-report <ID>`** — виводить шлях до HTML звіту по scan_id. Використовується GUI для точного відкриття звіту.
- **SSL CA bundle (macOS)** — `set_ca_bundle()` автоматично знаходить CA-сертифікати для Homebrew curl.

### Fixed — macOS GUI

- Вікно "Історія сканувань" неможливо закрити → замінено `beginSheet` на `makeKeyAndOrderFront`.
- Кнопка "Відкрити звіт" не знаходила файл → використовує `--get-report <scan_id>`.
- Подвійний банер при `--update` → прибрано зайвий `print_banner()`.
- `--update` повертав HTTP 404 → оновлено URL PayloadsAllTheThings.
- `--update` macOS SSL помилка → `set_ca_bundle()` з автовизначенням шляху.


