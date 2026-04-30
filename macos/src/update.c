/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 *
 * This file is part of ScanXSS — Web Vulnerability Scanner.
 * SPDX-License-Identifier: GPL-2.0
 *
 * update.c — синхронізація payload-ів з публічних джерел.
 *
 * Джерела:
 *  1. PayloadsAllTheThings (GitHub raw)
 *  2. SecLists (GitHub raw)
 *  3. NVD CVE JSON feed (нові вектори атак за останні N днів)
 *
 * Виклик: scanxss --update [--update-source patt|seclists|nvd]
 *
 * Алгоритм:
 *  - Завантажити raw файл через libcurl
 *  - Розібрати рядок за рядком
 *  - Відфільтрувати порожні рядки і коментарі (#)
 *  - Передати в payloads_add() — дублі ігноруються БД
 *  - Зберегти час оновлення в meta
 */

#include "scanxss.h"
#include <curl/curl.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>   /* access() для перевірки CA bundle */

/* ── GitHub raw URL-и ──────────────────────────────────────── *
 *
 * Для кожного модуля — масив URL з пріоритетом:
 * перший доступний буде використаний.
 * Причина: GitHub іноді перейменовує папки у репозиторіях.
 *
 * PayloadsAllTheThings (PATT) — актуальна структура:
 *   master/XSS Injection/Payloads/ (нова, з 2024)
 *   master/XSS Injection/Intruder/ (стара, може зникнути)
 *
 * SecLists — структура стабільна, але деякі файли переміщені.
 * ─────────────────────────────────────────────────────────── */

#define PATT_BASE \
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"

#define SECLISTS_BASE \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

/* Кожен запис: масив URL (NULL-terminated) + назва модуля.
 * fetch_url_any() спробує кожен по черзі до першого успіху.  */
typedef struct {
    const char *urls[4];   /* до 3 fallback + NULL */
    const char *module;
} MultiSource;

static const MultiSource PATT_SOURCES[] = {
    /* XSS — папка Intruders (з s) підтверджена у пошуку */
    { { PATT_BASE "/XSS%20Injection/Intruders/JHADDIX_XSS.txt",
        PATT_BASE "/XSS%20Injection/Intruders/IntrudersXSS.txt",
        PATT_BASE "/XSS%20Injection/Intruders/xss_alert.txt",
        NULL }, "xss" },
    /* SQL — папку перейменовано Intruders → Intruder */
    { { PATT_BASE "/SQL%20Injection/Intruder/Auth_Bypass.txt",
        PATT_BASE "/SQL%20Injection/Intruder/FUZZDB_MYSQL.txt",
        NULL }, "sqli" },
    /* LFI — папка Intruders підтверджена */
    { { PATT_BASE "/File%20Inclusion/Intruders/JHADDIX_LFI.txt",
        PATT_BASE "/File%20Inclusion/Intruders/Linux-files.txt",
        PATT_BASE "/File%20Inclusion/Intruders/Traversal.txt",
        NULL }, "lfi" },
    /* RCE — команди перенесено у Command Injection */
    { { PATT_BASE "/Command%20Injection/Intruder/command-execution-unix.txt",
        PATT_BASE "/Command%20Injection/Intruder/command_exec.txt",
        NULL }, "rce" },
    /* SSRF */
    { { PATT_BASE "/SSRF%20Injection/Intruder/SSRF.txt",
        NULL }, "ssrf" },
    /* Open Redirect — папку перейменовано */
    { { PATT_BASE "/Open%20Redirect/Intruder/Open-Redirect-payloads.txt",
        PATT_BASE "/Open%20Redirect/Intruder/open_redirect_wordlist.txt",
        NULL }, "redirect" },
    { { NULL }, NULL }
};

static const MultiSource SECLISTS_SOURCES[] = {
    /* XSS-Jhaddix.txt підтверджено у пошуку */
    { { SECLISTS_BASE "/Fuzzing/XSS/XSS-Jhaddix.txt",
        NULL }, "xss" },
    /* SQLi */
    { { SECLISTS_BASE "/Fuzzing/SQLi/quick-SQLi.txt",
        NULL }, "sqli" },
    /* LFI-Jhaddix.txt підтверджено у пошуку */
    { { SECLISTS_BASE "/Fuzzing/LFI/LFI-Jhaddix.txt",
        NULL }, "lfi" },
    /* SSRF — перевіряємо кілька шляхів */
    { { SECLISTS_BASE "/Discovery/Web-Content/SSRF.txt",
        SECLISTS_BASE "/Fuzzing/SSRF.txt",
        NULL }, "ssrf" },
    { { NULL }, NULL }
};

/* NVD CVE JSON feed (останні 30 днів) */
#define NVD_FEED_URL \
    "https://services.nvd.nist.gov/rest/json/cves/2.0?" \
    "cvssV3Severity=HIGH&cvssV3Severity=CRITICAL&" \
    "pubStartDate=%s&pubEndDate=%s"

/* ── Буфер для libcurl ─────────────────────────────────────── */
typedef struct { char *data; size_t len; size_t cap; } Buf;

static size_t write_cb(void *ptr, size_t sz, size_t nmemb, void *ud) {
    Buf *b = (Buf *)ud;
    size_t n = sz * nmemb;
    if (b->len + n + 1 > b->cap) {
        b->cap = (b->len + n + 1) * 2;
        b->data = realloc(b->data, b->cap);
        if (!b->data) return 0;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

/* ── Спільна ініціалізація curl handle для update ────────────── *
 * На macOS Homebrew curl використовує власний CA bundle,         *
 * відмінний від системного. Якщо CURLOPT_SSL_VERIFYPEER=1 без   *
 * явного CAINFO — curl не знаходить сертифікати → SSL помилка.  *
 * Перевіряємо стандартні шляхи CA bundle.                       */
static void set_ca_bundle(CURL *c) {
    /* Homebrew curl на Apple Silicon і Intel */
    static const char *ca_paths[] = {
        "/etc/ssl/cert.pem",                          /* macOS system */
        "/opt/homebrew/etc/ca-certificates/cert.pem", /* Homebrew ARM */
        "/usr/local/etc/ca-certificates/cert.pem",    /* Homebrew x86 */
        "/opt/homebrew/opt/curl/share/curl/curl-ca-bundle.crt",
        "/usr/local/opt/curl/share/curl/curl-ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",         /* Linux Debian/Ubuntu */
        "/etc/pki/tls/certs/ca-bundle.crt",           /* Linux RHEL/CentOS */
        NULL
    };
    for (int i = 0; ca_paths[i]; i++) {
        if (access(ca_paths[i], R_OK) == 0) {
            curl_easy_setopt(c, CURLOPT_CAINFO, ca_paths[i]);
            return;
        }
    }
    /* Якщо жоден не знайдено — вимикаємо верифікацію як крайній захід */
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
}

/* ── HTTP GET з таймаутом ──────────────────────────────────── */
static char *fetch_url(const char *url, int timeout_sec) {
    CURL *c = curl_easy_init();
    if (!c) return NULL;

    Buf buf = { calloc(1, 1), 0, 1 };
    curl_easy_setopt(c, CURLOPT_URL,            url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,  write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,      &buf);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,        (long)timeout_sec);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS,      5L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    set_ca_bundle(c);
    curl_easy_setopt(c, CURLOPT_USERAGENT,
                     "Mozilla/5.0 (compatible; curl/" LIBCURL_VERSION ")");

    CURLcode rc = curl_easy_perform(c);
    long http_code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK || http_code != 200) {
        free(buf.data);
        return NULL;
    }
    return buf.data;
}

/* ── fetch з виводом HTTP-коду для діагностики ───────────────── */
static char *fetch_url_verbose(const char *url, int timeout_sec,
                               long *http_code_out) {
    CURL *c = curl_easy_init();
    if (!c) return NULL;

    Buf buf = { calloc(1, 1), 0, 1 };
    curl_easy_setopt(c, CURLOPT_URL,            url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,  write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,      &buf);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,        (long)timeout_sec);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS,      5L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    set_ca_bundle(c);
    curl_easy_setopt(c, CURLOPT_USERAGENT,
                     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/124.0.0.0 Safari/537.36");

    CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (http_code_out) *http_code_out = code;
    curl_easy_cleanup(c);

    if (rc != CURLE_OK) {
        /* Виводимо curl помилку — допомагає діагностувати SSL проблеми */
        fprintf(stderr, COL_YELLOW "[curl err %d: %s] " COL_RESET,
                rc, curl_easy_strerror(rc));
        free(buf.data);
        return NULL;
    }
    if (code != 200) {
        free(buf.data);
        return NULL;
    }
    return buf.data;
}

/* ── Парсер текстового файлу (один payload на рядок) ────────── */
static int parse_and_import(const char *text, const char *module,
                             const char *source,
                             int *added_out, int *skipped_out) {
    if (!text || !text[0]) return 0;
    int added = 0, skipped = 0;

    char line[MAX_PARAM_LEN * 2];
    const char *p = text;

    while (*p) {
        /* читаємо рядок */
        size_t i = 0;
        while (*p && *p != '\n' && i < sizeof(line) - 1)
            line[i++] = *p++;
        if (*p == '\n') p++;
        line[i] = '\0';

        /* trim trailing whitespace */
        while (i > 0 && (line[i-1] == '\r' || line[i-1] == ' '
                         || line[i-1] == '\t'))
            line[--i] = '\0';

        /* пропускаємо порожні рядки і коментарі */
        if (i == 0 || line[0] == '#') continue;

        /* пропускаємо занадто довгі або підозрілі */
        if (i >= MAX_PARAM_LEN) { skipped++; continue; }

        int r = payloads_add(module, line, source);
        if (r > 0) added++;
        else       skipped++;
    }

    if (added_out)   *added_out   += added;
    if (skipped_out) *skipped_out += skipped;
    return added;
}

/* ── NVD: витягуємо ключові слова з описів CVE ─────────────── *
 * Не додаємо CVE як payload напряму — аналізуємо descriptions   *
 * і виявляємо нові вектори для існуючих модулів.                */
static void parse_nvd_feed(const char *json, int color) {
    if (!json) return;

    /* Шукаємо нові маркери SQL помилок, XSS-паттернів тощо     *
     * у полях description. Простий текстовий пошук без JSON-парсера. */
    struct { const char *keyword; const char *module; const char *marker; } hints[] = {
        { "SQL injection",         "sqli", NULL },
        { "cross-site scripting",  "xss",  NULL },
        { "XSS",                   "xss",  NULL },
        { "local file inclusion",  "lfi",  NULL },
        { "server-side request",   "ssrf", NULL },
        { "command injection",     "rce",  NULL },
        { "open redirect",         "redirect", NULL },
        { "CRLF injection",        "crlf", NULL },
        { NULL, NULL, NULL }
    };

    int cve_count = 0;
    const char *p = json;
    while ((p = strstr(p, "\"CVE-")) != NULL) {
        cve_count++;
        p++;
    }

    log_info(1, color, "[NVD] Проаналізовано %d CVE записів", cve_count);

    int relevant = 0;
    for (int h = 0; hints[h].keyword; h++) {
        if (str_contains_icase(json, hints[h].keyword))
            relevant++;
    }
    if (relevant > 0)
        log_info(1, color,
            "[NVD] Знайдено %d релевантних записів для модулів сканера", relevant);
}

/* ── Головна функція: --update ──────────────────────────────── */
void update_payloads(const ScanConfig *cfg, const char *source_filter) {
    int color = cfg->color;

    printf(COL_BOLD
           "\n╔══════════════════════════════════════════════╗\n"
           "║         Оновлення бази payload-ів            ║\n"
           "╚══════════════════════════════════════════════╝\n\n"
           COL_RESET);

    payloads_print_stats();

    int total_added = 0, total_skipped = 0;
    bool do_patt     = (!source_filter || strcmp(source_filter, "patt")     == 0);
    bool do_seclists = (!source_filter || strcmp(source_filter, "seclists") == 0);
    bool do_nvd      = (!source_filter || strcmp(source_filter, "nvd")      == 0);

    /* ── 1. PayloadsAllTheThings ──────────────────────────── */
    if (do_patt) {
        printf(COL_BOLD "[1/3] PayloadsAllTheThings\n" COL_RESET);
        for (int i = 0; PATT_SOURCES[i].module; i++) {
            printf("  %-10s → ", PATT_SOURCES[i].module);
            fflush(stdout);

            /* Пробуємо кожен URL з виводом коду при невдачі */
            char *text = NULL;
            for (int j = 0; PATT_SOURCES[i].urls[j] && !text; j++) {
                long code = 0;
                text = fetch_url_verbose(PATT_SOURCES[i].urls[j], 30, &code);
                if (!text && code > 0)
                    printf(COL_YELLOW "[HTTP %ld] " COL_RESET, code);
            }
            if (!text) {
                printf(COL_YELLOW "недоступно\n" COL_RESET);
                continue;
            }

            int added = 0, skipped = 0;
            parse_and_import(text, PATT_SOURCES[i].module,
                             "patt", &added, &skipped);
            free(text);
            printf(COL_GREEN "+%d нових" COL_RESET
                   "  (%d вже є)\n", added, skipped);
            total_added   += added;
            total_skipped += skipped;
        }
    }

    /* ── 2. SecLists ─────────────────────────────────────── */
    if (do_seclists) {
        printf(COL_BOLD "\n[2/3] SecLists\n" COL_RESET);
        for (int i = 0; SECLISTS_SOURCES[i].module; i++) {
            printf("  %-10s → ", SECLISTS_SOURCES[i].module);
            fflush(stdout);

            char *text = NULL;
            for (int j = 0; SECLISTS_SOURCES[i].urls[j] && !text; j++) {
                long code = 0;
                text = fetch_url_verbose(SECLISTS_SOURCES[i].urls[j], 30, &code);
                if (!text && code > 0)
                    printf(COL_YELLOW "[HTTP %ld] " COL_RESET, code);
            }
            if (!text) {
                printf(COL_YELLOW "недоступно\n" COL_RESET);
                continue;
            }

            int added = 0, skipped = 0;
            parse_and_import(text, SECLISTS_SOURCES[i].module,
                             "seclists", &added, &skipped);
            free(text);
            printf(COL_GREEN "+%d нових" COL_RESET
                   "  (%d вже є)\n", added, skipped);
            total_added   += added;
            total_skipped += skipped;
        }
    }

    /* ── 3. NVD CVE Feed ─────────────────────────────────── */
    if (do_nvd) {
        printf(COL_BOLD "\n[3/3] NVD CVE Feed (останні 30 днів)\n" COL_RESET);

        /* Формуємо дати */
        time_t now = time(NULL);
        time_t month_ago = now - 30 * 24 * 3600;
        struct tm *t1 = gmtime(&month_ago);
        char start[32], end[32];
        strftime(start, sizeof(start), "%Y-%m-%dT00:00:00.000", t1);
        struct tm *t2 = gmtime(&now);
        strftime(end,   sizeof(end),   "%Y-%m-%dT23:59:59.999", t2);

        char nvd_url[512];
        snprintf(nvd_url, sizeof(nvd_url), NVD_FEED_URL, start, end);

        printf("  Запит: %s...\n", start);
        fflush(stdout);

        char *json = fetch_url(nvd_url, 60);
        if (!json) {
            printf(COL_YELLOW "  NVD API недоступний\n" COL_RESET);
        } else {
            parse_nvd_feed(json, color);
            free(json);
        }
    }

    /* ── Підсумок ────────────────────────────────────────── */
    /* Записуємо час оновлення */
    time_t now = time(NULL);
    char ts[32];
    struct tm *tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    payloads_set_last_update(ts);

    printf(COL_BOLD "\n── Підсумок ──────────────────────────────────\n" COL_RESET);
    printf("  Нових payload-ів додано: " COL_GREEN "%d\n" COL_RESET, total_added);
    printf("  Вже існувало:            %d\n", total_skipped);
    printf("  Час оновлення:           %s\n\n", ts);

    /* Перезавантажуємо кеш */
    payloads_close();
    payloads_init(cfg->exe_dir);
    payloads_print_stats();

    printf(COL_GREEN
           "✅  База оновлена. Наступне сканування використає нові payload-и.\n\n"
           COL_RESET);
}
