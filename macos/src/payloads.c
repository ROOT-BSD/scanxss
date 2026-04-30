/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 *
 * This file is part of ScanXSS — Web Vulnerability Scanner.
 * SPDX-License-Identifier: GPL-2.0
 *
 * payloads.c — зовнішня SQLite БД payload-ів.
 *
 * Замість жорстко закодованих масивів у кожному модулі,
 * payload-и завантажуються з payloads.db і кешуються в пам'яті.
 * Оновлення payload-ів не потребує перекомпіляції.
 *
 * Схема БД:
 *   payloads(id, module, payload, enabled, priority, source, added_at)
 *   markers (id, module, marker,  enabled, source, added_at)
 *   hints   (id, module, hint,    enabled, source, added_at)
 *   meta    (key, value)
 */

#include "scanxss.h"
#include "sqlite3.h"
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>

/* ── Внутрішній кеш ────────────────────────────────────────── */
typedef struct {
    char **items;   /* NULL-terminated масив рядків */
    int    count;
} StrList;

typedef struct {
    StrList payloads[PL_MODULE_COUNT];
    StrList markers [PL_MODULE_COUNT];
    StrList hints   [PL_MODULE_COUNT];
    bool    loaded;
} PayloadCache;

static PayloadCache g_cache;
static sqlite3     *g_db;
static char         g_db_path[512];

/* ── Вбудовані fallback payload-и ─────────────────────────── *
 * Використовуються якщо payloads.db відсутній або пошкоджений  */

static const char *BUILTIN_PAYLOADS[PL_MODULE_COUNT][32] = {
    /* PL_XSS */
    { "<script>alert(1)</script>",
      "\"><script>alert(1)</script>",
      "<img src=x onerror=alert(1)>",
      "<svg onload=alert(1)>",
      "';alert(1);//",
      "<body onload=alert(1)>",
      "<input autofocus onfocus=alert(1)>",
      "<details open ontoggle=alert(1)>",
      "<iframe src=javascript:alert(1)>",
      "javascript:alert(1)",
      NULL },
    /* PL_SQLI */
    { "'",
      "\"",
      "' OR '1'='1",
      "' OR 1=1--",
      "1 AND 1=2 UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' AND SLEEP(3)--",
      "'; WAITFOR DELAY '0:0:3'--",
      "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
      NULL },
    /* PL_LFI */
    { "../../../../etc/passwd",
      "../../../../windows/win.ini",
      "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "....//....//etc/passwd",
      "php://filter/read=convert.base64-encode/resource=index.php",
      "/proc/self/environ",
      "../../../../etc/shadow",
      NULL },
    /* PL_RCE */
    { ";id", "|id", "$(id)", "`id`", "&& id",
      ";whoami", "|whoami", ";cat /etc/passwd",
      NULL },
    /* PL_SSRF */
    { "http://127.0.0.1/",
      "http://localhost/",
      "http://169.254.169.254/",
      "http://169.254.169.254/latest/meta-data/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://[::1]/",
      "http://0.0.0.0/",
      "http://127.0.0.1:22/",
      "http://127.0.0.1:6379/",
      "http://127.0.0.1:9200/",
      "file:///etc/passwd",
      "dict://127.0.0.1:11211/stat",
      NULL },
    /* PL_REDIRECT */
    { "https://scanxss-check.invalid/",
      "//scanxss-check.invalid/",
      "https:scanxss-check.invalid",
      NULL },
    /* PL_CRLF */
    { "%0d%0aX-ScanXSS:injected",
      "%0aX-ScanXSS:injected",
      "\r\nX-ScanXSS:injected",
      NULL },
};

static const char *BUILTIN_MARKERS[PL_MODULE_COUNT][16] = {
    /* PL_XSS */
    { "<script>alert(1)</script>", "onerror=alert(1)", "onload=alert(1)",
      "onfocus=alert(1)", "ontoggle=alert(1)", "javascript:alert(1)", NULL },
    /* PL_SQLI */
    { "you have an error in your sql syntax", "warning: mysql",
      "unclosed quotation mark", "quoted string not properly terminated",
      "ora-0", "sqlite3.operationalerror", "pg::syntaxerror",
      "syntax error in query", "mysql_fetch", "db2 sql error", NULL },
    /* PL_LFI */
    { "root:x:0:0:", "daemon:x:", "[boot loader]", "[extensions]", NULL },
    /* PL_RCE */
    { "uid=", "root:x:", "www-data", NULL },
    /* PL_SSRF */
    { "ami-id", "instance-id", "local-ipv4", "computeMetadata",
      "MSI_ENDPOINT", "root:x:0:0:", "REDIS", "elasticsearch", "+PONG", NULL },
    /* PL_REDIRECT */ { NULL },
    /* PL_CRLF */    { "X-ScanXSS", NULL },
};

static const char *BUILTIN_HINTS[PL_MODULE_COUNT][24] = {
    /* PL_XSS */      { NULL },
    /* PL_SQLI */     { NULL },
    /* PL_LFI */      { NULL },
    /* PL_RCE */      { NULL },
    /* PL_SSRF */
    { "url","uri","src","source","href","link","redirect","location",
      "target","dest","destination","path","file","load","fetch",
      "host","site","endpoint","callback","proxy","remote", NULL },
    /* PL_REDIRECT */
    { "url","uri","redirect","redir","next","goto","return","location",
      "dest","destination","target","href","link","path","src", NULL },
    /* PL_CRLF */     { NULL },
};

/* ── Ім'я модуля → індекс ──────────────────────────────────── */
static int module_idx(const char *name) {
    static const char *names[] = {
        "xss","sqli","lfi","rce","ssrf","redirect","crlf", NULL
    };
    for (int i = 0; names[i]; i++)
        if (strcmp(names[i], name) == 0) return i;
    return -1;
}

/* ── Пошук шляху до payloads.db ────────────────────────────── */
static void resolve_db_path(const char *exe_dir) {
    /* 1. Явно заданий через --payloads-db */
    if (g_db_path[0]) return;

    const char *home = getenv("HOME");

    /* 2. ~/.scanxss/payloads.db */
    if (home) {
        snprintf(g_db_path, sizeof(g_db_path), "%s/.scanxss/payloads.db", home);
        if (access(g_db_path, F_OK) == 0) return;
    }

    /* 3. Поряд з бінарником */
    if (exe_dir && exe_dir[0]) {
        snprintf(g_db_path, sizeof(g_db_path), "%s/payloads.db", exe_dir);
        if (access(g_db_path, F_OK) == 0) return;
    }

    /* 4. ./payloads.db */
    snprintf(g_db_path, sizeof(g_db_path), "./payloads.db");
    if (access(g_db_path, F_OK) == 0) return;

    /* Не знайдено — залишаємо шлях за замовчуванням */
    if (home)
        snprintf(g_db_path, sizeof(g_db_path), "%s/.scanxss/payloads.db", home);
    else
        snprintf(g_db_path, sizeof(g_db_path), "./payloads.db");
}

/* ── Схема БД ──────────────────────────────────────────────── */
static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA foreign_keys=ON;"

    "CREATE TABLE IF NOT EXISTS meta ("
    "  key   TEXT PRIMARY KEY,"
    "  value TEXT NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS payloads ("
    "  id        INTEGER PRIMARY KEY,"
    "  module    TEXT    NOT NULL,"        /* xss, sqli, lfi, ... */
    "  payload   TEXT    NOT NULL,"
    "  enabled   INTEGER NOT NULL DEFAULT 1,"
    "  priority  INTEGER NOT NULL DEFAULT 100,"  /* менше = вище */
    "  source    TEXT    NOT NULL DEFAULT 'builtin',"
    "  added_at  INTEGER DEFAULT (strftime('%s','now')),"
    "  UNIQUE(module, payload)"
    ");"

    "CREATE TABLE IF NOT EXISTS markers ("
    "  id       INTEGER PRIMARY KEY,"
    "  module   TEXT    NOT NULL,"
    "  marker   TEXT    NOT NULL,"
    "  enabled  INTEGER NOT NULL DEFAULT 1,"
    "  source   TEXT    NOT NULL DEFAULT 'builtin',"
    "  added_at INTEGER DEFAULT (strftime('%s','now')),"
    "  UNIQUE(module, marker)"
    ");"

    "CREATE TABLE IF NOT EXISTS hints ("
    "  id       INTEGER PRIMARY KEY,"
    "  module   TEXT    NOT NULL,"
    "  hint     TEXT    NOT NULL,"
    "  enabled  INTEGER NOT NULL DEFAULT 1,"
    "  source   TEXT    NOT NULL DEFAULT 'builtin',"
    "  added_at INTEGER DEFAULT (strftime('%s','now')),"
    "  UNIQUE(module, hint)"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_payloads_module  ON payloads(module, enabled, priority);"
    "CREATE INDEX IF NOT EXISTS idx_markers_module   ON markers (module, enabled);"
    "CREATE INDEX IF NOT EXISTS idx_hints_module     ON hints   (module, enabled);";

/* ── Вставка рядка з ігноруванням дублів ──────────────────── */
static void insert_or_ignore(const char *table, const char *col,
                              const char *module, const char *value,
                              const char *source) {
    char sql[1024];
    if (strcmp(table, "payloads") == 0)
        snprintf(sql, sizeof(sql),
            "INSERT OR IGNORE INTO payloads(module,payload,source,priority)"
            " VALUES('%s','%s','%s',100);",
            module, value, source);
    else if (strcmp(table, "markers") == 0)
        snprintf(sql, sizeof(sql),
            "INSERT OR IGNORE INTO markers(module,marker,source)"
            " VALUES('%s','%s','%s');",
            module, value, source);
    else
        snprintf(sql, sizeof(sql),
            "INSERT OR IGNORE INTO hints(module,hint,source)"
            " VALUES('%s','%s','%s');",
            module, value, source);
    (void)col;
    sqlite3_exec(g_db, sql, NULL, NULL, NULL);
}

/* ── Наповнення вбудованими даними ─────────────────────────── */
static void seed_builtins(void) {
    static const char *mnames[] = {
        "xss","sqli","lfi","rce","ssrf","redirect","crlf"
    };
    sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL);
    for (int m = 0; m < PL_MODULE_COUNT; m++) {
        for (int i = 0; BUILTIN_PAYLOADS[m][i]; i++)
            insert_or_ignore("payloads","payload", mnames[m],
                             BUILTIN_PAYLOADS[m][i], "builtin");
        for (int i = 0; BUILTIN_MARKERS[m][i]; i++)
            insert_or_ignore("markers","marker",  mnames[m],
                             BUILTIN_MARKERS[m][i], "builtin");
        for (int i = 0; BUILTIN_HINTS[m][i];   i++)
            insert_or_ignore("hints",  "hint",    mnames[m],
                             BUILTIN_HINTS[m][i],   "builtin");
    }

    /* Версія схеми */
    sqlite3_exec(g_db,
        "INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version','1');"
        "INSERT OR IGNORE INTO meta(key,value) VALUES('db_version','" SCANXSS_VERSION "');",
        NULL, NULL, NULL);
    sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
}

/* ── Завантаження StrList з БД ─────────────────────────────── */
static void load_strlist(StrList *sl, const char *sql) {
    sl->count = 0;
    sl->items = NULL;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return;

    /* Перший прохід — рахуємо */
    int cap = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) cap++;
    sqlite3_reset(stmt);

    if (cap == 0) { sqlite3_finalize(stmt); return; }

    /* +1 для NULL-термінатора */
    sl->items = calloc((size_t)(cap + 1), sizeof(char *));
    if (!sl->items) { sqlite3_finalize(stmt); return; }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < cap) {
        const char *txt = (const char *)sqlite3_column_text(stmt, 0);
        if (txt) sl->items[idx++] = strdup(txt);
    }
    sl->items[idx] = NULL;
    sl->count = idx;
    sqlite3_finalize(stmt);
}

/* ── Публічний API ─────────────────────────────────────────── */

void payloads_set_db_path(const char *path) {
    snprintf(g_db_path, sizeof(g_db_path), "%s", path);
}

int payloads_init(const char *exe_dir) {
    if (g_cache.loaded) return 0;

    resolve_db_path(exe_dir);

    /* Створити директорію якщо не існує */
    {
        char dir[512];
        snprintf(dir, sizeof(dir), "%s", g_db_path);
        char *d = dirname(dir);
        struct stat st;
        if (stat(d, &st) != 0)
            mkdir(d, 0700);
    }

    int rc = sqlite3_open(g_db_path, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr,
            COL_YELLOW "[payloads] Не вдалось відкрити %s — використовую вбудовані\n"
            COL_RESET, g_db_path);
        g_db = NULL;
        /* Завантажуємо вбудовані напряму в кеш */
        goto load_builtin_fallback;
    }

    sqlite3_exec(g_db, SCHEMA, NULL, NULL, NULL);
    seed_builtins();

    /* Завантажуємо кеш з БД */
    {
        static const char *mnames[] = {
            "xss","sqli","lfi","rce","ssrf","redirect","crlf"
        };
        char sql[256];
        for (int m = 0; m < PL_MODULE_COUNT; m++) {
            snprintf(sql, sizeof(sql),
                "SELECT payload FROM payloads"
                " WHERE module='%s' AND enabled=1"
                " ORDER BY priority ASC, id ASC;", mnames[m]);
            load_strlist(&g_cache.payloads[m], sql);

            snprintf(sql, sizeof(sql),
                "SELECT marker FROM markers"
                " WHERE module='%s' AND enabled=1"
                " ORDER BY id ASC;", mnames[m]);
            load_strlist(&g_cache.markers[m], sql);

            snprintf(sql, sizeof(sql),
                "SELECT hint FROM hints"
                " WHERE module='%s' AND enabled=1"
                " ORDER BY id ASC;", mnames[m]);
            load_strlist(&g_cache.hints[m], sql);
        }
    }
    g_cache.loaded = true;
    return 0;

load_builtin_fallback:
    /* Заповнюємо кеш вбудованими масивами */
    for (int m = 0; m < PL_MODULE_COUNT; m++) {
        int n;
        /* payloads */
        for (n = 0; BUILTIN_PAYLOADS[m][n]; n++);
        g_cache.payloads[m].items = calloc((size_t)(n+1), sizeof(char *));
        for (int i = 0; i < n; i++)
            g_cache.payloads[m].items[i] = strdup(BUILTIN_PAYLOADS[m][i]);
        g_cache.payloads[m].count = n;

        /* markers */
        for (n = 0; BUILTIN_MARKERS[m][n]; n++);
        g_cache.markers[m].items = calloc((size_t)(n+1), sizeof(char *));
        for (int i = 0; i < n; i++)
            g_cache.markers[m].items[i] = strdup(BUILTIN_MARKERS[m][i]);
        g_cache.markers[m].count = n;

        /* hints */
        for (n = 0; BUILTIN_HINTS[m][n]; n++);
        g_cache.hints[m].items = calloc((size_t)(n+1), sizeof(char *));
        for (int i = 0; i < n; i++)
            g_cache.hints[m].items[i] = strdup(BUILTIN_HINTS[m][i]);
        g_cache.hints[m].count = n;
    }
    g_cache.loaded = true;
    return 0;
}

void payloads_close(void) {
    for (int m = 0; m < PL_MODULE_COUNT; m++) {
        if (g_cache.payloads[m].items) {
            for (int i = 0; i < g_cache.payloads[m].count; i++)
                free(g_cache.payloads[m].items[i]);
            free(g_cache.payloads[m].items);
        }
        if (g_cache.markers[m].items) {
            for (int i = 0; i < g_cache.markers[m].count; i++)
                free(g_cache.markers[m].items[i]);
            free(g_cache.markers[m].items);
        }
        if (g_cache.hints[m].items) {
            for (int i = 0; i < g_cache.hints[m].count; i++)
                free(g_cache.hints[m].items[i]);
            free(g_cache.hints[m].items);
        }
    }
    memset(&g_cache, 0, sizeof(g_cache));
    if (g_db) { sqlite3_close(g_db); g_db = NULL; }
}

const char **payloads_get(PlModule m) {
    if ((int)m < 0 || m >= PL_MODULE_COUNT) return NULL;
    return (const char **)g_cache.payloads[m].items;
}

const char **payloads_markers(PlModule m) {
    if ((int)m < 0 || m >= PL_MODULE_COUNT) return NULL;
    return (const char **)g_cache.markers[m].items;
}

const char **payloads_hints(PlModule m) {
    if ((int)m < 0 || m >= PL_MODULE_COUNT) return NULL;
    return (const char **)g_cache.hints[m].items;
}

int payloads_count(PlModule m) {
    if ((int)m < 0 || m >= PL_MODULE_COUNT) return 0;
    return g_cache.payloads[m].count;
}

/* ── Статистика БД ─────────────────────────────────────────── */
void payloads_print_stats(void) {
    static const char *mnames[] = {
        "xss","sqli","lfi","rce","ssrf","redirect","crlf"
    };
    printf(COL_BOLD "\n[Payloads DB] %s\n" COL_RESET, g_db_path);
    printf("  %-10s  %8s  %8s  %8s\n", "Модуль", "Payloads", "Markers", "Hints");
    printf("  %-10s  %8s  %8s  %8s\n",
           "----------","--------","--------","--------");
    int tp=0, tm=0, th=0;
    for (int m = 0; m < PL_MODULE_COUNT; m++) {
        printf("  %-10s  %8d  %8d  %8d\n",
               mnames[m],
               g_cache.payloads[m].count,
               g_cache.markers [m].count,
               g_cache.hints   [m].count);
        tp += g_cache.payloads[m].count;
        tm += g_cache.markers [m].count;
        th += g_cache.hints   [m].count;
    }
    printf("  %-10s  %8d  %8d  %8d\n", "TOTAL", tp, tm, th);

    if (g_db) {
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(g_db,
                "SELECT value FROM meta WHERE key='last_update';",
                -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *ts = (const char *)sqlite3_column_text(stmt, 0);
                if (ts) printf("\n  Останнє оновлення: %s\n", ts);
            }
            sqlite3_finalize(stmt);
        }
    }
    printf("\n");
}

/* ── Додавання окремого payload-у (для --update) ───────────── */
int payloads_add(const char *module, const char *payload, const char *source) {
    if (!g_db) return -1;
    int idx = module_idx(module);
    if (idx < 0) return -1;

    char sql[2048];
    /* Екранування одинарних лапок */
    char safe_payload[MAX_PARAM_LEN * 2];
    size_t j = 0;
    for (size_t i = 0; payload[i] && j < sizeof(safe_payload)-2; i++) {
        if (payload[i] == '\'') safe_payload[j++] = '\'';
        safe_payload[j++] = payload[i];
    }
    safe_payload[j] = '\0';

    snprintf(sql, sizeof(sql),
        "INSERT OR IGNORE INTO payloads(module,payload,source,priority)"
        " VALUES('%s','%s','%s',200);",
        module, safe_payload, source ? source : "external");

    int rc = sqlite3_exec(g_db, sql, NULL, NULL, NULL);

    /* Якщо додано — оновлюємо кеш */
    if (rc == SQLITE_OK && sqlite3_changes(g_db) > 0) {
        /* Додаємо в кінець масиву кешу */
        StrList *sl = &g_cache.payloads[idx];
        sl->items = realloc(sl->items,
                           (size_t)(sl->count + 2) * sizeof(char *));
        if (sl->items) {
            sl->items[sl->count]   = strdup(payload);
            sl->items[sl->count+1] = NULL;
            sl->count++;
        }
        return 1;  /* додано нове */
    }
    return 0;  /* вже існував або помилка */
}

int payloads_add_marker(const char *module, const char *marker,
                        const char *source) {
    if (!g_db) return -1;
    int idx = module_idx(module);
    if (idx < 0) return -1;

    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT OR IGNORE INTO markers(module,marker,source)"
        " VALUES('%s','%s','%s');",
        module, marker, source ? source : "external");
    sqlite3_exec(g_db, sql, NULL, NULL, NULL);

    if (sqlite3_changes(g_db) > 0) {
        StrList *sl = &g_cache.markers[idx];
        sl->items = realloc(sl->items,
                           (size_t)(sl->count + 2) * sizeof(char *));
        if (sl->items) {
            sl->items[sl->count]   = strdup(marker);
            sl->items[sl->count+1] = NULL;
            sl->count++;
        }
        return 1;
    }
    return 0;
}

/* ── Запис часу оновлення ──────────────────────────────────── */
void payloads_set_last_update(const char *timestamp) {
    if (!g_db) return;
    char sql[256];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO meta(key,value) VALUES('last_update','%s');",
        timestamp);
    sqlite3_exec(g_db, sql, NULL, NULL, NULL);
}
