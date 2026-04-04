#include "scanxss.h"
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>

/* ── helpers ──────────────────────────────────────────────── */
static sqlite3 *db(ScanContext *ctx) { return (sqlite3 *)ctx->db; }

static int exec(ScanContext *ctx, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db(ctx), sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[session] SQL error: %s\n", err ? err : "?");
        sqlite3_free(err);
    }
    return rc;
}

/* ── schema ───────────────────────────────────────────────── */
static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "CREATE TABLE IF NOT EXISTS urls("
    "  id    INTEGER PRIMARY KEY,"
    "  url   TEXT UNIQUE NOT NULL,"
    "  ts    INTEGER DEFAULT (strftime('%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS forms("
    "  id     INTEGER PRIMARY KEY,"
    "  url    TEXT NOT NULL,"
    "  method INTEGER NOT NULL,"       /* 0=GET 1=POST */
    "  fields TEXT NOT NULL"           /* JSON-like: name=val&name2=val2 */
    ");"
    "CREATE TABLE IF NOT EXISTS vulns("
    "  id        INTEGER PRIMARY KEY,"
    "  type      INTEGER NOT NULL,"
    "  url       TEXT    NOT NULL,"
    "  parameter TEXT    NOT NULL,"
    "  payload   TEXT    NOT NULL,"
    "  evidence  TEXT    NOT NULL,"
    "  severity  INTEGER NOT NULL,"
    "  module    TEXT    NOT NULL,"
    "  found_at  INTEGER DEFAULT (strftime('%s','now'))"
    ");";

/* ── open / create ────────────────────────────────────────── */
int session_open(ScanContext *ctx) {
    const char *dir = ctx->config.session_dir[0]
                      ? ctx->config.session_dir : "/tmp/scanxss-sessions";

    /* mkdir -p */
    struct stat st;
    if (stat(dir, &st) != 0) {
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[session] Cannot create dir %s: %s\n",
                    dir, strerror(errno));
            return -1;
        }
    }

    /* derive DB filename from target URL (replace /:) */
    char dbpath[768];
    char safe[256] = {0};
    const char *u = ctx->config.target_url;
    /* skip scheme */
    if (strncmp(u, "http://",  7) == 0) u += 7;
    if (strncmp(u, "https://", 8) == 0) u += 8;
    size_t i = 0;
    for (; *u && i < sizeof(safe)-1; u++)
        safe[i++] = (*u == '/' || *u == ':' || *u == '?' || *u == '&') ? '_' : *u;
    snprintf(dbpath, sizeof(dbpath), "%s/%s.db", dir, safe);

    sqlite3 *handle = NULL;
    if (sqlite3_open(dbpath, &handle) != SQLITE_OK) {
        fprintf(stderr, "[session] Cannot open DB %s: %s\n",
                dbpath, sqlite3_errmsg(handle));
        sqlite3_close(handle);
        return -1;
    }
    ctx->db = handle;

    if (ctx->config.flush_session) {
        session_flush(ctx);
    }

    if (exec(ctx, SCHEMA) != SQLITE_OK) {
        sqlite3_close(handle);
        ctx->db = NULL;
        return -1;
    }

    printf("[Session] DB: %s\n", dbpath);
    return 0;
}

void session_close(ScanContext *ctx) {
    if (ctx->db) { sqlite3_close(db(ctx)); ctx->db = NULL; }
}

void session_flush(ScanContext *ctx) {
    exec(ctx, "DROP TABLE IF EXISTS urls;"
              "DROP TABLE IF EXISTS forms;"
              "DROP TABLE IF EXISTS vulns;");
    printf("[Session] Flushed.\n");
}

/* ── URL tracking ─────────────────────────────────────────── */
int session_save_url(ScanContext *ctx, const char *url) {
    if (!ctx->db) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(db(ctx),
        "INSERT OR IGNORE INTO urls(url) VALUES(?)", -1, &s, NULL);
    sqlite3_bind_text(s, 1, url, -1, SQLITE_STATIC);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return 0;
}

int session_url_visited(ScanContext *ctx, const char *url) {
    if (!ctx->db) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(db(ctx),
        "SELECT 1 FROM urls WHERE url=? LIMIT 1", -1, &s, NULL);
    sqlite3_bind_text(s, 1, url, -1, SQLITE_STATIC);
    int found = (sqlite3_step(s) == SQLITE_ROW);
    sqlite3_finalize(s);
    return found;
}

/* ── Form persistence ─────────────────────────────────────── */
int session_save_form(ScanContext *ctx, const Form *f) {
    if (!ctx->db) return 0;
    /* serialise fields as "name=value&..." */
    char fields[2048] = {0};
    for (int i = 0; i < f->field_count; i++) {
        if (i) strncat(fields, "&", sizeof(fields)-strlen(fields)-1);
        strncat(fields, f->fields[i].name,  sizeof(fields)-strlen(fields)-1);
        strncat(fields, "=",                sizeof(fields)-strlen(fields)-1);
        strncat(fields, f->fields[i].value, sizeof(fields)-strlen(fields)-1);
    }
    sqlite3_stmt *s;
    sqlite3_prepare_v2(db(ctx),
        "INSERT INTO forms(url,method,fields) VALUES(?,?,?)", -1, &s, NULL);
    sqlite3_bind_text(s, 1, f->url, -1, SQLITE_STATIC);
    sqlite3_bind_int (s, 2, (int)f->method);
    sqlite3_bind_text(s, 3, fields, -1, SQLITE_STATIC);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return 0;
}

/* ── Resume: reload URLs + forms ──────────────────────────── */
int session_load_crawl(ScanContext *ctx) {
    if (!ctx->db) return 0;
    int loaded = 0;
    sqlite3_stmt *s;

    /* URLs */
    sqlite3_prepare_v2(db(ctx), "SELECT url FROM urls", -1, &s, NULL);
    while (sqlite3_step(s) == SQLITE_ROW && ctx->crawl.url_count < MAX_LINKS) {
        const char *u = (const char *)sqlite3_column_text(s, 0);
        strncpy(ctx->crawl.urls[ctx->crawl.url_count++], u, MAX_URL_LEN-1);
        loaded++;
    }
    sqlite3_finalize(s);

    /* Forms */
    sqlite3_prepare_v2(db(ctx),
        "SELECT url,method,fields FROM forms", -1, &s, NULL);
    while (sqlite3_step(s) == SQLITE_ROW && ctx->crawl.form_count < MAX_FORMS) {
        Form *f = &ctx->crawl.forms[ctx->crawl.form_count++];
        strncpy(f->url, (const char *)sqlite3_column_text(s,0), MAX_URL_LEN-1);
        f->method = (HttpMethod)sqlite3_column_int(s, 1);
        const char *fields = (const char *)sqlite3_column_text(s, 2);
        /* deserialise name=value& */
        char buf[2048];
        strncpy(buf, fields ? fields : "", sizeof(buf)-1);
        char *tok = strtok(buf, "&");
        while (tok && f->field_count < MAX_HEADERS) {
            char *eq = strchr(tok, '=');
            if (eq) {
                size_t nl = (size_t)(eq - tok);
                if (nl < MAX_PARAM_LEN) {
                    strncpy(f->fields[f->field_count].name, tok, nl);
                    strncpy(f->fields[f->field_count].value, eq+1, MAX_PARAM_LEN-1);
                    f->field_count++;
                }
            }
            tok = strtok(NULL, "&");
        }
    }
    sqlite3_finalize(s);

    return loaded;
}

/* ── Vuln persistence ─────────────────────────────────────── */
int session_save_vuln(ScanContext *ctx, const Vuln *v) {
    if (!ctx->db) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(db(ctx),
        "INSERT INTO vulns(type,url,parameter,payload,evidence,severity,module)"
        " VALUES(?,?,?,?,?,?,?)", -1, &s, NULL);
    sqlite3_bind_int (s, 1, (int)v->type);
    sqlite3_bind_text(s, 2, v->url,       -1, SQLITE_STATIC);
    sqlite3_bind_text(s, 3, v->parameter, -1, SQLITE_STATIC);
    sqlite3_bind_text(s, 4, v->payload,   -1, SQLITE_STATIC);
    sqlite3_bind_text(s, 5, v->evidence,  -1, SQLITE_STATIC);
    sqlite3_bind_int (s, 6, v->severity);
    sqlite3_bind_text(s, 7, v->module,    -1, SQLITE_STATIC);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return 0;
}

int session_load_vulns(ScanContext *ctx) {
    if (!ctx->db) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(db(ctx),
        "SELECT type,url,parameter,payload,evidence,severity,module,found_at"
        " FROM vulns", -1, &s, NULL);
    while (sqlite3_step(s) == SQLITE_ROW && ctx->vuln_count < MAX_VULNS) {
        Vuln *v = &ctx->vulns[ctx->vuln_count++];
        v->type     = (VulnType)sqlite3_column_int(s, 0);
        strncpy(v->url,       (const char *)sqlite3_column_text(s,1), MAX_URL_LEN-1);
        strncpy(v->parameter, (const char *)sqlite3_column_text(s,2), MAX_PARAM_LEN-1);
        strncpy(v->payload,   (const char *)sqlite3_column_text(s,3), MAX_PARAM_LEN-1);
        strncpy(v->evidence,  (const char *)sqlite3_column_text(s,4), 511);
        v->severity = sqlite3_column_int(s, 5);
        strncpy(v->module, (const char *)sqlite3_column_text(s,6), 63);
        v->found_at = (time_t)sqlite3_column_int64(s, 7);
    }
    sqlite3_finalize(s);
    return ctx->vuln_count;
}
