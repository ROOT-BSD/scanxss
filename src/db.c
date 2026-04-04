/*
 * db.c — ScanXSS persistent database
 *
 * Schema (one SQLite file per target, or one shared file via --db):
 *
 *   targets   — one row per unique URL being scanned
 *   scans     — one row per scan run  (links to targets)
 *   urls      — crawled URLs          (links to scans)
 *   forms     — discovered forms      (links to scans)
 *   findings  — vulnerabilities       (links to scans)
 *
 * Modes:
 *   FULL      — new scan_id, fresh crawl, all modules
 *   RESUME    — reuse scan_id, skip already-crawled URLs
 *   RESCAN    — new scan_id, reuse crawl from last scan, all modules
 *   RETARGET  — new scan_id, reuse crawl, only modules that fired before
 */

#include "scanxss.h"
#include "sqlite3.h"
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <libgen.h>
#include <limits.h>
#ifdef __linux__
#  include <unistd.h>
#endif
#ifdef __APPLE__
#  include <mach-o/dyld.h>   /* _NSGetExecutablePath */
#  include <unistd.h>
#endif

/* ── helpers ──────────────────────────────────────────────── */
static sqlite3 *H(ScanContext *ctx) { return (sqlite3 *)ctx->db; }

static int db_exec(ScanContext *ctx, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(H(ctx), sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, COL_RED "[db] SQL error: %s\n" COL_RESET, err ? err : "?");
        sqlite3_free(err);
    }
    return rc;
}

static int64_t db_last_id(ScanContext *ctx) {
    return (int64_t)sqlite3_last_insert_rowid(H(ctx));
}

/* ── schema ───────────────────────────────────────────────── */
static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA foreign_keys=ON;"

    "CREATE TABLE IF NOT EXISTS targets("
    "  id         INTEGER PRIMARY KEY,"
    "  url        TEXT UNIQUE NOT NULL,"
    "  first_seen INTEGER DEFAULT (strftime('%s','now')),"
    "  last_seen  INTEGER DEFAULT (strftime('%s','now'))"
    ");"

    "CREATE TABLE IF NOT EXISTS scans("
    "  id          INTEGER PRIMARY KEY,"
    "  target_id   INTEGER NOT NULL REFERENCES targets(id),"
    "  mode        TEXT    NOT NULL DEFAULT 'full',"   /* full|resume|rescan|retarget */
    "  modules     INTEGER NOT NULL DEFAULT 255,"      /* VulnType bitmask */
    "  started_at  INTEGER DEFAULT (strftime('%s','now')),"
    "  finished_at INTEGER,"
    "  requests    INTEGER DEFAULT 0,"
    "  urls_found  INTEGER DEFAULT 0,"
    "  forms_found INTEGER DEFAULT 0,"
    "  vulns_found INTEGER DEFAULT 0,"
    "  status      TEXT    DEFAULT 'running'"          /* running|done|interrupted */
    ");"

    "CREATE TABLE IF NOT EXISTS urls("
    "  id       INTEGER PRIMARY KEY,"
    "  scan_id  INTEGER NOT NULL REFERENCES scans(id),"
    "  url      TEXT    NOT NULL,"
    "  UNIQUE(scan_id, url)"
    ");"

    "CREATE TABLE IF NOT EXISTS forms("
    "  id       INTEGER PRIMARY KEY,"
    "  scan_id  INTEGER NOT NULL REFERENCES scans(id),"
    "  url      TEXT    NOT NULL,"
    "  method   INTEGER NOT NULL DEFAULT 0,"
    "  fields   TEXT    NOT NULL DEFAULT ''"
    ");"

    "CREATE TABLE IF NOT EXISTS findings("
    "  id          INTEGER PRIMARY KEY,"
    "  scan_id     INTEGER NOT NULL REFERENCES scans(id),"
    "  type        INTEGER NOT NULL,"
    "  url         TEXT    NOT NULL,"
    "  parameter   TEXT    NOT NULL,"
    "  payload     TEXT    NOT NULL,"
    "  evidence    TEXT    NOT NULL,"
    "  severity    INTEGER NOT NULL,"
    "  module      TEXT    NOT NULL,"
    "  confirmed   INTEGER DEFAULT 1,"  /* 1=active, 0=fixed */
    "  found_at    INTEGER DEFAULT (strftime('%s','now')),"
    "  verified_at INTEGER"
    ");"

    "CREATE INDEX IF NOT EXISTS idx_scans_target   ON scans(target_id);"
    "CREATE INDEX IF NOT EXISTS idx_urls_scan      ON urls(scan_id);"
    "CREATE INDEX IF NOT EXISTS idx_forms_scan     ON forms(scan_id);"
    "CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);"
    "CREATE INDEX IF NOT EXISTS idx_findings_type  ON findings(type);"
    ;

/* ── resolve directory of the running executable ─────────── *
 * Priority:
 *   1. --db FILE           (explicit absolute path)
 *   2. --session-dir DIR   (explicit directory)
 *   3. exe_dir             (directory of the binary — default)
 *   4. cwd                 (last resort fallback)
 * ─────────────────────────────────────────────────────────── */
void db_set_exe_dir(ScanContext *ctx, const char *argv0) {
    char resolved[PATH_MAX] = {0};

#ifdef __linux__
    /* /proc/self/exe is the most reliable on Linux */
    ssize_t n = readlink("/proc/self/exe", resolved, sizeof(resolved)-1);
    if (n > 0) {
        resolved[n] = '\0';
        /* dirname() may modify the buffer — work on a copy */
        char tmp[PATH_MAX];
        strncpy(tmp, resolved, PATH_MAX-1);
        strncpy(ctx->config.exe_dir, dirname(tmp), sizeof(ctx->config.exe_dir)-1);
        return;
    }
#elif defined(__APPLE__)
    uint32_t sz = (uint32_t)sizeof(resolved);
    if (_NSGetExecutablePath(resolved, &sz) == 0) {
        char tmp[PATH_MAX];
        strncpy(tmp, resolved, PATH_MAX-1);
        strncpy(ctx->config.exe_dir, dirname(tmp), sizeof(ctx->config.exe_dir)-1);
        return;
    }
#endif

    /* Fallback: use argv[0] via realpath */
    if (argv0 && realpath(argv0, resolved)) {
        char tmp[PATH_MAX];
        strncpy(tmp, resolved, PATH_MAX-1);
        strncpy(ctx->config.exe_dir, dirname(tmp), sizeof(ctx->config.exe_dir)-1);
        return;
    }

    /* Last resort: current working directory */
    if (getcwd(ctx->config.exe_dir, sizeof(ctx->config.exe_dir)-1) == NULL)
        strncpy(ctx->config.exe_dir, ".", sizeof(ctx->config.exe_dir)-1);
}

/* ── build DB file path ────────────────────────────────────── */
static void make_dbpath(ScanContext *ctx, char *out, size_t out_size) {
    /* 1. Explicit --db path */
    if (ctx->config.db_path[0]) {
        strncpy(out, ctx->config.db_path, out_size-1);
        return;
    }

    /* Base directory: --session-dir > exe_dir > cwd */
    const char *base = ctx->config.session_dir[0] ? ctx->config.session_dir
                     : ctx->config.exe_dir[0]      ? ctx->config.exe_dir
                     : ".";

    /* DB stored in ../DB_SCAN/scan.db relative to binary */
    snprintf(out, out_size, "%s/../DB_SCAN/scan.db", base);
}

/* ── open ─────────────────────────────────────────────────── */
int db_open(ScanContext *ctx) {
    /* ensure base directory exists (only for auto path, not --db) */
    if (!ctx->config.db_path[0]) {
        /* ensure ../DB_SCAN directory exists */
        char db_dir[600] = {0};
        if (ctx->config.session_dir[0]) {
            snprintf(db_dir, sizeof(db_dir), "%s", ctx->config.session_dir);
        } else {
            const char *base2 = ctx->config.exe_dir[0] ? ctx->config.exe_dir : ".";
            snprintf(db_dir, sizeof(db_dir), "%s/../DB_SCAN", base2);
        }
        struct stat st;
        if (stat(db_dir, &st) != 0 && mkdir(db_dir, 0755) != 0 && errno != EEXIST) {
            /* try recursive: parent may not exist */
            char parent[600]={0}; snprintf(parent,sizeof(parent),"%s",db_dir);
            char *sl=strrchr(parent,'/'); if(sl){*sl='\0'; mkdir(parent,0755);}
            if (mkdir(db_dir, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "[db] Cannot create dir %s: %s\n", db_dir, strerror(errno));
                return -1;
            }
        }
    }

    char dbpath[768];
    make_dbpath(ctx, dbpath, sizeof(dbpath));

    sqlite3 *handle = NULL;
    if (sqlite3_open(dbpath, &handle) != SQLITE_OK) {
        fprintf(stderr, "[db] Cannot open %s: %s\n", dbpath, sqlite3_errmsg(handle));
        sqlite3_close(handle);
        return -1;
    }
    ctx->db = handle;

    if (db_exec(ctx, SCHEMA) != SQLITE_OK) {
        sqlite3_close(handle); ctx->db = NULL; return -1;
    }

    printf(COL_CYAN "[DB] " COL_RESET "%s\n", dbpath);
    return 0;
}

void db_close(ScanContext *ctx) {
    if (ctx->db) { sqlite3_close(H(ctx)); ctx->db = NULL; }
}

/* ── scan lifecycle ───────────────────────────────────────── */
int64_t db_scan_begin(ScanContext *ctx) {
    if (!ctx->db) return 0;

    /* upsert target */
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "INSERT OR IGNORE INTO targets(url) VALUES(?)", -1, &s, NULL);
    sqlite3_bind_text(s, 1, ctx->config.target_url, -1, SQLITE_STATIC);
    sqlite3_step(s); sqlite3_finalize(s);

    sqlite3_prepare_v2(H(ctx),
        "UPDATE targets SET last_seen=strftime('%s','now') WHERE url=?",
        -1, &s, NULL);
    sqlite3_bind_text(s, 1, ctx->config.target_url, -1, SQLITE_STATIC);
    sqlite3_step(s); sqlite3_finalize(s);

    int64_t target_id;
    sqlite3_prepare_v2(H(ctx),
        "SELECT id FROM targets WHERE url=?", -1, &s, NULL);
    sqlite3_bind_text(s, 1, ctx->config.target_url, -1, SQLITE_STATIC);
    sqlite3_step(s);
    target_id = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);

    /* mode string */
    const char *mode_str[] = {"full","resume","rescan","retarget"};
    const char *mode = mode_str[(int)ctx->config.scan_mode & 3];

    sqlite3_prepare_v2(H(ctx),
        "INSERT INTO scans(target_id,mode,modules) VALUES(?,?,?)",
        -1, &s, NULL);
    sqlite3_bind_int64(s, 1, target_id);
    sqlite3_bind_text (s, 2, mode, -1, SQLITE_STATIC);
    sqlite3_bind_int  (s, 3, (int)ctx->config.modules);
    sqlite3_step(s); sqlite3_finalize(s);

    ctx->scan_id = db_last_id(ctx);
    return ctx->scan_id;
}

void db_scan_finish(ScanContext *ctx) {
    if (!ctx->db || !ctx->scan_id) return;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "UPDATE scans SET finished_at=strftime('%s','now'), status='done',"
        " requests=?, urls_found=?, forms_found=?, vulns_found=?"
        " WHERE id=?", -1, &s, NULL);
    sqlite3_bind_int  (s, 1, ctx->requests_made);
    sqlite3_bind_int  (s, 2, ctx->crawl.url_count);
    sqlite3_bind_int  (s, 3, ctx->crawl.form_count);
    sqlite3_bind_int  (s, 4, ctx->vuln_count);
    sqlite3_bind_int64(s, 5, ctx->scan_id);
    sqlite3_step(s); sqlite3_finalize(s);
}

/* ── crawl data ───────────────────────────────────────────── */
int db_save_url(ScanContext *ctx, const char *url) {
    if (!ctx->db || !ctx->scan_id) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "INSERT OR IGNORE INTO urls(scan_id,url) VALUES(?,?)", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, ctx->scan_id);
    sqlite3_bind_text (s, 2, url, -1, SQLITE_STATIC);
    sqlite3_step(s); sqlite3_finalize(s);
    return 0;
}

int db_url_visited(ScanContext *ctx, const char *url) {
    if (!ctx->db || !ctx->scan_id) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "SELECT 1 FROM urls WHERE scan_id=? AND url=? LIMIT 1", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, ctx->scan_id);
    sqlite3_bind_text (s, 2, url, -1, SQLITE_STATIC);
    int found = (sqlite3_step(s) == SQLITE_ROW);
    sqlite3_finalize(s);
    return found;
}

static void serialise_fields(const Form *f, char *out, size_t sz) {
    out[0] = '\0';
    for (int i = 0; i < f->field_count; i++) {
        if (i) strncat(out, "&", sz-strlen(out)-1);
        strncat(out, f->fields[i].name,  sz-strlen(out)-1);
        strncat(out, "=",                sz-strlen(out)-1);
        strncat(out, f->fields[i].value, sz-strlen(out)-1);
    }
}

static void deserialise_fields(Form *f, const char *raw) {
    char buf[2048]; strncpy(buf, raw ? raw : "", sizeof(buf)-1);
    char *tok = strtok(buf, "&");
    while (tok && f->field_count < MAX_HEADERS) {
        char *eq = strchr(tok, '=');
        if (eq) {
            size_t nl = (size_t)(eq-tok);
            if (nl > 0 && nl < MAX_PARAM_LEN) {
                strncpy(f->fields[f->field_count].name, tok, nl);
                strncpy(f->fields[f->field_count].value, eq+1, MAX_PARAM_LEN-1);
                f->field_count++;
            }
        }
        tok = strtok(NULL, "&");
    }
}

int db_save_form(ScanContext *ctx, const Form *f) {
    if (!ctx->db || !ctx->scan_id) return 0;
    char fields[2048]; serialise_fields(f, fields, sizeof(fields));
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "INSERT INTO forms(scan_id,url,method,fields) VALUES(?,?,?,?)",
        -1, &s, NULL);
    sqlite3_bind_int64(s, 1, ctx->scan_id);
    sqlite3_bind_text (s, 2, f->url,   -1, SQLITE_STATIC);
    sqlite3_bind_int  (s, 3, (int)f->method);
    sqlite3_bind_text (s, 4, fields,   -1, SQLITE_STATIC);
    sqlite3_step(s); sqlite3_finalize(s);
    return 0;
}

/* find most recent scan_id for this target */
static int64_t latest_scan_id(ScanContext *ctx) {
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "SELECT s.id FROM scans s"
        " JOIN targets t ON t.id=s.target_id"
        " WHERE t.url=? AND s.status='done'"
        " ORDER BY s.id DESC LIMIT 1", -1, &s, NULL);
    sqlite3_bind_text(s, 1, ctx->config.target_url, -1, SQLITE_STATIC);
    int64_t sid = 0;
    if (sqlite3_step(s) == SQLITE_ROW) sid = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return sid;
}

int db_load_crawl(ScanContext *ctx) {
    if (!ctx->db) return 0;
    int64_t src = ctx->config.rescan_id > 0
                  ? ctx->config.rescan_id
                  : latest_scan_id(ctx);
    if (!src) { printf("[DB] No previous scan found.\n"); return 0; }

    int loaded = 0;
    sqlite3_stmt *s;

    /* URLs */
    sqlite3_prepare_v2(H(ctx),
        "SELECT url FROM urls WHERE scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, src);
    while (sqlite3_step(s)==SQLITE_ROW && ctx->crawl.url_count < MAX_LINKS) {
        const char *u = (const char *)sqlite3_column_text(s, 0);
        strncpy(ctx->crawl.urls[ctx->crawl.url_count++], u, MAX_URL_LEN-1);
        /* re-record in new scan */
        db_save_url(ctx, u);
        loaded++;
    }
    sqlite3_finalize(s);

    /* Forms */
    sqlite3_prepare_v2(H(ctx),
        "SELECT url,method,fields FROM forms WHERE scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, src);
    while (sqlite3_step(s)==SQLITE_ROW && ctx->crawl.form_count < MAX_FORMS) {
        Form *f = &ctx->crawl.forms[ctx->crawl.form_count++];
        strncpy(f->url, (const char *)sqlite3_column_text(s,0), MAX_URL_LEN-1);
        f->method = (HttpMethod)sqlite3_column_int(s, 1);
        deserialise_fields(f, (const char *)sqlite3_column_text(s, 2));
        db_save_form(ctx, f);
    }
    sqlite3_finalize(s);

    printf("[DB] Loaded crawl from scan #%lld: %d URLs, %d forms\n",
           (long long)src, ctx->crawl.url_count, ctx->crawl.form_count);
    return loaded;
}

/* ── findings ─────────────────────────────────────────────── */
int db_save_finding(ScanContext *ctx, Vuln *v) {
    if (!ctx->db || !ctx->scan_id) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "INSERT INTO findings"
        "(scan_id,type,url,parameter,payload,evidence,severity,module)"
        " VALUES(?,?,?,?,?,?,?,?)", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, ctx->scan_id);
    sqlite3_bind_int  (s, 2, (int)v->type);
    sqlite3_bind_text (s, 3, v->url,       -1, SQLITE_STATIC);
    sqlite3_bind_text (s, 4, v->parameter, -1, SQLITE_STATIC);
    sqlite3_bind_text (s, 5, v->payload,   -1, SQLITE_STATIC);
    sqlite3_bind_text (s, 6, v->evidence,  -1, SQLITE_STATIC);
    sqlite3_bind_int  (s, 7, v->severity);
    sqlite3_bind_text (s, 8, v->module,    -1, SQLITE_STATIC);
    sqlite3_step(s); sqlite3_finalize(s);
    v->db_id = db_last_id(ctx);
    return 0;
}

int db_load_findings(ScanContext *ctx, int64_t scan_id) {
    if (!ctx->db) return 0;
    int64_t src = scan_id > 0 ? scan_id : latest_scan_id(ctx);
    if (!src) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "SELECT id,type,url,parameter,payload,evidence,severity,module,found_at"
        " FROM findings WHERE scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, src);
    while (sqlite3_step(s)==SQLITE_ROW && ctx->vuln_count < MAX_VULNS) {
        Vuln *v = &ctx->vulns[ctx->vuln_count++];
        v->db_id    = sqlite3_column_int64(s, 0);
        v->type     = (VulnType)sqlite3_column_int(s, 1);
        strncpy(v->url,       (const char *)sqlite3_column_text(s,2), MAX_URL_LEN-1);
        strncpy(v->parameter, (const char *)sqlite3_column_text(s,3), MAX_PARAM_LEN-1);
        strncpy(v->payload,   (const char *)sqlite3_column_text(s,4), MAX_PARAM_LEN-1);
        strncpy(v->evidence,  (const char *)sqlite3_column_text(s,5), 511);
        v->severity = sqlite3_column_int(s, 6);
        strncpy(v->module, (const char *)sqlite3_column_text(s,7), 63);
        v->found_at = (time_t)sqlite3_column_int64(s, 8);
        v->confirmed = true;
    }
    sqlite3_finalize(s);
    return ctx->vuln_count;
}

int db_confirm_finding(ScanContext *ctx, int64_t finding_id, bool confirmed) {
    if (!ctx->db) return 0;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "UPDATE findings SET confirmed=?, verified_at=strftime('%s','now')"
        " WHERE id=?", -1, &s, NULL);
    sqlite3_bind_int  (s, 1, confirmed ? 1 : 0);
    sqlite3_bind_int64(s, 2, finding_id);
    sqlite3_step(s); sqlite3_finalize(s);
    return 0;
}

/* ── retarget helpers ─────────────────────────────────────── */
VulnType db_vuln_types_of_scan(ScanContext *ctx, int64_t scan_id) {
    if (!ctx->db) return VULN_ALL;
    int64_t src = scan_id > 0 ? scan_id : latest_scan_id(ctx);
    if (!src) return VULN_ALL;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "SELECT DISTINCT type FROM findings WHERE scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, src);
    VulnType mask = VULN_NONE;
    while (sqlite3_step(s) == SQLITE_ROW)
        mask |= (VulnType)sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    printf("[DB] Retarget: previous scan #%lld had vuln types mask=0x%02x\n",
           (long long)src, (unsigned)mask);
    return mask ? mask : VULN_ALL;
}

int db_load_retarget_forms(ScanContext *ctx, int64_t scan_id) {
    /* Load only forms/URLs that had findings in previous scan */
    if (!ctx->db) return 0;
    int64_t src = scan_id > 0 ? scan_id : latest_scan_id(ctx);
    if (!src) return db_load_crawl(ctx);

    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "SELECT DISTINCT f.url, f.method, f.fields"
        " FROM forms f"
        " JOIN findings fi ON fi.scan_id=f.scan_id AND fi.url=f.url"
        " WHERE f.scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, src);

    int loaded = 0;
    while (sqlite3_step(s)==SQLITE_ROW && ctx->crawl.form_count < MAX_FORMS) {
        Form *f = &ctx->crawl.forms[ctx->crawl.form_count++];
        strncpy(f->url, (const char *)sqlite3_column_text(s,0), MAX_URL_LEN-1);
        f->method = (HttpMethod)sqlite3_column_int(s, 1);
        deserialise_fields(f, (const char *)sqlite3_column_text(s, 2));
        db_save_form(ctx, f);
        loaded++;
    }
    sqlite3_finalize(s);
    printf("[DB] Retarget: loaded %d forms that had previous findings\n", loaded);
    return loaded;
}

/* ── history / reporting ──────────────────────────────────── */
void db_list_scans(ScanContext *ctx) {
    if (!ctx->db) { fprintf(stderr, "No DB open.\n"); return; }
    printf("\n" COL_BOLD "%-6s %-10s %-12s %-8s %-8s %-8s %-8s %-12s\n" COL_RESET,
           "ID", "Mode", "Status", "URLs", "Forms", "Vulns", "Reqs", "Started");
    printf("%-6s %-10s %-12s %-8s %-8s %-8s %-8s %-12s\n",
           "------","----------","------------","--------","--------","--------","--------","------------");

    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "SELECT s.id, s.mode, s.status, s.urls_found, s.forms_found,"
        " s.vulns_found, s.requests, datetime(s.started_at,'unixepoch')"
        " FROM scans s JOIN targets t ON t.id=s.target_id"
        " WHERE t.url=? ORDER BY s.id DESC LIMIT 20",
        -1, &s, NULL);
    sqlite3_bind_text(s, 1, ctx->config.target_url, -1, SQLITE_STATIC);
    int any = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        any = 1;
        int64_t id   = sqlite3_column_int64(s, 0);
        const char *mode = (const char *)sqlite3_column_text(s, 1);
        const char *stat = (const char *)sqlite3_column_text(s, 2);
        int urls  = sqlite3_column_int(s, 3);
        int forms = sqlite3_column_int(s, 4);
        int vulns = sqlite3_column_int(s, 5);
        int reqs  = sqlite3_column_int(s, 6);
        const char *ts = (const char *)sqlite3_column_text(s, 7);

        const char *vc = vulns > 0 ? COL_RED : COL_GREEN;
        printf("%-6lld %-10s %-12s %-8d %-8d %s%-8d" COL_RESET " %-8d %-12s\n",
               (long long)id, mode, stat, urls, forms, vc, vulns, reqs, ts ? ts : "?");
    }
    sqlite3_finalize(s);
    if (!any) printf("(no scans for %s)\n", ctx->config.target_url);
    printf("\n");
}

void db_show_scan(ScanContext *ctx, int64_t scan_id) {
    if (!ctx->db) return;
    int64_t src = scan_id > 0 ? scan_id : latest_scan_id(ctx);
    if (!src) { printf("No scan found.\n"); return; }

    printf("\n" COL_BOLD "═══ Scan #%lld findings ═══\n" COL_RESET, (long long)src);
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "SELECT id,type,severity,module,url,parameter,payload,evidence,confirmed"
        " FROM findings WHERE scan_id=? ORDER BY severity DESC",
        -1, &s, NULL);
    sqlite3_bind_int64(s, 1, src);

    const char *sev_col[] = {"",COL_RESET,COL_BLUE,COL_YELLOW,COL_RED,COL_RED};
    const char *sev_name[]={"","Info","Low","Medium","High","Critical"};
    int n = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        n++;
        int64_t fid  = sqlite3_column_int64(s, 0);
        int     type = sqlite3_column_int(s, 1);
        int     sev  = sqlite3_column_int(s, 2);
        if (sev < 1 || sev > 5) sev = 1;
        const char *mod  = (const char *)sqlite3_column_text(s, 3);
        const char *url  = (const char *)sqlite3_column_text(s, 4);
        const char *par  = (const char *)sqlite3_column_text(s, 5);
        const char *pay  = (const char *)sqlite3_column_text(s, 6);
        const char *evi  = (const char *)sqlite3_column_text(s, 7);
        int confirmed    = sqlite3_column_int(s, 8);
        const char *ck   = confirmed ? COL_RED "✓" COL_RESET : COL_GREEN "✗fixed" COL_RESET;
        printf(" %s[%s]" COL_RESET " #%lld %s | %s | param=%s\n"
               "    payload : %s\n"
               "    evidence: %s\n\n",
               sev_col[sev], sev_name[sev], (long long)fid,
               mod, url, par, pay, evi);
        (void)type; (void)ck;
    }
    sqlite3_finalize(s);
    if (!n) printf("  No findings for scan #%lld\n", (long long)src);
    printf("\n");
}

void db_flush_scan(ScanContext *ctx, int64_t scan_id) {
    if (!ctx->db) return;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(H(ctx),
        "DELETE FROM findings WHERE scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, scan_id);
    sqlite3_step(s); sqlite3_finalize(s);

    sqlite3_prepare_v2(H(ctx),
        "DELETE FROM forms WHERE scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, scan_id);
    sqlite3_step(s); sqlite3_finalize(s);

    sqlite3_prepare_v2(H(ctx),
        "DELETE FROM urls WHERE scan_id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, scan_id);
    sqlite3_step(s); sqlite3_finalize(s);

    sqlite3_prepare_v2(H(ctx),
        "DELETE FROM scans WHERE id=?", -1, &s, NULL);
    sqlite3_bind_int64(s, 1, scan_id);
    sqlite3_step(s); sqlite3_finalize(s);

    printf("[DB] Scan #%lld deleted.\n", (long long)scan_id);
}

void db_flush_all(ScanContext *ctx) {
    if (!ctx->db) return;
    db_exec(ctx,
        "DELETE FROM findings;"
        "DELETE FROM forms;"
        "DELETE FROM urls;"
        "DELETE FROM scans;"
        "DELETE FROM targets;");
    printf("[DB] All data wiped.\n");
}
