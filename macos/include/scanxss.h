/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 *
 * This file is part of ScanXSS — Web Vulnerability Scanner.
 *
 * ScanXSS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ScanXSS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef SCANXSS_H
#define SCANXSS_H

/* ── Portability ──────────────────────────────────────────── */
#if defined(__linux__) || defined(__linux) || defined(linux)
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#  endif
#elif defined(__APPLE__) && defined(__MACH__)
#  ifndef _DARWIN_C_SOURCE
#    define _DARWIN_C_SOURCE
#  endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* ─── Version ─────────────────────────────────────────────── */
#define SCANXSS_VERSION  "1.3.1"
#define SCANXSS_NAME     "ScanXSS"

/* ─── Limits ──────────────────────────────────────────────── */
#define MAX_URL_LEN       1024
#define MAX_PARAM_LEN     256
#define MAX_HEADERS       32
#define MAX_FORMS         128
#define MAX_LINKS         512
#define MAX_VULNS         512
#define MAX_DEPTH         5
#define DEFAULT_TIMEOUT   10
#define DEFAULT_RATE      10

/* ─── ANSI colours ────────────────────────────────────────── */
#define COL_RED     "\033[1;31m"
#define COL_GREEN   "\033[1;32m"
#define COL_YELLOW  "\033[1;33m"
#define COL_BLUE    "\033[1;34m"
#define COL_CYAN    "\033[1;36m"
#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"

/* ─── Vulnerability types ─────────────────────────────────── */
typedef enum {
    VULN_NONE        = 0,
    VULN_XSS         = 1 << 0,
    VULN_SQLI        = 1 << 1,
    VULN_LFI         = 1 << 2,
    VULN_RCE         = 1 << 3,
    VULN_SSRF        = 1 << 4,
    VULN_OPEN_REDIR  = 1 << 5,
    VULN_CRLF        = 1 << 6,
    VULN_XXE         = 1 << 7,
    VULN_ALL         = 0xFF
} VulnType;

typedef enum { METHOD_GET = 0, METHOD_POST = 1 } HttpMethod;

/* ─── Scan mode ───────────────────────────────────────────── */
typedef enum {
    SCAN_MODE_FULL    = 0,   /* full crawl + all modules          */
    SCAN_MODE_RESUME  = 1,   /* resume interrupted scan           */
    SCAN_MODE_RETARGET= 2,   /* re-test only previously found vulns */
    SCAN_MODE_RESCAN  = 3,   /* fresh attack on saved crawl data  */
} ScanMode;

/* ─── Param / Form / Response ─────────────────────────────── */
typedef struct { char name[MAX_PARAM_LEN]; char value[MAX_PARAM_LEN]; } Param;

typedef struct {
    long    status_code;
    char   *body;
    size_t  body_len;
    char    content_type[256];
    char    redirect_url[MAX_URL_LEN];   /* Location: header     */
    char    final_url[MAX_URL_LEN];       /* URL after redirects  */
    double  elapsed_ms;
} HttpResponse;

typedef struct {
    char       url[MAX_URL_LEN];
    HttpMethod method;
    Param      fields[MAX_HEADERS];
    int        field_count;
} Form;

typedef struct {
    char  urls[MAX_LINKS][MAX_URL_LEN];
    int   url_count;
    Form  forms[MAX_FORMS];
    int   form_count;
} CrawlResult;

/* ─── Vulnerability ───────────────────────────────────────── */
typedef struct {
    int64_t   db_id;                 /* row id in findings table, 0 = unsaved */
    VulnType  type;
    char      url[MAX_URL_LEN];
    char      parameter[MAX_PARAM_LEN];
    char      payload[MAX_PARAM_LEN];
    char      evidence[512];
    int       severity;
    char      module[64];
    time_t    found_at;
    bool      confirmed;             /* still present on re-scan? */
} Vuln;

/* ─── Rate limiter ────────────────────────────────────────── */
typedef struct {
    int             rate;
    struct timespec last_req;
    long            req_count;
} RateLimiter;

/* ─── Scanner Config ──────────────────────────────────────── */
typedef struct {
    char        target_url[MAX_URL_LEN];
    int         depth;
    int         timeout;
    int         verbose;
    int         color;
    VulnType    modules;
    char        output_file[512];
    char        output_format[16];
    char        report_dir[512];       /* directory for reports (default: ./reports) */
    char        cookies[MAX_URL_LEN];
    char        proxy[MAX_URL_LEN];
    int         max_links;
    bool        follow_redirects;
    char        user_agent[256];
    char        scope[32];
    int         rate;
    char        db_path[512];        /* explicit DB file path (optional)   */
    char        session_dir[512];    /* directory for per-target DBs        */
    ScanMode    scan_mode;
    bool        flush_session;       /* kept for compat, implies RESCAN     */
    bool        resume;              /* kept for compat, implies RESUME     */
    char        endpoint[MAX_URL_LEN];
    int64_t     rescan_id;           /* scan_id to retarget (0 = latest)   */
    char        exe_dir[512];        /* directory containing the binary    */
} ScanConfig;

/* ─── Scanner Context ─────────────────────────────────────── */
typedef struct {
    ScanConfig   config;
    CrawlResult  crawl;
    Vuln         vulns[MAX_VULNS];
    int          vuln_count;
    time_t       start_time;
    time_t       end_time;
    int          requests_made;
    RateLimiter  rate;
    void        *db;                 /* opaque sqlite3*   */
    int64_t      scan_id;            /* current scan row id */
} ScanContext;

/* ─── Module interface ────────────────────────────────────── */
typedef int (*ModuleRunFn)(ScanContext *ctx, const Form *form);
typedef struct {
    const char  *name;
    VulnType     type;
    ModuleRunFn  run;
    const char  *description;
} AttackModule;

/* ─── http.c ──────────────────────────────────────────────── */
HttpResponse *http_get (const ScanConfig *cfg, const char *url);
HttpResponse *http_post(const ScanConfig *cfg, const char *url,
                        const Param *params, int count);
void          http_response_free(HttpResponse *resp);

/* ─── rate.c ──────────────────────────────────────────────── */
void rate_init(RateLimiter *r, int req_per_sec);
void rate_wait(RateLimiter *r);

/* ─── db.c ────────────────────────────────────────────────── */
int     db_open         (ScanContext *ctx);
void    db_close        (ScanContext *ctx);
void    db_set_exe_dir  (ScanContext *ctx, const char *argv0);

/* scan lifecycle */
int64_t db_scan_begin   (ScanContext *ctx);          /* INSERT INTO scans  */
void    db_scan_finish  (ScanContext *ctx);          /* UPDATE end_time    */

/* crawl data */
int  db_save_url        (ScanContext *ctx, const char *url);
int  db_url_visited     (ScanContext *ctx, const char *url);
int  db_save_form       (ScanContext *ctx, const Form *f);
int  db_load_crawl      (ScanContext *ctx);          /* load from last scan */

/* findings */
int  db_save_finding    (ScanContext *ctx, Vuln *v); /* sets v->db_id      */
int  db_load_findings   (ScanContext *ctx, int64_t scan_id); /* into ctx->vulns */
int  db_confirm_finding (ScanContext *ctx, int64_t finding_id, bool confirmed);

/* retargeted re-scan: load only vuln types found in previous scan */
VulnType db_vuln_types_of_scan(ScanContext *ctx, int64_t scan_id);
int      db_load_retarget_forms(ScanContext *ctx, int64_t scan_id);

/* history / reporting */
void    db_list_scans   (ScanContext *ctx);
void    db_show_scan    (ScanContext *ctx, int64_t scan_id);
void    db_flush_scan   (ScanContext *ctx, int64_t scan_id); /* remove findings */
void    db_flush_all    (ScanContext *ctx);                   /* full wipe       */

/* ─── progress.c ──────────────────────────────────────────── */
typedef struct { int total; int done; int color; char label[64]; } ProgressBar;
void progress_init  (ProgressBar *p, int total, int color, const char *label);
void progress_update(ProgressBar *p, int done);
void progress_finish(ProgressBar *p);
void progress_global_init  (int total, int color, const char *phase);
void progress_global_tick  (int done);
void progress_global_finish(void);

/* ─── crawler.c ───────────────────────────────────────────── */
int  crawler_run(ScanContext *ctx);
void crawler_extract_links(const char *base_url, const char *html,
                           CrawlResult *result);
void crawler_extract_forms(const char *url, const char *html,
                           CrawlResult *result);

/* ─── modules ─────────────────────────────────────────────── */
int module_xss_run          (ScanContext *ctx, const Form *form);
int module_sqli_run         (ScanContext *ctx, const Form *form);
int module_lfi_run          (ScanContext *ctx, const Form *form);
int module_rce_run          (ScanContext *ctx, const Form *form);
int module_open_redirect_run(ScanContext *ctx, const Form *form);
int module_crlf_run         (ScanContext *ctx, const Form *form);
int module_ssrf_run         (ScanContext *ctx, const Form *form);

/* ─── attack.c ────────────────────────────────────────────── */
int  attack_run_all     (ScanContext *ctx);
int  attack_run_retarget(ScanContext *ctx, int64_t prev_scan_id);
void attack_add_vuln    (ScanContext *ctx, Vuln *v);

/* ─── report.c ────────────────────────────────────────────── */
int report_json(const ScanContext *ctx, const char *filename);
int report_html(const ScanContext *ctx, const char *filename);
int report_txt (const ScanContext *ctx, const char *filename);
/* generate all formats into report_dir automatically */
int report_generate(ScanContext *ctx);

/* ─── utils.c ─────────────────────────────────────────────── */
char *url_encode        (const char *s);
char *str_replace       (const char *src, const char *from, const char *to);
bool  str_contains_icase(const char *hay, const char *needle);
bool  url_in_scope      (const char *base, const char *url, const char *scope);
void  log_info (int verbose, int color, const char *fmt, ...);
void  log_vuln (int color, const char *fmt, ...);
void  log_warn (int color, const char *fmt, ...);
char *html_strip(const char *html);
char *base_url  (const char *url);
char *resolve_url(const char *base, const char *href);

/* keep old session.c names as thin wrappers (for test compat) */
static inline int  session_open(ScanContext *c)              { return db_open(c); }
static inline void session_close(ScanContext *c)             { db_close(c); }
static inline int  session_save_url(ScanContext *c, const char *u) { return db_save_url(c,u); }
static inline int  session_url_visited(ScanContext *c, const char *u) { return db_url_visited(c,u); }
static inline int  session_save_form(ScanContext *c, const Form *f)   { return db_save_form(c,f); }
static inline int  session_load_crawl(ScanContext *c)        { return db_load_crawl(c); }
static inline void session_save_vuln(ScanContext *c, const Vuln *v) {
    Vuln copy = *v; db_save_finding(c, &copy);
}
static inline int  session_load_vulns(ScanContext *c)        { return db_load_findings(c, 0); }
static inline void session_flush(ScanContext *c)             { db_flush_all(c); }

#endif /* SCANXSS_H */
