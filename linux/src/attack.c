/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * SPDX-License-Identifier: GPL-2.0
 *
 * attack.c — оркестрація модулів атак.
 *
 * Паралелізм:
 *   Кожна пара (form, module) виконується як окрема задача у
 *   worker pool. Потоки незалежні — кожен має власний HTTP-стек
 *   через libcurl (curl_easy_init per thread — thread-safe).
 *
 *   Shared state захищено:
 *     ctx->vulns[] / ctx->vuln_count — g_vuln_mutex
 *     ctx->requests_made             — g_vuln_mutex (той самий)
 *     progress bar                   — g_vuln_mutex
 */

#include "scanxss.h"
#include <pthread.h>
#include <unistd.h>   /* sysconf(_SC_NPROCESSORS_ONLN) */

static AttackModule modules[] = {
    { "xss",      VULN_XSS,        module_xss_run,            "Cross-Site Scripting"  },
    { "sqli",     VULN_SQLI,       module_sqli_run,           "SQL Injection"         },
    { "lfi",      VULN_LFI,        module_lfi_run,            "Local File Inclusion"  },
    { "rce",      VULN_RCE,        module_rce_run,            "Remote Code Execution" },
    { "ssrf",     VULN_SSRF,       module_ssrf_run,           "SSRF"                  },
    { "redirect", VULN_OPEN_REDIR, module_open_redirect_run,  "Open Redirect"         },
    { "crlf",     VULN_CRLF,       module_crlf_run,           "CRLF Injection"        },
};
static int module_count = (int)(sizeof(modules)/sizeof(modules[0]));

/* ── Mutex для shared state між потоками ─────────────────── */
static pthread_mutex_t g_vuln_mutex = PTHREAD_MUTEX_INITIALIZER;
static int             g_job_done   = 0;
static int             g_job_total  = 0;

/* ── attack_add_vuln — thread-safe ───────────────────────── */
void attack_add_vuln(ScanContext *ctx, Vuln *v) {
    pthread_mutex_lock(&g_vuln_mutex);

    if (ctx->vuln_count < MAX_VULNS) {
        /* dedup */
        bool dup = false;
        for (int i = 0; i < ctx->vuln_count; i++) {
            Vuln *e = &ctx->vulns[i];
            if (e->type == v->type
                && strcmp(e->url,       v->url)       == 0
                && strcmp(e->parameter, v->parameter) == 0) {
                dup = true; break;
            }
        }
        if (!dup) {
            v->found_at = time(NULL);
            db_save_finding(ctx, v);
            ctx->vulns[ctx->vuln_count++] = *v;
        }
    }

    pthread_mutex_unlock(&g_vuln_mutex);
}

/* ── Задача для worker pool: (form × module) ─────────────── */
typedef struct {
    ScanContext  *ctx;
    const Form   *form;
    AttackModule *mod;
} AttackTask;

static void attack_task_run(void *arg) {
    AttackTask *t = (AttackTask *)arg;
    t->mod->run(t->ctx, t->form);

    pthread_mutex_lock(&g_vuln_mutex);
    g_job_done++;
    int done = g_job_done;
    pthread_mutex_unlock(&g_vuln_mutex);

    /* draw() вже захищений власним mutex у progress.c */
    progress_global_tick(done);

    free(t);
}

/* ── Build synthetic GET forms from query-string URLs ────── */
static void harvest_url_forms(ScanContext *ctx) {
    for (int u = 0; u < ctx->crawl.url_count; u++) {
        if (ctx->crawl.form_count >= MAX_FORMS) break;
        const char *url = ctx->crawl.urls[u];
        const char *qs  = strchr(url, '?');
        if (!qs) continue;
        size_t blen = (size_t)(qs - url);
        int dup = 0;
        for (int fi = 0; fi < ctx->crawl.form_count; fi++) {
            if (strncmp(ctx->crawl.forms[fi].url, url, blen)==0
                && ctx->crawl.forms[fi].url[blen]=='\0') { dup=1; break; }
        }
        if (dup) continue;
        Form f = {0}; f.method = METHOD_GET; f.baseline_len = -1;
        if (blen < MAX_URL_LEN) strncpy(f.url, url, blen);
        char qcopy[MAX_URL_LEN]; strncpy(qcopy, qs+1, MAX_URL_LEN-1);
        char *tok = strtok(qcopy, "&");
        while (tok && f.field_count < MAX_HEADERS) {
            char *eq = strchr(tok, '=');
            if (eq) {
                size_t nl = (size_t)(eq-tok);
                if (nl > 0 && nl < MAX_PARAM_LEN) {
                    strncpy(f.fields[f.field_count].name, tok, nl);
                    strncpy(f.fields[f.field_count].value, eq+1, MAX_PARAM_LEN-1);
                    f.field_count++;
                }
            }
            tok = strtok(NULL, "&");
        }
        if (f.field_count > 0)
            ctx->crawl.forms[ctx->crawl.form_count++] = f;
    }
}

/* ── Паралельний attack loop ─────────────────────────────── */
static int run_modules(ScanContext *ctx, VulnType mod_mask) {
    const ScanConfig *cfg = &ctx->config;

    /* ── Автовизначення кількості потоків ───────────────────── *
     * Якщо --threads не задано (cfg->threads == 0):             *
     *   I/O-bound задача → оптимум >> кількості ядер.           *
     *   Формула: min(32, ncpu × 4), але не менше 4.             *
     * Головне обмеження — rate limit сервера, не CPU.           */
    int nthreads;
    if (cfg->threads > 0) {
        nthreads = cfg->threads;
    } else {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) ncpu = 1;
        nthreads = (int)(ncpu * 4);
        if (nthreads > 32)              nthreads = 32;
        if (nthreads < 4)               nthreads = 4;
    }
    if (nthreads > WORKER_MAX_THREADS)  nthreads = WORKER_MAX_THREADS;

    int active = 0;
    for (int m = 0; m < module_count; m++)
        if (mod_mask & modules[m].type) active++;

    g_job_done  = 0;
    g_job_total = ctx->crawl.form_count * (active > 0 ? active : 1);

    printf(COL_BOLD "[Attack] Forms: %d  Modules: %d  Jobs: %d  Threads: %d\n"
           COL_RESET,
           ctx->crawl.form_count, active, g_job_total, nthreads);

    progress_global_init(g_job_total > 0 ? g_job_total : 1,
                         cfg->color, "Attacking");

    WorkerPool *pool = worker_pool_create(nthreads);
    if (!pool) {
        /* Fallback: послідовне виконання */
        fprintf(stderr, COL_YELLOW
                "[!] Worker pool failed — sequential mode\n" COL_RESET);
        int job = 0;
        for (int fi = 0; fi < ctx->crawl.form_count; fi++) {
            const Form *form = &ctx->crawl.forms[fi];
            if (form->field_count == 0) {
                job += active; progress_global_tick(job); continue;
            }
            for (int mi = 0; mi < module_count; mi++) {
                if (!(mod_mask & modules[mi].type)) continue;
                modules[mi].run(ctx, form);
                progress_global_tick(++job);
            }
        }
        progress_global_finish();
        goto done;
    }

    /* Подаємо задачі у pool */
    for (int fi = 0; fi < ctx->crawl.form_count; fi++) {
        const Form *form = &ctx->crawl.forms[fi];
        if (form->field_count == 0) {
            pthread_mutex_lock(&g_vuln_mutex);
            g_job_done += active;
            int done = g_job_done;
            pthread_mutex_unlock(&g_vuln_mutex);
            progress_global_tick(done);
            continue;
        }
        for (int mi = 0; mi < module_count; mi++) {
            if (!(mod_mask & modules[mi].type)) continue;
            AttackTask *t = malloc(sizeof(AttackTask));
            if (!t) continue;
            t->ctx  = ctx;
            t->form = form;
            t->mod  = &modules[mi];
            worker_pool_submit(pool, attack_task_run, t);
        }
    }

    worker_pool_wait(pool);
    worker_pool_destroy(pool);
    progress_global_finish();

done:
    printf(COL_BOLD "[Attack] Done. Vulnerabilities: " COL_RESET);
    printf(ctx->vuln_count > 0 ? COL_RED "%d\n" COL_RESET
                                : COL_GREEN "0\n" COL_RESET, ctx->vuln_count);
    return ctx->vuln_count;
}

/* ── Full attack ─────────────────────────────────────────── */
int attack_run_all(ScanContext *ctx) {
    harvest_url_forms(ctx);
    return run_modules(ctx, ctx->config.modules);
}

/* ── Retargeted re-scan ──────────────────────────────────── */
int attack_run_retarget(ScanContext *ctx, int64_t prev_scan_id) {
    const ScanConfig *cfg = &ctx->config;

    Vuln prev_vulns[MAX_VULNS];
    int  prev_count = 0;

    int saved_vuln_count = ctx->vuln_count;
    ctx->vuln_count = 0;
    db_load_findings(ctx, prev_scan_id);
    prev_count = ctx->vuln_count;
    if (prev_count > 0)
        memcpy(prev_vulns, ctx->vulns, (size_t)prev_count * sizeof(Vuln));

    printf(COL_YELLOW "[Retarget] Попередніх знахідок: %d\n" COL_RESET, prev_count);

    ctx->vuln_count = saved_vuln_count;
    int forms_loaded = db_load_retarget_forms(ctx, prev_scan_id);
    if (forms_loaded == 0) {
        printf(COL_YELLOW "[Retarget] Форми не знайдені — завантажую повний crawl\n"
               COL_RESET);
        db_load_crawl(ctx);
    }

    harvest_url_forms(ctx);

    if (ctx->crawl.form_count == 0) {
        printf(COL_YELLOW "[Retarget] Немає форм. Спробуйте --rescan.\n" COL_RESET);
        ctx->vuln_count = 0;
        return 0;
    }

    VulnType mask = db_vuln_types_of_scan(ctx, prev_scan_id);
    mask &= cfg->modules;
    if (!mask) mask = cfg->modules;

    printf(COL_YELLOW "[Retarget] %d форм, модулі: 0x%02x\n" COL_RESET,
           ctx->crawl.form_count, (unsigned)mask);

    ctx->vuln_count = 0;
    run_modules(ctx, mask);
    int new_found = ctx->vuln_count;

    printf("\n" COL_BOLD "[Retarget] Результати верифікації:\n" COL_RESET);

    int still_active = 0, now_fixed = 0, brand_new = 0;

    for (int i = 0; i < prev_count; i++) {
        Vuln *pv = &prev_vulns[i];
        bool found_again = false;
        for (int j = 0; j < new_found; j++) {
            Vuln *nv = &ctx->vulns[j];
            if (nv->type == pv->type
                && strcmp(nv->url,       pv->url)       == 0
                && strcmp(nv->parameter, pv->parameter) == 0) {
                found_again = true; break;
            }
        }
        pv->confirmed = found_again;
        if (pv->db_id) db_confirm_finding(ctx, pv->db_id, found_again);
        if (found_again) still_active++;
        else             now_fixed++;
        printf("  [%s] %-8s %-40s param=%s\n",
               found_again ? COL_RED "ACTIVE" COL_RESET
                           : COL_GREEN " FIXED" COL_RESET,
               pv->module, pv->url, pv->parameter);
    }

    for (int j = 0; j < new_found; j++) {
        Vuln *nv = &ctx->vulns[j];
        bool is_new = true;
        for (int i = 0; i < prev_count; i++) {
            if (nv->type == prev_vulns[i].type
                && strcmp(nv->url,       prev_vulns[i].url)       == 0
                && strcmp(nv->parameter, prev_vulns[i].parameter) == 0) {
                is_new = false; break;
            }
        }
        if (is_new) {
            brand_new++;
            printf("  [" COL_YELLOW "NEW   " COL_RESET "] %-8s %-40s param=%s\n",
                   nv->module, nv->url, nv->parameter);
        }
    }

    printf("\n");
    if (still_active) printf(COL_RED   "  Активних:  %d\n" COL_RESET, still_active);
    if (now_fixed)    printf(COL_GREEN "  Виправлено: %d\n" COL_RESET, now_fixed);
    if (brand_new)    printf(COL_YELLOW "  Нових:      %d\n" COL_RESET, brand_new);
    printf("\n");

    return ctx->vuln_count;
}
