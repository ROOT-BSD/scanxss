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

#include "scanxss.h"

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

/* ─── Add + persist finding ───────────────────────────────── */
void attack_add_vuln(ScanContext *ctx, Vuln *v) {
    if (ctx->vuln_count >= MAX_VULNS) return;
    /* dedup by type + url + parameter */
    for (int i = 0; i < ctx->vuln_count; i++) {
        Vuln *e = &ctx->vulns[i];
        if (e->type == v->type
            && strcmp(e->url,       v->url)       == 0
            && strcmp(e->parameter, v->parameter) == 0)
            return;
    }
    v->found_at = time(NULL);
    db_save_finding(ctx, v);   /* sets v->db_id */
    ctx->vulns[ctx->vuln_count++] = *v;
}

/* ─── Build synthetic GET forms from query-string URLs ────── */
static void harvest_url_forms(ScanContext *ctx) {
    for (int u = 0; u < ctx->crawl.url_count; u++) {
        if (ctx->crawl.form_count >= MAX_FORMS) break;
        const char *url = ctx->crawl.urls[u];
        const char *qs  = strchr(url, '?');
        if (!qs) continue;
        size_t blen = (size_t)(qs - url);
        /* dedup */
        int dup = 0;
        for (int fi = 0; fi < ctx->crawl.form_count; fi++) {
            if (strncmp(ctx->crawl.forms[fi].url, url, blen)==0
                && ctx->crawl.forms[fi].url[blen]=='\0') { dup=1; break; }
        }
        if (dup) continue;
        Form f = {0}; f.method = METHOD_GET;
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

/* ─── Shared attack loop ──────────────────────────────────── */
static int run_modules(ScanContext *ctx, VulnType mod_mask) {
    const ScanConfig *cfg = &ctx->config;
    int active = 0;
    for (int m = 0; m < module_count; m++)
        if (mod_mask & modules[m].type) active++;
    int total_jobs = ctx->crawl.form_count * (active > 0 ? active : 1);
    printf(COL_BOLD "[Attack] Forms: %d  Modules: %d  Jobs: %d\n" COL_RESET,
           ctx->crawl.form_count, active, total_jobs);
    progress_global_init(total_jobs > 0 ? total_jobs : 1, cfg->color, "Attacking");
    int job = 0;
    for (int fi = 0; fi < ctx->crawl.form_count; fi++) {
        const Form *form = &ctx->crawl.forms[fi];
        if (form->field_count == 0) { job += active; progress_global_tick(job); continue; }
        for (int mi = 0; mi < module_count; mi++) {
            AttackModule *mod = &modules[mi];
            if (!(mod_mask & mod->type)) continue;
            log_info(cfg->verbose, cfg->color,
                     "[%s] → %s (%d params)", mod->name, form->url, form->field_count);
            mod->run(ctx, form);
            progress_global_tick(++job);
        }
    }
    progress_global_finish();
    printf(COL_BOLD "[Attack] Done. Vulnerabilities: " COL_RESET);
    printf(ctx->vuln_count > 0 ? COL_RED "%d\n" COL_RESET
                                : COL_GREEN "0\n" COL_RESET, ctx->vuln_count);
    return ctx->vuln_count;
}

/* ─── Full attack ─────────────────────────────────────────── */
int attack_run_all(ScanContext *ctx) {
    harvest_url_forms(ctx);
    return run_modules(ctx, ctx->config.modules);
}

/* ─── Retargeted re-scan ──────────────────────────────────── */
int attack_run_retarget(ScanContext *ctx, int64_t prev_scan_id) {
    /* load only vulnerable forms from previous scan */
    db_load_retarget_forms(ctx, prev_scan_id);
    harvest_url_forms(ctx);

    /* restrict modules to only types found before */
    VulnType mask = db_vuln_types_of_scan(ctx, prev_scan_id);
    /* intersect with user's --modules flag */
    mask &= ctx->config.modules;
    if (!mask) mask = ctx->config.modules;

    printf(COL_YELLOW "[Retarget] Testing %d forms with mask=0x%02x\n" COL_RESET,
           ctx->crawl.form_count, (unsigned)mask);

    /* load old vulns so we can mark confirmed/fixed */
    int old_count = ctx->vuln_count;
    db_load_findings(ctx, prev_scan_id);
    int prev_count = ctx->vuln_count - old_count;
    printf("[Retarget] %d previous findings to verify\n", prev_count);

    /* run modules */
    int new_vulns_start = ctx->vuln_count;
    /* temporarily zero vuln_count so run_modules fills fresh */
    int saved_count = ctx->vuln_count;
    ctx->vuln_count = 0;
    run_modules(ctx, mask);
    int new_found = ctx->vuln_count;

    /* merge: restore previous + mark confirmed/fixed */
    printf("\n" COL_BOLD "[Retarget] Verification:\n" COL_RESET);
    for (int i = old_count; i < old_count + prev_count; i++) {
        Vuln *prev = &ctx->vulns[i + new_found];   /* previous findings shifted */
        /* check if still present in new results */
        bool still_present = false;
        for (int j = 0; j < new_found; j++) {
            Vuln *nw = &ctx->vulns[j];
            if (nw->type == prev->type
                && strcmp(nw->url,       prev->url)       == 0
                && strcmp(nw->parameter, prev->parameter) == 0) {
                still_present = true; break;
            }
        }
        prev->confirmed = still_present;
        if (prev->db_id)
            db_confirm_finding(ctx, prev->db_id, still_present);
        printf("  [%s] %-10s %s param=%s\n",
               still_present ? COL_RED "ACTIVE" COL_RESET
                             : COL_GREEN " FIXED" COL_RESET,
               prev->module, prev->url, prev->parameter);
    }

    /* restore combined count */
    ctx->vuln_count = new_found;
    (void)saved_count; (void)new_vulns_start;
    return ctx->vuln_count;
}
