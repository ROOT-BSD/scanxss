/*
 * Copyright (c) 2025 root_bsd (mglushak@gmail.com)
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
 * SPDX-License-Identifier: GPL-2.0
 */

#include "scanxss.h"

/* Error-based detection payloads — most trigger DB errors quickly */
static const char *sqli_payloads[] = {
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "1 AND 1=2 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    NULL
};

/* Canonical DB error strings */
static const char *sqli_errors[] = {
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-0",
    "sqlite3.operationalerror",
    "pg::syntaxerror",
    "syntax error in query",
    "mysql_fetch",
    "db2 sql error",
    NULL
};

static HttpResponse *fire(ScanContext *ctx, const Form *form, Param *params) {
    const ScanConfig *cfg = &ctx->config;
    rate_wait(&ctx->rate);
    ctx->requests_made++;
    if (form->method == METHOD_POST)
        return http_post(cfg, form->url, params, form->field_count);
    char url[MAX_URL_LEN*2] = {0};
    strncpy(url, form->url, MAX_URL_LEN-1);
    strncat(url, "?", sizeof(url)-strlen(url)-1);
    for (int i = 0; i < form->field_count; i++) {
        if (i) strncat(url, "&", sizeof(url)-strlen(url)-1);
        strncat(url, params[i].name,  sizeof(url)-strlen(url)-1);
        strncat(url, "=",             sizeof(url)-strlen(url)-1);
        char *enc = url_encode(params[i].value);
        strncat(url, enc, sizeof(url)-strlen(url)-1);
        free(enc);
    }
    return http_get(cfg, url);
}

/* Probe: fetch clean baseline and check response length */
static long baseline_len(ScanContext *ctx, const Form *form) {
    Param params[MAX_HEADERS];
    memcpy(params, form->fields, sizeof(Param)*form->field_count);
    HttpResponse *r = fire(ctx, form, params);
    if (!r) return -1;
    long len = (long)r->body_len;
    http_response_free(r);
    return len;
}

int module_sqli_run(ScanContext *ctx, const Form *form) {
    const ScanConfig *cfg = &ctx->config;
    log_info(cfg->verbose, cfg->color, "SQLi: %s", form->url);
    int found = 0;

    /* Get baseline once per form */
    long base = baseline_len(ctx, form);

    for (int f = 0; f < form->field_count; f++) {
        Param params[MAX_HEADERS];
        for (int p = 0; sqli_payloads[p]; p++) {
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            strncpy(params[f].value, sqli_payloads[p], MAX_PARAM_LEN-1);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;

            bool vuln = false;
            if (resp->body) {
                for (int e = 0; sqli_errors[e] && !vuln; e++)
                    vuln = str_contains_icase(resp->body, sqli_errors[e]);
                /* Differential: significant length change on quote payload */
                if (!vuln && base > 0 && (p == 0 || p == 1)) {
                    long diff = (long)resp->body_len - base;
                    if (diff < -200 || diff > 500) vuln = true;
                }
            }
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_SQLI; v.severity = 5; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   sqli_payloads[p],     MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence),
                         "DB error or differential response (base=%ld got=%zu)",
                         base, resp->body_len);
                strncpy(v.module, "sqli", 63);
                attack_add_vuln(ctx, &v);
                log_vuln(cfg->color, "SQLi URL=%-40s PARAM=%s",
                         form->url, form->fields[f].name);
                found++;
                http_response_free(resp);
                break;   /* next field */
            }
            http_response_free(resp);
        }
    }
    return found;
}
