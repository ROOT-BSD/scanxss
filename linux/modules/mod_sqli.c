/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * SPDX-License-Identifier: GPL-2.0
 */

#include "scanxss.h"

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


int module_sqli_run(ScanContext *ctx, const Form *form) {
    const ScanConfig *cfg = &ctx->config;
    log_info(cfg->verbose, cfg->color, "SQLi: %s", form->url);

    const char **payloads = payloads_get(PL_SQLI);
    const char **markers  = payloads_markers(PL_SQLI);
    if (!payloads || !markers) return 0;

    /* Читаємо baseline з кешу Form — якщо вже виміряно crawl-ером.
     * Якщо ні (-1) — вимірюємо один раз і зберігаємо в Form.     *
     * Form передається як const, але baseline_len — mutable кеш.  */
    long base = ((Form *)form)->baseline_len;
    if (base < 0) {
        Param params[MAX_HEADERS];
        memcpy(params, form->fields, sizeof(Param)*form->field_count);
        HttpResponse *r = fire(ctx, form, params);
        if (r) { base = (long)r->body_len; http_response_free(r); }
        ((Form *)form)->baseline_len = base; /* кешуємо */
    }

    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        Param params[MAX_HEADERS];
        for (int p = 0; payloads[p]; p++) {
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            strncpy(params[f].value, payloads[p], MAX_PARAM_LEN-1);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;

            bool vuln = false;
            if (resp->body) {
                for (int e = 0; markers[e] && !vuln; e++)
                    vuln = str_contains_icase(resp->body, markers[e]);
                /* Differential: значна зміна довжини на quote payload */
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
                strncpy(v.payload,   payloads[p],          MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence),
                         "DB error or differential response (base=%ld got=%zu)",
                         base, resp->body_len);
                strncpy(v.module, "sqli", 63);
                attack_add_vuln(ctx, &v);
                log_vuln(cfg->color, "SQLi URL=%-40s PARAM=%s",
                         form->url, form->fields[f].name);
                found++;
                http_response_free(resp);
                break;
            }
            http_response_free(resp);
        }
    }
    return found;
}
