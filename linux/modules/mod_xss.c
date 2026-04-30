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

static bool probe_reflects(ScanContext *ctx, const Form *form, int fidx) {
    const char *PROBE = "scanxss_probe_7x9";
    Param params[MAX_HEADERS];
    memcpy(params, form->fields, sizeof(Param)*form->field_count);
    strncpy(params[fidx].value, PROBE, MAX_PARAM_LEN-1);
    HttpResponse *r = fire(ctx, form, params);
    if (!r) return false;
    bool reflects = r->body && str_contains_icase(r->body, PROBE);
    http_response_free(r);
    return reflects;
}

int module_xss_run(ScanContext *ctx, const Form *form) {
    const ScanConfig *cfg = &ctx->config;
    log_info(cfg->verbose, cfg->color, "XSS: %s", form->url);

    const char **payloads = payloads_get(PL_XSS);
    const char **markers  = payloads_markers(PL_XSS);
    if (!payloads || !markers) return 0;

    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        if (!probe_reflects(ctx, form, f)) continue;

        Param params[MAX_HEADERS];
        for (int p = 0; payloads[p]; p++) {
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            strncpy(params[f].value, payloads[p], MAX_PARAM_LEN-1);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;

            bool vuln = false;
            if (resp->body)
                for (int m = 0; markers[m] && !vuln; m++)
                    vuln = str_contains_icase(resp->body, markers[m]);

            if (vuln) {
                Vuln v = {0};
                v.type = VULN_XSS; v.severity = 4; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   payloads[p],          MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence), "Reflected payload in response");
                strncpy(v.module, "xss", 63);
                attack_add_vuln(ctx, &v);
                log_vuln(cfg->color, "XSS  URL=%-40s PARAM=%s",
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
