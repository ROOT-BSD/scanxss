/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * SPDX-License-Identifier: GPL-2.0
 */

#include "scanxss.h"

static bool param_is_ssrf_candidate(const char *name) {
    const char **hints = payloads_hints(PL_SSRF);
    if (!hints) return false;
    for (int i = 0; hints[i]; i++)
        if (str_contains_icase(name, hints[i]))
            return true;
    return false;
}

static int test_ssrf(ScanContext *ctx, const Form *form,
                     int fidx, const char *payload) {
    const ScanConfig *cfg = &ctx->config;
    Param params[MAX_HEADERS];
    memcpy(params, form->fields, sizeof(Param)*form->field_count);
    strncpy(params[fidx].value, payload, MAX_PARAM_LEN-1);

    HttpResponse *resp = NULL;
    rate_wait(&ctx->rate);
    ctx->requests_made++;
    if (form->method == METHOD_POST) {
        resp = http_post(cfg, form->url, params, form->field_count);
    } else {
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
        resp = http_get(cfg, url);
    }
    if (!resp) return 0;

    const char **markers = payloads_markers(PL_SSRF);
    int found = 0;
    if (resp->body && markers) {
        for (int k = 0; markers[k]; k++) {
            if (str_contains_icase(resp->body, markers[k])) {
                Vuln v = {0};
                v.type = VULN_SSRF; v.severity = 5; v.found_at = time(NULL);
                strncpy(v.url,       form->url,               MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[fidx].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   payload,                 MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence),
                         "Internal response indicator: %s", markers[k]);
                strncpy(v.module, "ssrf", sizeof(v.module)-1);
                attack_add_vuln(ctx, &v);
                log_vuln(cfg->color, "SSRF found! URL=%s PARAM=%s PAYLOAD=%s",
                         form->url, form->fields[fidx].name, payload);
                found = 1;
                break;
            }
        }
    }
    http_response_free(resp);
    return found;
}

int module_ssrf_run(ScanContext *ctx, const Form *form) {
    const ScanConfig *cfg = &ctx->config;
    log_info(cfg->verbose, cfg->color, "SSRF testing: %s", form->url);

    const char **payloads = payloads_get(PL_SSRF);
    if (!payloads) return 0;

    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        if (!cfg->verbose && !param_is_ssrf_candidate(form->fields[f].name))
            continue;

        for (int p = 0; payloads[p]; p++)
            found += test_ssrf(ctx, form, f, payloads[p]);

        if (cfg->endpoint[0]) {
            char cb[MAX_URL_LEN];
            snprintf(cb, sizeof(cb), "%s?ssrf_token=%lx_%s",
                     cfg->endpoint, (unsigned long)time(NULL),
                     form->fields[f].name);
            found += test_ssrf(ctx, form, f, cb);
        }
    }
    return found;
}
