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

/* ═══════════════════════════════════════════════════════════
 * LFI
 * ═══════════════════════════════════════════════════════════ */
int module_lfi_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "LFI:  %s", form->url);

    const char **payloads = payloads_get(PL_LFI);
    const char **markers  = payloads_markers(PL_LFI);
    if (!payloads || !markers) return 0;

    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        for (int p = 0; payloads[p]; p++) {
            Param params[MAX_HEADERS];
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            strncpy(params[f].value, payloads[p], MAX_PARAM_LEN-1);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;
            bool vuln = false;
            if (resp->body)
                for (int e = 0; markers[e] && !vuln; e++)
                    vuln = str_contains_icase(resp->body, markers[e]);
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_LFI; v.severity = 5; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   payloads[p],          MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence), "File content in response");
                strncpy(v.module, "lfi", 63);
                attack_add_vuln(ctx, &v);
                log_vuln(ctx->config.color, "LFI  URL=%-40s PARAM=%s",
                         form->url, form->fields[f].name);
                found++; http_response_free(resp); break;
            }
            http_response_free(resp);
        }
    }
    return found;
}

/* ═══════════════════════════════════════════════════════════
 * RCE
 * ═══════════════════════════════════════════════════════════ */
int module_rce_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "RCE:  %s", form->url);

    const char **payloads = payloads_get(PL_RCE);
    const char **markers  = payloads_markers(PL_RCE);
    if (!payloads || !markers) return 0;

    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        for (int p = 0; payloads[p]; p++) {
            Param params[MAX_HEADERS];
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            snprintf(params[f].value, MAX_PARAM_LEN, "test%s", payloads[p]);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;
            bool vuln = false;
            if (resp->body)
                for (int e = 0; markers[e] && !vuln; e++)
                    vuln = str_contains_icase(resp->body, markers[e]);
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_RCE; v.severity = 5; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   payloads[p],          MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence), "Command output in response");
                strncpy(v.module, "rce", 63);
                attack_add_vuln(ctx, &v);
                log_vuln(ctx->config.color, "RCE  URL=%-40s PARAM=%s",
                         form->url, form->fields[f].name);
                found++; http_response_free(resp); break;
            }
            http_response_free(resp);
        }
    }
    return found;
}

/* ═══════════════════════════════════════════════════════════
 * Open Redirect
 * ═══════════════════════════════════════════════════════════ */
int module_open_redirect_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "Redir:%s", form->url);

    const char **payloads = payloads_get(PL_REDIRECT);
    const char **hints    = payloads_hints(PL_REDIRECT);
    if (!payloads) return 0;

    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        bool candidate = false;
        if (hints)
            for (int h = 0; hints[h] && !candidate; h++)
                candidate = str_contains_icase(form->fields[f].name, hints[h]);
        if (!candidate) continue;

        for (int p = 0; payloads[p]; p++) {
            Param params[MAX_HEADERS];
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            strncpy(params[f].value, payloads[p], MAX_PARAM_LEN-1);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;
            bool vuln = str_contains_icase(resp->redirect_url, "scanxss-check.invalid");
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_OPEN_REDIR; v.severity = 3; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   payloads[p],          MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence),
                         "Redirect to: %.200s", resp->redirect_url);
                strncpy(v.module, "redirect", 63);
                attack_add_vuln(ctx, &v);
                log_vuln(ctx->config.color, "Redir URL=%-40s PARAM=%s",
                         form->url, form->fields[f].name);
                found++;
            }
            http_response_free(resp);
            if (found) break;
        }
    }
    return found;
}

/* ═══════════════════════════════════════════════════════════
 * CRLF
 * ═══════════════════════════════════════════════════════════ */
int module_crlf_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "CRLF: %s", form->url);

    const char **payloads = payloads_get(PL_CRLF);
    const char **markers  = payloads_markers(PL_CRLF);
    if (!payloads) return 0;

    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        for (int p = 0; payloads[p]; p++) {
            char url[MAX_URL_LEN*2];
            snprintf(url, sizeof(url)-1, "%s?%s=%s",
                     form->url, form->fields[f].name, payloads[p]);
            rate_wait(&ctx->rate);
            ctx->requests_made++;
            HttpResponse *resp = http_get(&ctx->config, url);
            if (!resp) continue;
            bool vuln = str_contains_icase(resp->content_type, "scanxss");
            if (!vuln && resp->body && markers)
                for (int m = 0; markers[m] && !vuln; m++)
                    vuln = str_contains_icase(resp->body, markers[m]);
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_CRLF; v.severity = 3; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   payloads[p],          MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence), "CRLF header injected");
                strncpy(v.module, "crlf", 63);
                attack_add_vuln(ctx, &v);
                log_vuln(ctx->config.color, "CRLF URL=%-40s PARAM=%s",
                         form->url, form->fields[f].name);
                found++;
            }
            http_response_free(resp);
            if (found) break;
        }
    }
    return found;
}
