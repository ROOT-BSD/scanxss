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

/* ── Generic request helper ─────────────────────────────────── */
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
static const char *lfi_payloads[] = {
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    NULL
};
static const char *lfi_indicators[] = {
    "root:x:0:0:", "daemon:x:", "[boot loader]", "[extensions]", NULL
};

int module_lfi_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "LFI:  %s", form->url);
    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        for (int p = 0; lfi_payloads[p]; p++) {
            Param params[MAX_HEADERS];
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            strncpy(params[f].value, lfi_payloads[p], MAX_PARAM_LEN-1);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;
            bool vuln = false;
            if (resp->body)
                for (int e = 0; lfi_indicators[e] && !vuln; e++)
                    vuln = str_contains_icase(resp->body, lfi_indicators[e]);
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_LFI; v.severity = 5; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   lfi_payloads[p],      MAX_PARAM_LEN-1);
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
static const char *rce_payloads[] = {
    ";id", "|id", "$(id)", "`id`", "&& id", NULL
};
static const char *rce_indicators[] = { "uid=", "root:x:", "www-data", NULL };

int module_rce_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "RCE:  %s", form->url);
    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        for (int p = 0; rce_payloads[p]; p++) {
            Param params[MAX_HEADERS];
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            snprintf(params[f].value, MAX_PARAM_LEN, "test%s", rce_payloads[p]);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;
            bool vuln = false;
            if (resp->body)
                for (int e = 0; rce_indicators[e] && !vuln; e++)
                    vuln = str_contains_icase(resp->body, rce_indicators[e]);
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_RCE; v.severity = 5; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   rce_payloads[p],      MAX_PARAM_LEN-1);
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
static const char *redir_payloads[] = {
    "https://scanxss-check.invalid/",
    "//scanxss-check.invalid/",
    "https:scanxss-check.invalid",
    NULL
};
static const char *redir_param_hints[] = {
    "url","uri","redirect","redir","next","goto","return","location",
    "dest","destination","target","href","link","path","src", NULL
};

int module_open_redirect_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "Redir:%s", form->url);
    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        /* Only test params that look like redirect vectors */
        bool candidate = false;
        for (int h = 0; redir_param_hints[h] && !candidate; h++)
            candidate = str_contains_icase(form->fields[f].name, redir_param_hints[h]);
        if (!candidate) continue;

        for (int p = 0; redir_payloads[p]; p++) {
            Param params[MAX_HEADERS];
            memcpy(params, form->fields, sizeof(Param)*form->field_count);
            strncpy(params[f].value, redir_payloads[p], MAX_PARAM_LEN-1);
            HttpResponse *resp = fire(ctx, form, params);
            if (!resp) continue;
            bool vuln = str_contains_icase(resp->redirect_url, "scanxss-check.invalid");
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_OPEN_REDIR; v.severity = 3; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   redir_payloads[p],    MAX_PARAM_LEN-1);
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
static const char *crlf_payloads[] = {
    "%0d%0aX-ScanXSS:injected",
    "%0aX-ScanXSS:injected",
    "\r\nX-ScanXSS:injected",
    NULL
};

int module_crlf_run(ScanContext *ctx, const Form *form) {
    log_info(ctx->config.verbose, ctx->config.color, "CRLF: %s", form->url);
    int found = 0;
    for (int f = 0; f < form->field_count; f++) {
        for (int p = 0; crlf_payloads[p]; p++) {
            char url[MAX_URL_LEN*2];
            snprintf(url, sizeof(url)-1, "%s?%s=%s",
                     form->url, form->fields[f].name, crlf_payloads[p]);
            rate_wait(&ctx->rate);
            ctx->requests_made++;
            HttpResponse *resp = http_get(&ctx->config, url);
            if (!resp) continue;
            bool vuln = str_contains_icase(resp->content_type, "scanxss")
                     || (resp->body && str_contains_icase(resp->body, "X-ScanXSS"));
            if (vuln) {
                Vuln v = {0};
                v.type = VULN_CRLF; v.severity = 3; v.found_at = time(NULL);
                strncpy(v.url,       form->url,            MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[f].name, MAX_PARAM_LEN-1);
                strncpy(v.payload,   crlf_payloads[p],     MAX_PARAM_LEN-1);
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
