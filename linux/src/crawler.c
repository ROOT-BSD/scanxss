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
#include <unistd.h>

/* ── Visited-URL hash set ─────────────────────────────────── */
#define VIS_SIZE 8192
static char visited[VIS_SIZE][MAX_URL_LEN];

static unsigned int djb2(const char *s) {
    unsigned int h = 5381;
    while (*s) h = ((h<<5)+h) ^ (unsigned char)*s++;
    return h;
}

static void visited_reset(void) {
    memset(visited, 0, sizeof(visited));
}

static bool visited_check(const char *url) {
    unsigned int idx = djb2(url) & (VIS_SIZE-1);
    for (int i = 0; i < VIS_SIZE; i++) {
        unsigned int k = (idx+i) & (VIS_SIZE-1);
        if (!visited[k][0])   return false;   /* empty slot = not found */
        if (strcmp(visited[k], url) == 0) return true;
    }
    return true; /* table full — treat as visited to avoid loop */
}

static bool visited_add(const char *url) {
    if (visited_check(url)) return false;      /* already present */
    unsigned int idx = djb2(url) & (VIS_SIZE-1);
    for (int i = 0; i < VIS_SIZE; i++) {
        unsigned int k = (idx+i) & (VIS_SIZE-1);
        if (!visited[k][0]) {
            strncpy(visited[k], url, MAX_URL_LEN-1);
            return true;
        }
    }
    return false; /* full */
}

/* ── HTML attribute extractor ─────────────────────────────── */
static int get_attr(const char *ts, const char *te,
                    const char *attr, char *out, size_t sz) {
    char s1[64], s2[64];
    snprintf(s1, sizeof(s1), "%s=\"", attr);
    snprintf(s2, sizeof(s2), "%s='",  attr);
    char q = '"';
    const char *pos = strcasestr(ts, s1);
    if (!pos || pos >= te) { pos = strcasestr(ts, s2); q='\''; }
    if (!pos || pos >= te) return 0;
    const char *val = pos + strlen(attr) + 2;
    const char *end = memchr(val, q, (size_t)(te - val + 128));
    if (!end) return 0;
    size_t len = (size_t)(end - val);
    if (len >= sz) len = sz-1;
    memcpy(out, val, len); out[len] = '\0';
    return 1;
}

/* ── Normalise URL: strip fragment, decode %20→space etc. ─── */
static void normalise_url(char *url) {
    /* strip fragment */
    char *frag = strchr(url, '#');
    if (frag) *frag = '\0';
    /* strip trailing spaces */
    size_t len = strlen(url);
    while (len > 0 && url[len-1] == ' ') url[--len] = '\0';
}

/* ── Extract links from HTML into result ──────────────────── */
void crawler_extract_links(const char *base_url_str, const char *html,
                            CrawlResult *result) {
    if (!html || !html[0]) return;

    const char *attrs[] = {"href", "src", "action", NULL};
    for (int ai = 0; attrs[ai]; ai++) {
        char search[32];
        snprintf(search, sizeof(search), " %s=", attrs[ai]); /* space before attr */
        const char *p = html;
        while (result->url_count < MAX_LINKS) {
            /* find attr with optional space/tab before it */
            const char *found = strcasestr(p, attrs[ai]);
            if (!found) break;
            /* must be followed by = */
            const char *eq = found + strlen(attrs[ai]);
            while (*eq == ' ' || *eq == '\t') eq++;
            if (*eq != '=') { p = found+1; continue; }
            eq++; /* skip = */

            char q = (*eq == '"' || *eq == '\'') ? *eq : 0;
            const char *val = q ? eq+1 : eq;
            char href[MAX_URL_LEN] = {0};
            size_t i = 0;
            const char *v = val;
            while (*v && i < MAX_URL_LEN-1) {
                if (q && *v == q) break;
                if (!q && (*v==' '||*v=='>'||*v=='\r'||*v=='\n'||*v=='\t')) break;
                href[i++] = *v++;
            }
            p = v;

            if (!href[0]) continue;
            normalise_url(href);
            if (!href[0]) continue;

            /* skip non-navigable */
            if (href[0] == '#') continue;
            if (strncasecmp(href, "mailto:",    7) == 0) continue;
            if (strncasecmp(href, "javascript:",11) == 0) continue;
            if (strncasecmp(href, "data:",       5) == 0) continue;
            if (strncasecmp(href, "tel:",         4) == 0) continue;
            if (strncasecmp(href, "ftp:",         4) == 0) continue;
            if (strncasecmp(href, "ws:",          3) == 0) continue;
            if (strncasecmp(href, "wss:",         4) == 0) continue;

            char *resolved = resolve_url(base_url_str, href);
            if (!resolved) continue;
            normalise_url(resolved);

            /* scope check uses cfg->scope passed via base — we use "subdomain"
               as the effective minimum; caller further filters if needed */
            if (url_in_scope(base_url_str, resolved, "subdomain")) {
                /* dedup within this result batch */
                int dup = 0;
                for (int j = 0; j < result->url_count; j++)
                    if (strcmp(result->urls[j], resolved)==0) { dup=1; break; }
                if (!dup)
                    strncpy(result->urls[result->url_count++],
                            resolved, MAX_URL_LEN-1);
            }
            free(resolved);
        }
    }
}

/* ── Extract forms ────────────────────────────────────────── */
void crawler_extract_forms(const char *page_url, const char *html,
                            CrawlResult *result) {
    if (!html || !html[0]) return;
    const char *p = html;
    while ((p = strcasestr(p, "<form")) != NULL) {
        if (result->form_count >= MAX_FORMS) break;
        /* find end of opening tag */
        const char *te = p+5;
        while (*te && *te!='>') te++;
        if (!*te) { p++; continue; }

        Form *form = &result->forms[result->form_count];
        form->method = METHOD_GET;
        strncpy(form->url, page_url, MAX_URL_LEN-1);

        char mval[16]={0};
        if (get_attr(p,te,"method",mval,sizeof(mval)) &&
            strcasecmp(mval,"post")==0)
            form->method = METHOD_POST;

        char action[MAX_URL_LEN]={0};
        if (get_attr(p,te,"action",action,sizeof(action)) && action[0]) {
            char *r = resolve_url(page_url, action);
            if (r) { strncpy(form->url,r,MAX_URL_LEN-1); free(r); }
        }

        const char *fe = strcasestr(te, "</form>");
        if (!fe) fe = html + strlen(html);

        const char *ip = te+1;
        while (ip < fe && form->field_count < MAX_HEADERS) {
            const char *inp = strcasestr(ip,"<input");
            const char *ta  = strcasestr(ip,"<textarea");
            const char *sel = strcasestr(ip,"<select");
            const char *fd  = NULL;
            if (inp && inp<fe) fd=inp;
            if (ta  && ta<fe  && (!fd||ta<fd))  fd=ta;
            if (sel && sel<fe && (!fd||sel<fd)) fd=sel;
            if (!fd) break;
            const char *end = strchr(fd,'>');
            if (!end||end>fe) { ip=fd+1; continue; }

            Param *field = &form->fields[form->field_count];
            strncpy(field->name,"input",MAX_PARAM_LEN-1);
            field->value[0]='\0';

            char nbuf[MAX_PARAM_LEN]={0};
            if (get_attr(fd,end,"name",nbuf,sizeof(nbuf)) && nbuf[0])
                strncpy(field->name,nbuf,MAX_PARAM_LEN-1);

            /* skip submit/button/hidden with no attack value */
            char tybuf[32]={0};
            if (get_attr(fd,end,"type",tybuf,sizeof(tybuf))) {
                if (strcasecmp(tybuf,"submit")==0 ||
                    strcasecmp(tybuf,"button")==0 ||
                    strcasecmp(tybuf,"image") ==0 ||
                    strcasecmp(tybuf,"reset") ==0)
                { ip=end+1; continue; }
            }

            char vbuf[MAX_PARAM_LEN]={0};
            if (get_attr(fd,end,"value",vbuf,sizeof(vbuf)))
                strncpy(field->value,vbuf,MAX_PARAM_LEN-1);

            form->field_count++;
            ip=end+1;
        }

        if (form->field_count > 0)
            result->form_count++;

        p = fe+1;
    }
}

/* ── BFS Crawler ──────────────────────────────────────────── */
int crawler_run(ScanContext *ctx) {
    const ScanConfig *cfg = &ctx->config;
    visited_reset();

    typedef struct { char url[MAX_URL_LEN]; int depth; } QEntry;
    /* queue size = 2× max_links so we can buffer discovered-but-not-yet-visited */
    int qcap = cfg->max_links * 2 + 2;
    QEntry *queue = calloc((size_t)qcap, sizeof(QEntry));
    if (!queue) return -1;

    int head=0, tail=0;
    strncpy(queue[0].url, cfg->target_url, MAX_URL_LEN-1);
    queue[0].depth = 0;
    tail = 1;
    visited_add(cfg->target_url);

    /* effective scope: user's choice but at least "subdomain" */
    const char *scope = cfg->scope[0] ? cfg->scope : "subdomain";

    printf(COL_BOLD "\n[Crawler] Starting: %s  scope:%s  depth:%d  limit:%d\n"
           COL_RESET,
           cfg->target_url, scope, cfg->depth, cfg->max_links);

    /* progress total is dynamic — starts at 1 (seed), grows as we discover */
    int discovered = 1;
    progress_global_init(1, cfg->color, "Crawling");

    int processed=0, skipped_status=0, skipped_scope=0,
        skipped_nonhtml=0, skipped_last_code=0;

    while (head != tail && ctx->crawl.url_count < cfg->max_links) {
        QEntry cur = queue[head];
        head = (head+1) % qcap;
        processed++;

        /* update progress: done=processed, total=max(discovered, processed) */
        if (discovered < processed) discovered = processed;
        progress_global_tick(processed);

        log_info(cfg->verbose, cfg->color,
                 "[%d/%d] d=%d  %s",
                 ctx->crawl.url_count, cfg->max_links,
                 cur.depth, cur.url);

        rate_wait(&ctx->rate);

        HttpResponse *resp = http_get(cfg, cur.url);
        ctx->requests_made++;

        if (!resp) {
            log_warn(cfg->color, "No response for: %s", cur.url);
            continue;
        }

        /* IMPORTANT: after FOLLOWLOCATION the final URL may differ —
           use cur.url (what we requested) as the "page URL" for link resolution
           so relative links resolve correctly                                   */
        long code = resp->status_code;

        if (code < 0) {
            /* curl error — network/SSL issue */
            log_warn(cfg->color, "Network error [%s]: %s",
                     resp->content_type[0] ? resp->content_type : "curl error",
                     cur.url);
            skipped_status++;
            http_response_free(resp);
            continue;
        }

        if (code < 200 || code >= 400) {
            const char *hint = "";
            if (code == 403) hint = " (Forbidden — try -a 'Mozilla/5.0')";
            if (code == 401) hint = " (Unauthorized — try -c 'session=...')";
            if (code == 429) hint = " (Rate limited — try -r 2)";
            if (code == 503) hint = " (Bot protection — try -a 'Mozilla/5.0')";
            log_warn(cfg->color, "HTTP %ld%s: %s", code, hint, cur.url);
            skipped_status++;
            skipped_last_code = (int)code;
            http_response_free(resp);
            continue;
        }

        /* record the successfully fetched page */
        if (ctx->crawl.url_count < MAX_LINKS) {
            strncpy(ctx->crawl.urls[ctx->crawl.url_count++],
                    cur.url, MAX_URL_LEN-1);
            session_save_url(ctx, cur.url);

        }

        /* is the response navigable HTML? */
        bool is_html = !resp->body ? false :
            (resp->content_type[0] == '\0'                            ||
             str_contains_icase(resp->content_type, "html")           ||
             str_contains_icase(resp->content_type, "xhtml")          ||
             str_contains_icase(resp->content_type, "xml"));

        if (!is_html || !resp->body || resp->body_len == 0) {
            skipped_nonhtml++;
            if (cfg->verbose && !is_html)
                log_info(1, cfg->color,
                         "  Non-HTML (%s) — skipping links",
                         resp->content_type);
            http_response_free(resp);
            continue;
        }

        /* warn about suspiciously small body (SPA shells) */
        if (resp->body_len < 512 && ctx->crawl.url_count == 1) {
            log_warn(cfg->color,
                     "Very small body (%zu bytes) — site may be SPA or bot-protected",
                     resp->body_len);
        }

        /* ── extract forms ── */
        /* use final_url as base for form action resolution */
        const char *page_base = resp->final_url[0] ? resp->final_url : cur.url;
        int prev_fc = ctx->crawl.form_count;
        crawler_extract_forms(page_base, resp->body, &ctx->crawl);
        int new_forms = ctx->crawl.form_count - prev_fc;
        for (int fi = prev_fc; fi < ctx->crawl.form_count; fi++)
            session_save_form(ctx, &ctx->crawl.forms[fi]);
        if (cfg->verbose && new_forms > 0)
            log_info(1, cfg->color, "  %d form(s) found", new_forms);

        /* ── extract & enqueue links ── */
        if (cur.depth < cfg->depth) {
            CrawlResult tmp = {0};
            /* use final_url (after redirects) as base for link resolution */
            const char *link_base = resp->final_url[0]
                                    ? resp->final_url : cur.url;
            crawler_extract_links(link_base, resp->body, &tmp);

            int enq=0, rej_scope=0;
            for (int i = 0; i < tmp.url_count; i++) {
                const char *u = tmp.urls[i];

                /* apply user's scope on top of subdomain minimum */
                if (!url_in_scope(cfg->target_url, u, scope)) {
                    rej_scope++;
                    skipped_scope++;
                    continue;
                }
                if (visited_check(u)) continue;
                if (session_url_visited(ctx, u)) continue;

                if (!visited_add(u)) continue;

                if ((tail+1) % qcap == head) {
                    log_warn(cfg->color, "Queue full — some links dropped");
                    break;
                }
                strncpy(queue[tail].url, u, MAX_URL_LEN-1);
                queue[tail].depth = cur.depth+1;
                tail = (tail+1) % qcap;
                enq++;
                if (discovered < processed + enq)
                    discovered = processed + enq;
            }

            if (cfg->verbose)
                log_info(1, cfg->color,
                         "  links=%d enqueued=%d rejected(scope)=%d",
                         tmp.url_count, enq, rej_scope);

            /* update progress bar total */
            progress_global_init(discovered, cfg->color, "Crawling");
            progress_global_tick(processed);
        }

        http_response_free(resp);
    }

    free(queue);
    progress_global_finish();

    printf(COL_GREEN "[Crawler] Done." COL_RESET
           "  pages=%d  forms=%d  reqs=%d  "
           "skip(status)=%d  skip(scope)=%d  skip(non-html)=%d\n",
           ctx->crawl.url_count, ctx->crawl.form_count,
           ctx->requests_made,
           skipped_status, skipped_scope, skipped_nonhtml);

    /* ── zero-pages diagnostic ── */
    if (ctx->crawl.url_count == 0) {
        printf(COL_YELLOW
               "\n[!] Zero pages crawled. Diagnostics:\n"
               "    Requests made:     %d\n"
               "    HTTP errors:       %d (last code: %d)\n"
               "    Scope rejections:  %d\n"
               "    Non-HTML bodies:   %d\n"
               "\n"
               "  Рекомендації:\n"
               "    HTTP 403/503 — сайт блокує сканер:\n"
               "      додайте: -a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'\n"
               "    HTTP 401   — потрібна авторизація:\n"
               "      додайте: -c 'session=ВАШ_ТОКЕН'\n"
               "    HTTP 429   — rate limit:\n"
               "      зменшіть: -r 2\n"
               "    0 scope    — всі посилання за межами домену:\n"
               "      перевірте: -v для деталей\n"
               "    SPA сайт   — сторінка рендериться у JS:\n"
               "      скористайтесь headless браузером\n"
               COL_RESET "\n",
               ctx->requests_made, skipped_status, skipped_last_code,
               skipped_scope, skipped_nonhtml);
    }

    return 0;
}
