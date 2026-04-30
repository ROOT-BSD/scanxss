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
#include <curl/curl.h>

/* ── Default browser-like User-Agent ────────────────────────
 * Sending "ScanXSS/1.x" immediately triggers bot filters.
 * Default to a real Chrome UA — user can override with -a.  */
#define DEFAULT_UA \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
    "AppleWebKit/537.36 (KHTML, like Gecko) " \
    "Chrome/124.0.0.0 Safari/537.36"

/* ── Write callback ─────────────────────────────────────────*/
typedef struct { char *data; size_t len; size_t cap; } MemBuf;

static size_t write_cb(void *ptr, size_t sz, size_t nmemb, void *ud) {
    MemBuf *buf = (MemBuf *)ud;
    size_t  n   = sz * nmemb;
    if (buf->len + n + 1 > buf->cap) {
        buf->cap  = (buf->len + n + 1) * 2;
        buf->data = realloc(buf->data, buf->cap);
        if (!buf->data) return 0;
    }
    memcpy(buf->data + buf->len, ptr, n);
    buf->len += n;
    buf->data[buf->len] = '\0';
    return n;
}

/* ── Header callback — capture Content-Type, Location ───── */
typedef struct {
    char ct[256];
    char redir[MAX_URL_LEN];
    char final_url[MAX_URL_LEN]; /* URL after redirect chain */
} HeaderCtx;

static size_t header_cb(char *buf, size_t sz, size_t n, void *ud) {
    HeaderCtx *h = (HeaderCtx *)ud;
    size_t total = sz * n;
    if (strncasecmp(buf, "Content-Type:", 13) == 0)
        sscanf(buf+13, " %255[^\r\n]", h->ct);
    else if (strncasecmp(buf, "Location:", 9) == 0)
        sscanf(buf+9, " %1023[^\r\n]", h->redir);
    return total;
}

/* ── Build a CURL handle with all standard options ─────────*/
static CURL *make_curl(const ScanConfig *cfg, MemBuf *body, HeaderCtx *hctx) {
    CURL *c = curl_easy_init();
    if (!c) return NULL;

    /* body + headers */
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA,     body);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA,     hctx);

    /* timeouts */
    long to = (long)(cfg->timeout > 0 ? cfg->timeout : 15);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,        to);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, to / 2 + 1);

    /* User-Agent — default to Chrome, not "ScanXSS" */
    curl_easy_setopt(c, CURLOPT_USERAGENT,
                     cfg->user_agent[0] ? cfg->user_agent : DEFAULT_UA);

    /* browser-like headers to avoid trivial bot-detection */
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs,
        "Accept: text/html,application/xhtml+xml,"
        "application/xml;q=0.9,image/webp,*/*;q=0.8");
    hdrs = curl_slist_append(hdrs, "Accept-Language: uk-UA,uk;q=0.9,en;q=0.8");
    hdrs = curl_slist_append(hdrs, "Accept-Encoding: gzip, deflate, br");
    hdrs = curl_slist_append(hdrs, "Connection: keep-alive");
    hdrs = curl_slist_append(hdrs, "Upgrade-Insecure-Requests: 1");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    /* libcurl frees slist after easy_cleanup — store pointer to free later */
    curl_easy_setopt(c, CURLOPT_PRIVATE, (void *)hdrs);

    /* SSL: ignore self-signed certs (pentest target) */
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);

    /* redirect handling */
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION,
                     cfg->follow_redirects ? 1L : 0L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(c, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);

    /* encoding — curl auto-decompresses gzip/br */
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");

    if (cfg->cookies[0])
        curl_easy_setopt(c, CURLOPT_COOKIE, cfg->cookies);
    if (cfg->proxy[0])
        curl_easy_setopt(c, CURLOPT_PROXY, cfg->proxy);

    return c;
}

static HttpResponse *finish(CURL *c, MemBuf *body, HeaderCtx *hctx) {
    HttpResponse *resp = calloc(1, sizeof(HttpResponse));
    CURLcode rc = curl_easy_perform(c);

    /* free custom headers */
    void *hdrs = NULL;
    curl_easy_getinfo(c, CURLINFO_PRIVATE, &hdrs);
    if (hdrs) curl_slist_free_all((struct curl_slist *)hdrs);

    if (rc != CURLE_OK) {
        /* store curl error code as negative status so caller can see it */
        resp->status_code = -(long)rc;
        strncpy(resp->content_type, curl_easy_strerror(rc),
                sizeof(resp->content_type)-1);
        free(body->data);
        resp->body     = NULL;
        resp->body_len = 0;
        curl_easy_cleanup(c);
        return resp;
    }

    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp->status_code);

    /* get final URL after redirects */
    char *eff = NULL;
    curl_easy_getinfo(c, CURLINFO_EFFECTIVE_URL, &eff);
    if (eff) strncpy(hctx->final_url, eff, sizeof(hctx->final_url)-1);

    resp->body     = body->data;
    resp->body_len = body->len;
    strncpy(resp->content_type, hctx->ct,         sizeof(resp->content_type)-1);
    strncpy(resp->redirect_url, hctx->redir,       sizeof(resp->redirect_url)-1);
    strncpy(resp->final_url,    hctx->final_url,   sizeof(resp->final_url)-1);

    curl_easy_cleanup(c);
    return resp;
}

/* ── Public API ─────────────────────────────────────────────*/
HttpResponse *http_get(const ScanConfig *cfg, const char *url) {
    MemBuf    body = { calloc(1,1), 0, 1 };
    HeaderCtx hctx = {0};
    CURL *c = make_curl(cfg, &body, &hctx);
    if (!c) { free(body.data); return NULL; }
    curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(c, CURLOPT_URL, url);
    return finish(c, &body, &hctx);
}

/* ── HEAD-запит: тільки заголовки, без тіла ─────────────── *
 * Використовується для перевірки Content-Type перед         *
 * повним завантаженням — пропускаємо зображення, PDF, ZIP.  */
HttpResponse *http_head(const ScanConfig *cfg, const char *url) {
    MemBuf    body = { calloc(1,1), 0, 1 };
    HeaderCtx hctx = {0};
    CURL *c = make_curl(cfg, &body, &hctx);
    if (!c) { free(body.data); return NULL; }
    curl_easy_setopt(c, CURLOPT_NOBODY, 1L);   /* тільки заголовки */
    curl_easy_setopt(c, CURLOPT_URL, url);
    HttpResponse *resp = finish(c, &body, &hctx);
    /* HEAD повертає порожнє тіло — звільняємо буфер */
    if (resp) { free(resp->body); resp->body = NULL; resp->body_len = 0; }
    return resp;
}

HttpResponse *http_post(const ScanConfig *cfg, const char *url,
                        const Param *params, int count) {
    MemBuf    body = { calloc(1,1), 0, 1 };
    HeaderCtx hctx = {0};
    CURL *c = make_curl(cfg, &body, &hctx);
    if (!c) { free(body.data); return NULL; }

    char postdata[8192] = {0};
    for (int i = 0; i < count; i++) {
        char *en = curl_easy_escape(c, params[i].name,  0);
        char *ev = curl_easy_escape(c, params[i].value, 0);
        if (i) strncat(postdata, "&", sizeof(postdata)-strlen(postdata)-1);
        strncat(postdata, en, sizeof(postdata)-strlen(postdata)-1);
        strncat(postdata, "=", sizeof(postdata)-strlen(postdata)-1);
        strncat(postdata, ev, sizeof(postdata)-strlen(postdata)-1);
        curl_free(en); curl_free(ev);
    }
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, postdata);
    return finish(c, &body, &hctx);
}

void http_response_free(HttpResponse *resp) {
    if (!resp) return;
    free(resp->body);
    free(resp);
}

/* ══════════════════════════════════════════════════════════
 * curl Multi — паралельні HTTP GET-запити
 *
 * http_multi_get() виконує до MULTI_MAX_PARALLEL запитів
 * одночасно без потоків. Кожен результат передається у
 * callback по мірі завершення.
 *
 * Використовується у фазі атак: сотні GET-запитів з різними
 * payload-ами незалежні — ідеально для curl_multi.
 *
 * API:
 *   int http_multi_get(cfg, urls, count, cb, userdata)
 *   cb(resp, url, index, userdata) викликається для кожного
 *   завершеного запиту. resp може бути NULL при помилці.
 *   cb відповідає за http_response_free(resp).
 * ══════════════════════════════════════════════════════════ */

#define MULTI_MAX_PARALLEL  8    /* запитів одночасно */
#define MULTI_MAX_URLS   4096    /* максимум URLs за один виклик */

typedef struct {
    MemBuf    body;
    HeaderCtx hctx;
    char      url[MAX_URL_LEN];
    int       index;
    void     *userdata;
} MultiSlot;

int http_multi_get(const ScanConfig *cfg,
                   const char **urls, int count,
                   HttpMultiCb cb, void *userdata) {
    if (!urls || count <= 0 || !cb) return 0;
    if (count > MULTI_MAX_URLS) count = MULTI_MAX_URLS;

    CURLM *multi = curl_multi_init();
    if (!multi) return 0;

    /* Ліміт паралельних з'єднань */
    curl_multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS,
                      (long)MULTI_MAX_PARALLEL);
    curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS,
                      (long)MULTI_MAX_PARALLEL);

    int in_flight = 0;   /* зараз у multi */
    int submitted = 0;   /* скільки URL вже додано */
    int completed = 0;   /* скільки завершено */

    /* Масив слотів — не більше MULTI_MAX_PARALLEL одночасно */
    MultiSlot *slots = calloc((size_t)MULTI_MAX_PARALLEL, sizeof(MultiSlot));
    CURL     **handles = calloc((size_t)MULTI_MAX_PARALLEL, sizeof(CURL *));
    if (!slots || !handles) {
        free(slots); free(handles);
        curl_multi_cleanup(multi);
        return 0;
    }

    /* Запускаємо перші MULTI_MAX_PARALLEL запитів */
    while (submitted < count && in_flight < MULTI_MAX_PARALLEL) {
        int slot = in_flight;
        MultiSlot *s = &slots[slot];

        s->body.data = calloc(1, 1);
        s->body.len  = 0;
        s->body.cap  = 1;
        s->index     = submitted;
        s->userdata  = userdata;
        strncpy(s->url, urls[submitted], MAX_URL_LEN - 1);
        memset(&s->hctx, 0, sizeof(s->hctx));

        CURL *c = make_curl(cfg, &s->body, &s->hctx);
        if (!c) {
            free(s->body.data);
            submitted++;
            continue;
        }
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(c, CURLOPT_URL, s->url);
        /* Зберігаємо індекс слота у private */
        curl_easy_setopt(c, CURLOPT_PRIVATE, (void *)(intptr_t)slot);

        handles[slot] = c;
        curl_multi_add_handle(multi, c);
        submitted++;
        in_flight++;
    }

    /* Event loop */
    while (in_flight > 0) {
        int still_running = 0;
        curl_multi_perform(multi, &still_running);

        /* Обробляємо завершені */
        CURLMsg *msg;
        int msgs_left;
        while ((msg = curl_multi_info_read(multi, &msgs_left)) != NULL) {
            if (msg->msg != CURLMSG_DONE) continue;

            CURL *done_handle = msg->easy_handle;

            /* Знаходимо слот */
            void *priv = NULL;
            curl_easy_getinfo(done_handle, CURLINFO_PRIVATE, &priv);
            int slot = (int)(intptr_t)priv;
            MultiSlot *s = &slots[slot];

            /* Будуємо HttpResponse */
            HttpResponse *resp = calloc(1, sizeof(HttpResponse));
            if (resp) {
                CURLcode rc = msg->data.result;
                if (rc == CURLE_OK) {
                    curl_easy_getinfo(done_handle,
                                      CURLINFO_RESPONSE_CODE,
                                      &resp->status_code);
                    char *eff = NULL;
                    curl_easy_getinfo(done_handle,
                                      CURLINFO_EFFECTIVE_URL, &eff);
                    if (eff) strncpy(s->hctx.final_url, eff,
                                     sizeof(s->hctx.final_url) - 1);
                } else {
                    resp->status_code = -(long)rc;
                }
                resp->body      = s->body.data;
                resp->body_len  = s->body.len;
                strncpy(resp->content_type, s->hctx.ct,
                        sizeof(resp->content_type) - 1);
                strncpy(resp->redirect_url, s->hctx.redir,
                        sizeof(resp->redirect_url) - 1);
                strncpy(resp->final_url, s->hctx.final_url,
                        sizeof(resp->final_url) - 1);
                s->body.data = NULL; /* передали власність у resp */
            } else {
                free(s->body.data);
            }

            /* Звільняємо custom headers */
            void *hdrs = NULL;
            curl_easy_getinfo(done_handle, CURLINFO_PRIVATE, &hdrs);
            /* CURLINFO_PRIVATE перезаписаний slot — звільняємо через окреме місце */
            curl_multi_remove_handle(multi, done_handle);
            curl_easy_cleanup(done_handle);
            handles[slot] = NULL;

            /* Викликаємо callback */
            cb(resp, s->url, s->index, userdata);
            completed++;
            in_flight--;
            progress_global_spin();

            /* Додаємо наступний URL у звільнений слот */
            if (submitted < count) {
                s->body.data = calloc(1, 1);
                s->body.len  = 0;
                s->body.cap  = 1;
                s->index     = submitted;
                strncpy(s->url, urls[submitted], MAX_URL_LEN - 1);
                memset(&s->hctx, 0, sizeof(s->hctx));

                CURL *c = make_curl(cfg, &s->body, &s->hctx);
                if (c) {
                    curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
                    curl_easy_setopt(c, CURLOPT_URL, s->url);
                    curl_easy_setopt(c, CURLOPT_PRIVATE,
                                     (void *)(intptr_t)slot);
                    handles[slot] = c;
                    curl_multi_add_handle(multi, c);
                    submitted++;
                    in_flight++;
                } else {
                    submitted++;
                }
            }
        }

        /* Чекаємо активності — не busy-loop */
        if (still_running > 0) {
            int numfds = 0;
            curl_multi_wait(multi, NULL, 0, 100, &numfds);
            progress_global_spin();
        }
    }

    /* Прибираємо незавершені (якщо перервано) */
    for (int i = 0; i < MULTI_MAX_PARALLEL; i++) {
        if (handles[i]) {
            curl_multi_remove_handle(multi, handles[i]);
            curl_easy_cleanup(handles[i]);
        }
        free(slots[i].body.data);
    }
    free(slots);
    free(handles);
    curl_multi_cleanup(multi);
    return completed;
}
