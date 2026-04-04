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
