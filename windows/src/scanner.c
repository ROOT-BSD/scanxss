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

#include "scanxss_win.h"
#include "payloads.h"
#include <winhttp.h>
#include <stdlib.h>

/* ══════════════════════════════════════════════════════════
 * HTTP CLIENT
 * ══════════════════════════════════════════════════════════ */
typedef struct {
    char  *body;
    size_t len;
    long   status;
    char   content_type[256];
} WinResp;

static WinResp *whttp_get(const ScanParams *p, const char *url_a) {
    WinResp *r = calloc(1, sizeof(WinResp));

    wchar_t wurl[MAX_URL] = {0};
    MultiByteToWideChar(CP_UTF8, 0, url_a, -1, wurl, MAX_URL-1);

    URL_COMPONENTSW uc = {0};
    uc.dwStructSize    = sizeof(uc);
    wchar_t whost[512]={0}, wpath[MAX_URL]={0}, wscheme[16]={0};
    uc.lpszScheme   = wscheme; uc.dwSchemeLength  = 15;
    uc.lpszHostName = whost;   uc.dwHostNameLength= 511;
    uc.lpszUrlPath  = wpath;   uc.dwUrlPathLength = MAX_URL-1;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) { free(r); return NULL; }

    bool https = (uc.nPort == 443 || _wcsicmp(wscheme, L"https") == 0);

    wchar_t wua[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0,
        p->user_agent[0] ? p->user_agent :
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36",
        -1, wua, 511);

    HINTERNET hS = WinHttpOpen(wua,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { free(r); return NULL; }

    /* FIX 1: Enable automatic gzip/deflate decompression (Win 8.1+) */
    DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_ALL;
    WinHttpSetOption(hS, WINHTTP_OPTION_DECOMPRESSION, &decomp, sizeof(decomp));

    WinHttpSetTimeouts(hS,
        p->timeout*1000, p->timeout*1000,
        p->timeout*1000, p->timeout*1000);

    HINTERNET hC = WinHttpConnect(hS, whost, uc.nPort, 0);
    if (!hC) { WinHttpCloseHandle(hS); free(r); return NULL; }

    DWORD fl = WINHTTP_FLAG_REFRESH;
    if (https) fl |= WINHTTP_FLAG_SECURE;

    const wchar_t *path_to_use = (wpath[0]) ? wpath : L"/";
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path_to_use,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, fl);
    if (!hR) {
        WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        free(r); return NULL;
    }

    /* SSL: ignore cert errors for pentest targets */
    if (https) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                  | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    /* FIX 2: Send browser-like headers WITHOUT Accept-Encoding
     * (decompression handled by WINHTTP_OPTION_DECOMPRESSION above) */
    WinHttpAddRequestHeaders(hR,
        L"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
        L"Accept-Language: uk-UA,uk;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
        L"Connection: keep-alive\r\n"
        L"Upgrade-Insecure-Requests: 1\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    if (p->cookies[0]) {
        wchar_t wck[1024]={0}, ckhdr[1100]={0};
        MultiByteToWideChar(CP_UTF8, 0, p->cookies, -1, wck, 1023);
        _snwprintf(ckhdr, 1099, L"Cookie: %s\r\n", wck);
        WinHttpAddRequestHeaders(hR, ckhdr, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    /* FIX 3: Follow redirects */
    DWORD rdirs = 10;
    WinHttpSetOption(hR, WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS,
                     &rdirs, sizeof(rdirs));

    if (!WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
     || !WinHttpReceiveResponse(hR, NULL)) {
        WinHttpCloseHandle(hR);
        WinHttpCloseHandle(hC);
        WinHttpCloseHandle(hS);
        free(r); return NULL;
    }

    DWORD status = 0, sz = sizeof(DWORD);
    WinHttpQueryHeaders(hR,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &sz, NULL);
    r->status = (long)status;

    wchar_t wct[256] = {0}; sz = sizeof(wct)-2;
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_CONTENT_TYPE, NULL, wct, &sz, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wct, -1, r->content_type, 255, NULL, NULL);

    /* Read body — decompressed automatically by WinHttp */
    size_t cap = 131072; /* start at 128KB */
    r->body = malloc(cap);
    r->len  = 0;
    DWORD avail = 0, rd = 0;
    while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
        if (r->len + avail + 1 > cap) {
            cap = (r->len + avail + 1) * 2;
            char *nb = realloc(r->body, cap);
            if (!nb) break;
            r->body = nb;
        }
        rd = 0;
        WinHttpReadData(hR, r->body + r->len, avail, &rd);
        r->len += rd;
    }
    if (r->body) r->body[r->len] = '\0';

    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return r;
}

static void wfree(WinResp *r) { if (r) { free(r->body); free(r); } }

/* ══════════════════════════════════════════════════════════
 * THREAD HELPERS
 * ══════════════════════════════════════════════════════════ */
static void tlog(ScanParams *p, const char *t, COLORREF c) {
    PostMessage(p->hwnd, WM_SCAN_LOG, (WPARAM)c, (LPARAM)_strdup(t));
}
static void tlogf(ScanParams *p, COLORREF c, const char *fmt, ...) {
    char buf[2048]; va_list a; va_start(a,fmt);
    vsnprintf(buf, 2047, fmt, a); va_end(a);
    tlog(p, buf, c);
}
static void report_vuln(ScanParams *p, int sev,
                         const char *mod, const char *type,
                         const char *url, const char *param,
                         const char *payload, const char *evidence) {
    VulnRecord *v = calloc(1, sizeof(VulnRecord));
    v->severity = sev; v->confirmed = true; v->found_at = time(NULL);
    strncpy(v->module,    mod,      31);
    strncpy(v->type,      type,     63);
    strncpy(v->url,       url,  MAX_URL-1);
    strncpy(v->parameter, param,   255);
    strncpy(v->payload,   payload, 255);
    strncpy(v->evidence,  evidence,511);
    PostMessage(p->hwnd, WM_SCAN_VULN, 0, (LPARAM)v);
}
static void set_progress(ScanParams *p, int pct) {
    PostMessage(p->hwnd, WM_SCAN_PROGRESS, (WPARAM)(pct < 0?0:pct>100?100:pct), 0);
}

/* ══════════════════════════════════════════════════════════
 * URL UTILITIES
 * ══════════════════════════════════════════════════════════ */
static void url_enc(char *out, size_t sz, const char *s) {
    size_t j = 0;
    for (; *s && j < sz-4; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') out[j++] = c;
        else { snprintf(out+j, 4, "%%%02X", c); j += 3; }
    }
    out[j] = '\0';
}

static void build_url(char *out, size_t sz,
                       const char *base, const char *param, const char *val) {
    char enc[1024] = {0};
    url_enc(enc, sizeof(enc), val);
    /* check if base already has query string */
    const char *existing_qs = strchr(base, '?');
    if (existing_qs)
        snprintf(out, sz, "%s&%s=%s", base, param, enc);
    else
        snprintf(out, sz, "%s?%s=%s", base, param, enc);
}

static bool icontains(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return false;
    size_t hl = strlen(hay), nl = strlen(needle);
    if (nl > hl) return false;
    for (size_t i = 0; i <= hl-nl; i++)
        if (_strnicmp(hay+i, needle, nl) == 0) return true;
    return false;
}

/* Extract scheme+host from URL */
static void get_scope_host(const char *url, char *out, size_t sz) {
    out[0] = '\0';
    const char *hs = strstr(url, "://");
    if (!hs) return;
    hs += 3;
    size_t i = 0;
    while (hs[i] && hs[i] != '/' && hs[i] != ':' && hs[i] != '?' && i < sz-1) {
        out[i] = hs[i]; i++; }
    out[i] = '\0';
    /* strip www. */
    if (strncmp(out, "www.", 4) == 0)
        memmove(out, out+4, strlen(out+4)+1);
}

/* ══════════════════════════════════════════════════════════
 * LINK EXTRACTOR
 * ══════════════════════════════════════════════════════════ */
#define MAX_LINKS_PER_PAGE 512

static int extract_links(const char *page_url, const char *html,
                           char out[][MAX_URL], int max_out,
                           const char *scope_host) {
    if (!html || !*html) return 0;
    int n = 0;

    /* We look for href=, src=, action= attributes */
    const char *attrs[] = {"href=", "src=", "action=", NULL};

    for (int ai = 0; attrs[ai] && n < max_out; ai++) {
        const char *p = html;
        size_t alen = strlen(attrs[ai]);

        while (n < max_out) {
            /* Find attribute (case-insensitive) */
            const char *found = NULL;
            for (const char *q = p; *q; q++) {
                if (_strnicmp(q, attrs[ai], alen) == 0) { found = q; break; }
            }
            if (!found) break;
            p = found + alen;

            /* skip whitespace */
            while (*p == ' ' || *p == '\t') p++;

            char q = (*p == '"' || *p == '\'') ? *p++ : 0;
            char href[MAX_URL] = {0};
            size_t i = 0;
            while (*p && i < MAX_URL-1) {
                if (q  && *p == q)  break;
                if (!q && (*p==' '||*p=='>'||*p=='\r'||*p=='\n'||*p=='\t')) break;
                href[i++] = *p++;
            }

            /* Clean up */
            char *fr = strchr(href, '#'); if (fr) *fr = '\0';
            if (!href[0] || href[0] == '#') continue;
            if (_strnicmp(href, "mailto:",    7) == 0) continue;
            if (_strnicmp(href, "javascript:",11) == 0) continue;
            if (_strnicmp(href, "data:",       5) == 0) continue;
            if (_strnicmp(href, "tel:",         4) == 0) continue;
            if (_strnicmp(href, "ftp:",         4) == 0) continue;

            /* Resolve to absolute URL */
            char resolved[MAX_URL] = {0};
            if (_strnicmp(href, "http://", 7) == 0 ||
                _strnicmp(href, "https://",8) == 0) {
                snprintf(resolved, MAX_URL, "%s", href);
            } else if (strncmp(href, "//", 2) == 0) {
                /* protocol-relative */
                const char *scheme_end = strstr(page_url, "://");
                char scheme[8] = "https";
                if (scheme_end) {
                    size_t sl = (size_t)(scheme_end - page_url);
                    if (sl < 8) { memcpy(scheme, page_url, sl); scheme[sl]='\0'; }
                }
                snprintf(resolved, MAX_URL, "%s:%s", scheme, href);
            } else if (href[0] == '/') {
                /* absolute path */
                const char *hs = strstr(page_url, "://");
                if (hs) {
                    hs += 3;
                    const char *ps = strchr(hs, '/');
                    size_t origin_len = ps ? (size_t)(ps - page_url) : strlen(page_url);
                    if (origin_len < MAX_URL) {
                        memcpy(resolved, page_url, origin_len);
                        resolved[origin_len] = '\0';
                        strncat(resolved, href, MAX_URL - strlen(resolved) - 1);
                    }
                }
            } else {
                /* relative path */
                snprintf(resolved, MAX_URL, "%s", page_url);
                char *last_slash = strrchr(resolved, '/');
                if (last_slash && last_slash > resolved + 8)
                    *(last_slash+1) = '\0';
                else
                    strncat(resolved, "/", MAX_URL-strlen(resolved)-1);
                strncat(resolved, href, MAX_URL - strlen(resolved) - 1);
            }
            if (!resolved[0]) continue;

            /* Scope check: resolved host must end with scope_host */
            char rhost[256] = {0};
            get_scope_host(resolved, rhost, sizeof(rhost));
            if (!rhost[0]) continue;

            bool in_scope;
            if (!scope_host || !scope_host[0]) {
                in_scope = true;
            } else {
                size_t rl = strlen(rhost), sl = strlen(scope_host);
                in_scope = (rl >= sl) &&
                           (strcmp(rhost + rl - sl, scope_host) == 0) &&
                           (rl == sl || rhost[rl-sl-1] == '.');
                if (!in_scope) in_scope = (strcmp(rhost, scope_host) == 0);
            }
            if (!in_scope) continue;

            /* Skip static assets */
            const char *ext = strrchr(resolved, '.');
            if (ext && (
                _stricmp(ext,".css")==0 || _stricmp(ext,".js")==0  ||
                _stricmp(ext,".png")==0 || _stricmp(ext,".jpg")==0 ||
                _stricmp(ext,".gif")==0 || _stricmp(ext,".svg")==0 ||
                _stricmp(ext,".ico")==0 || _stricmp(ext,".woff")==0||
                _stricmp(ext,".woff2")==0|| _stricmp(ext,".ttf")==0||
                _stricmp(ext,".pdf")==0 || _stricmp(ext,".zip")==0)) continue;

            /* Dedup */
            bool dup = false;
            for (int d = 0; d < n; d++)
                if (strcmp(out[d], resolved) == 0) { dup = true; break; }
            if (!dup) snprintf(out[n++], MAX_URL, "%s", resolved);
        }
    }
    return n;
}

/* ══════════════════════════════════════════════════════════
 * FORM EXTRACTOR
 * ══════════════════════════════════════════════════════════ */
typedef struct {
    char url[MAX_URL];
    int  method;      /* 0=GET, 1=POST */
    char params[16][64];
    int  param_count;
} SimpleForm;

static int extract_forms(const char *page_url, const char *html,
                           SimpleForm *forms, int max_f) {
    if (!html || !*html) return 0;
    int n = 0;
    const char *p = html;

    while (n < max_f) {
        /* find <form */
        const char *fs = NULL;
        for (const char *q = p; *q; q++) {
            if (_strnicmp(q, "<form", 5) == 0 &&
                (q[5]==' '||q[5]=='>'||q[5]=='\n'||q[5]=='\r'||q[5]=='\t')) {
                fs = q; break;
            }
        }
        if (!fs) break;

        SimpleForm *f = &forms[n];
        f->method = 0;
        snprintf(f->url, MAX_URL, "%s", page_url);

        /* find end of opening <form ...> tag */
        const char *te = fs+5;
        while (*te && *te != '>') te++;
        if (!*te) { p = fs+1; continue; }

        /* parse method= */
        for (const char *q = fs; q < te; q++) {
            if (_strnicmp(q, "method=", 7) == 0) {
                q += 7;
                char qch = (*q=='"'||*q=='\'') ? *q++ : 0;
                char mv[16]={0}; size_t mi=0;
                while(*q && mi<15 && (qch?*q!=qch:*q!=' '&&*q!='>'&&*q!='\r'))
                    mv[mi++]=*q++;
                if (_stricmp(mv,"post")==0) f->method=1;
                break;
            }
        }

        /* parse action= */
        for (const char *q = fs; q < te; q++) {
            if (_strnicmp(q, "action=", 7) == 0) {
                q += 7;
                char qch = (*q=='"'||*q=='\'') ? *q++ : 0;
                char av[MAX_URL]={0}; size_t ai2=0;
                while(*q && ai2<MAX_URL-1 && (qch?*q!=qch:*q!=' '&&*q!='>'&&*q!='\r'))
                    av[ai2++]=*q++;
                if (av[0]) {
                    /* resolve */
                    if (_strnicmp(av,"http",4)==0)
                        snprintf(f->url, MAX_URL, "%s", av);
                    else if (av[0]=='/') {
                        const char *hs=strstr(page_url,"://");
                        char origin[MAX_URL]={0};
                        if(hs){hs+=3;const char *ps=strchr(hs,'/');
                            size_t ol=ps?(size_t)(ps-page_url):strlen(page_url);
                            if(ol<MAX_URL){memcpy(origin,page_url,ol);origin[ol]='\0';}}
                        snprintf(f->url,MAX_URL,"%s%s",origin,av);
                    }
                }
                break;
            }
        }

        /* find </form> */
        const char *fe = NULL;
        for (const char *q = te; *q; q++) {
            if (_strnicmp(q,"</form>",7)==0) { fe=q; break; }
        }
        if (!fe) fe = html + strlen(html);

        /* extract input/textarea/select names */
        const char *ip = te+1;
        while (ip < fe && f->param_count < 16) {
            const char *inp = NULL;
            for (const char *q=ip; q<fe; q++) {
                if (_strnicmp(q,"<input",6)==0||
                    _strnicmp(q,"<textarea",9)==0||
                    _strnicmp(q,"<select",7)==0)
                { inp=q; break; }
            }
            if (!inp) break;
            const char *iend = strchr(inp, '>');
            if (!iend || iend > fe) { ip=inp+1; continue; }

            /* skip submit/button/hidden */
            char type_val[32]={0};
            for(const char *q=inp;q<iend;q++) {
                if(_strnicmp(q,"type=",5)==0) {
                    q+=5; char qc=(*q=='"'||*q=='\'')?*q++:0;
                    size_t ti=0;
                    while(*q&&ti<31&&(qc?*q!=qc:*q!=' '&&*q!='>'&&*q!='\r'))
                        type_val[ti++]=*q++;
                    break;
                }
            }
            if(_stricmp(type_val,"submit")==0||_stricmp(type_val,"button")==0||
               _stricmp(type_val,"hidden")==0||_stricmp(type_val,"reset")==0||
               _stricmp(type_val,"image")==0)
            { ip=inp+1; continue; }

            /* get name= */
            char name_val[64]={0};
            for(const char *q=inp;q<iend;q++) {
                if(_strnicmp(q,"name=",5)==0) {
                    q+=5; char qc=(*q=='"'||*q=='\'')?*q++:0;
                    size_t ni=0;
                    while(*q&&ni<63&&(qc?*q!=qc:*q!=' '&&*q!='>'&&*q!='\r'))
                        name_val[ni++]=*q++;
                    break;
                }
            }
            if (name_val[0])
                snprintf(f->params[f->param_count++], 64, "%s", name_val);
            ip = iend+1;
        }

        if (f->param_count > 0) n++;
        p = fe+1;
    }
    return n;
}

/* ══════════════════════════════════════════════════════════
 * ATTACK MODULES (use encrypted payloads)
 * ══════════════════════════════════════════════════════════ */
static size_t px_len(const unsigned char *e) {
    size_t l=0; while(e[l]) l++; return l;
}

static bool probe_reflect(ScanParams *p, const char *url, const char *param) {
    size_t pl = px_len(_px_probe_0);
    char *probe = px_dec(_px_probe_0, pl);
    char turl[MAX_URL*2]={0};
    build_url(turl, sizeof(turl), url, param, probe);
    WinResp *r = whttp_get(p, turl);
    bool ok = r && r->body && r->status>=200 && r->status<400
              && strstr(r->body, probe);
    wfree(r); free(probe);
    return ok;
}

static bool test_xss(ScanParams *p, const char *url,
                      const char *param, int pi) {
    size_t pl = px_len(_px_xss_arr[pi]);
    char *payload = px_dec(_px_xss_arr[pi], pl);
    char turl[MAX_URL*2]={0};
    build_url(turl, sizeof(turl), url, param, payload);
    WinResp *r = whttp_get(p, turl);
    bool found = false;
    if (r && r->body && r->status>=200 && r->status<400) {
        for (int m=0; _px_xss_markers_arr[m] && !found; m++) {
            size_t ml = px_len(_px_xss_markers_arr[m]);
            char *mark = px_dec(_px_xss_markers_arr[m], ml);
            if (icontains(r->body, mark)) found = true;
            free(mark);
        }
    }
    if (found) {
        tlogf(p, RGB(255,60,60), "  [XSS] %s param=%s", url, param);
        report_vuln(p,4,"xss","Cross-Site Scripting (XSS)",
                    url, param, payload, "Payload reflected unescaped");
    }
    free(payload); wfree(r);
    return found;
}

static bool test_sqli(ScanParams *p, const char *url,
                       const char *param, int pi) {
    size_t pl = px_len(_px_sqli_arr[pi]);
    char *payload = px_dec(_px_sqli_arr[pi], pl);
    char turl[MAX_URL*2]={0};
    build_url(turl, sizeof(turl), url, param, payload);
    WinResp *r = whttp_get(p, turl);
    bool found = false;
    if (r && r->body && r->status>=200 && r->status<400) {
        for (int e=0; _px_sqli_errors_arr[e] && !found; e++) {
            size_t el = px_len(_px_sqli_errors_arr[e]);
            char *err = px_dec(_px_sqli_errors_arr[e], el);
            if (icontains(r->body, err)) found = true;
            free(err);
        }
    }
    if (found) {
        tlogf(p, RGB(255,60,60), "  [SQLi] %s param=%s", url, param);
        report_vuln(p,5,"sqli","SQL Injection",
                    url, param, payload, "Database error in response");
    }
    free(payload); wfree(r);
    return found;
}

static bool test_lfi(ScanParams *p, const char *url,
                      const char *param, int pi) {
    size_t pl = px_len(_px_lfi_arr[pi]);
    char *payload = px_dec(_px_lfi_arr[pi], pl);
    char turl[MAX_URL*2]={0};
    build_url(turl, sizeof(turl), url, param, payload);
    WinResp *r = whttp_get(p, turl);
    bool found = false;
    if (r && r->body) {
        for (int m=0; _px_lfi_markers_arr[m] && !found; m++) {
            size_t ml = px_len(_px_lfi_markers_arr[m]);
            char *mark = px_dec(_px_lfi_markers_arr[m], ml);
            if (strstr(r->body, mark)) found = true;
            free(mark);
        }
    }
    if (found) {
        tlogf(p, RGB(255,60,60), "  [LFI] %s param=%s", url, param);
        report_vuln(p,5,"lfi","Local File Inclusion",
                    url, param, payload, "File content in response");
    }
    free(payload); wfree(r);
    return found;
}

static bool test_rce(ScanParams *p, const char *url,
                      const char *param) {
    /* RCE payloads: command injection */
    const char *payloads[] = {"; id", "| id", "`id`", "$(id)", "; whoami", NULL};
    const char *markers[]  = {"uid=", "root", "www-data", "daemon", NULL};
    for (int pi = 0; payloads[pi] && !p->stop_requested; pi++) {
        char turl[MAX_URL*2] = {0};
        build_url(turl, sizeof(turl), url, param, payloads[pi]);
        WinResp *r = whttp_get(p, turl);
        if (r && r->body) {
            for (int m = 0; markers[m]; m++) {
                if (icontains(r->body, markers[m])) {
                    tlogf(p, RGB(255,60,60), "  [RCE] %s param=%s", url, param);
                    report_vuln(p,5,"rce","Remote Code Execution",
                                url, param, payloads[pi], markers[m]);
                    wfree(r); return true;
                }
            }
        }
        wfree(r);
    }
    return false;
}

static bool test_ssrf(ScanParams *p, const char *url,
                       const char *param) {
    /* SSRF: probe internal addresses */
    const char *targets[] = {
        "http://127.0.0.1/",
        "http://169.254.169.254/",  /* AWS metadata */
        "http://192.168.1.1/",
        NULL
    };
    for (int ti = 0; targets[ti] && !p->stop_requested; ti++) {
        char turl[MAX_URL*2] = {0};
        build_url(turl, sizeof(turl), url, param, targets[ti]);
        WinResp *r = whttp_get(p, turl);
        if (r && r->status >= 200 && r->status < 500 && r->body && r->len > 0) {
            /* Any non-error response to internal addr suggests SSRF */
            tlogf(p, RGB(255,160,0), "  [SSRF] %s param=%s → %s",
                  url, param, targets[ti]);
            report_vuln(p,4,"ssrf","Server-Side Request Forgery",
                        url, param, targets[ti], "Internal address responded");
            wfree(r); return true;
        }
        wfree(r);
    }
    return false;
}

/* ══════════════════════════════════════════════════════════
 * MAIN SCAN THREAD
 * ══════════════════════════════════════════════════════════ */
#define MAX_Q    1024
#define MAX_PAGES 512
#define MAX_FORMS_W 512

DWORD WINAPI scan_thread(LPVOID arg) {
    ScanParams *p = (ScanParams *)arg;

    /* Derive scope host from target URL */
    char scope_host[256] = {0};
    get_scope_host(p->url, scope_host, sizeof(scope_host));

    tlogf(p, RGB(100,220,100),
          "Starting: %s  depth:%d  rate:%d/s  scope:%s",
          p->url, p->depth, p->rate, p->scope);

    /* ── Allocate crawl structures ── */
    char  (*queue)[MAX_URL] = calloc(MAX_Q,    MAX_URL);
    bool   *in_queue        = calloc(MAX_Q,    sizeof(bool));
    char  (*pages)[MAX_URL] = calloc(MAX_PAGES,MAX_URL);
    SimpleForm *forms       = calloc(MAX_FORMS_W, sizeof(SimpleForm));
    int   *queue_depth      = calloc(MAX_Q,    sizeof(int));

    if (!queue || !pages || !forms || !in_queue || !queue_depth) {
        tlog(p, "ERROR: out of memory", RGB(255,0,0));
        goto done;
    }

    /* Seed queue */
    int head = 0, tail = 0;
    snprintf(queue[tail], MAX_URL, "%s", p->url);
    queue_depth[tail] = 0;
    tail++;

    int page_count = 0, form_count = 0;
    int rate_ms = (p->rate > 0) ? (1000 / p->rate) : 50;

    tlog(p, "[Crawl] Discovering pages...", RGB(100,200,255));

    while (head != tail && page_count < MAX_PAGES && !p->stop_requested) {
        char  cur[MAX_URL];
        int   cur_depth;
        snprintf(cur, MAX_URL, "%s", queue[head]);
        cur_depth = queue_depth[head];
        head = (head + 1) % MAX_Q;

        /* rate limit */
        Sleep(rate_ms);

        WinResp *resp = whttp_get(p, cur);
        if (!resp) { continue; }

        set_progress(p, page_count * 40 / (p->depth * 30 + 1));

        if (resp->status < 200 || resp->status >= 400) {
            char hint[80] = "";
            if (resp->status == 403) strncpy(hint," (403 Forbidden - bot protection)",79);
            else if (resp->status == 429) strncpy(hint," (429 Rate Limited - slow down)",79);
            else if (resp->status == 401) strncpy(hint," (401 - set cookies)",79);
            tlogf(p, RGB(200,100,100), "  HTTP %ld%s: %s",
                  resp->status, hint, cur);
            wfree(resp);
            continue;
        }

        bool is_html = resp->body && (
            resp->content_type[0] == '\0' ||
            icontains(resp->content_type, "html") ||
            icontains(resp->content_type, "xhtml"));

        if (!is_html || !resp->body || resp->len == 0) {
            wfree(resp);
            continue;
        }

        /* Record page */
        snprintf(pages[page_count++], MAX_URL, "%s", cur);
        tlogf(p, RGB(140,220,140), "  ✓ [%d] %s  (%zu bytes)",
              page_count, cur, resp->len);

        /* Extract forms */
        int old_fc = form_count;
        form_count += extract_forms(cur, resp->body,
                                     forms + form_count,
                                     MAX_FORMS_W - form_count);
        if (form_count > old_fc)
            tlogf(p, RGB(140,160,240), "    +%d form(s)", form_count - old_fc);

        /* Extract links if depth allows */
        if (cur_depth < p->depth) {
            char (*links)[MAX_URL] = calloc(MAX_LINKS_PER_PAGE, MAX_URL);
            if (links) {
                int nl = extract_links(cur, resp->body, links,
                                        MAX_LINKS_PER_PAGE, scope_host);
                int enq = 0;
                for (int i = 0; i < nl; i++) {
                    /* Dedup: check entire queue */
                    bool seen = false;
                    int qi = head;
                    while (qi != tail) {
                        if (strcmp(queue[qi], links[i]) == 0) { seen=true; break; }
                        qi = (qi+1) % MAX_Q;
                    }
                    /* Also check already-processed pages */
                    if (!seen)
                        for (int pj=0; pj<page_count; pj++)
                            if (strcmp(pages[pj], links[i])==0) { seen=true; break; }

                    if (!seen) {
                        int next_tail = (tail+1) % MAX_Q;
                        if (next_tail != head) { /* queue not full */
                            snprintf(queue[tail], MAX_URL, "%s", links[i]);
                            queue_depth[tail] = cur_depth + 1;
                            tail = next_tail;
                            enq++;
                        }
                    }
                }
                if (nl > 0)
                    tlogf(p, RGB(120,140,200),
                          "    %d links found, %d queued (depth %d→%d)",
                          nl, enq, cur_depth, cur_depth+1);
                free(links);
            }
        }
        wfree(resp);
    }

    tlogf(p, RGB(100,220,100),
          "[Crawl] Done. Pages: %d  Forms: %d", page_count, form_count);

    if (page_count == 0) {
        tlog(p, "  ⚠ Zero pages crawled.", RGB(255,160,0));
        tlog(p, "  Try: adjust User-Agent, add Cookies, check URL.", RGB(255,200,100));
    }

    /* ── Add URL query params as attack surfaces ── */
    for (int pi = 0; pi < page_count && form_count < MAX_FORMS_W; pi++) {
        const char *qs = strchr(pages[pi], '?');
        if (!qs) continue;
        SimpleForm *f = &forms[form_count];
        f->method = 0;
        size_t bl = (size_t)(qs - pages[pi]);
        if (bl >= MAX_URL) bl = MAX_URL-1;
        memcpy(f->url, pages[pi], bl); f->url[bl] = '\0';
        char qcopy[MAX_URL]={0}; snprintf(qcopy, MAX_URL, "%s", qs+1);
        char *tok = strtok(qcopy, "&");
        while (tok && f->param_count < 16) {
            char *eq = strchr(tok,'=');
            size_t nl = eq ? (size_t)(eq-tok) : strlen(tok);
            if (nl > 0 && nl < 64) {
                memcpy(f->params[f->param_count], tok, nl);
                f->param_count++;
            }
            tok = strtok(NULL, "&");
        }
        if (f->param_count > 0) {
            tlogf(p, RGB(120,140,200), "  [URL params] %s (%d params)",
                  f->url, f->param_count);
            form_count++;
        }
    }

    /* ── Common params probe on pages with no forms ── */
    const char *cparams[] = {
        "id","q","s","search","query","page","cat","file",
        "path","url","redirect","lang","type","view","name", NULL
    };
    for (int pi = 0; pi < page_count && form_count < MAX_FORMS_W; pi++) {
        /* strip query from URL for dedup */
        char base_no_qs[MAX_URL]={0};
        const char *qs2 = strchr(pages[pi],'?');
        if (qs2) { size_t bl=(size_t)(qs2-pages[pi]); if(bl<MAX_URL){memcpy(base_no_qs,pages[pi],bl);base_no_qs[bl]='\0';} }
        else snprintf(base_no_qs, MAX_URL, "%s", pages[pi]);

        /* check if we already have a form for this base URL */
        bool has = false;
        for (int fi=0; fi<form_count; fi++)
            if (strcmp(forms[fi].url, base_no_qs)==0) { has=true; break; }
        if (has) continue;

        SimpleForm *f = &forms[form_count];
        f->method = 0;
        snprintf(f->url, MAX_URL, "%s", base_no_qs);
        for (int ci=0; cparams[ci] && f->param_count<8; ci++)
            snprintf(f->params[f->param_count++], 64, "%s", cparams[ci]);
        form_count++;
        tlogf(p, RGB(100,120,180), "  [Common] %s (%d params)",
              base_no_qs, f->param_count);
    }

    tlogf(p, RGB(100,200,255),
          "[Attack] %d forms, %d total attack surfaces",
          form_count, form_count);

    /* ── Attack phase ── */
    int mods_count = ((p->modules&0x01)?1:0) + ((p->modules&0x02)?1:0) +
                     ((p->modules&0x04)?1:0) + ((p->modules&0x08)?1:0) +
                     ((p->modules&0x10)?1:0);
    int total = form_count * mods_count;
    int job = 0;

#define UPD_PROG() set_progress(p, 40 + (++job)*55/(total > 0 ? total : 1))

    for (int fi = 0; fi < form_count && !p->stop_requested; fi++) {
        SimpleForm *f = &forms[fi];
        tlogf(p, RGB(130,130,200), "  Testing: %s [%s] (%d params)",
              f->url, f->method?"POST":"GET", f->param_count);

        for (int pi2 = 0; pi2 < f->param_count && !p->stop_requested; pi2++) {
            Sleep(rate_ms);
            const char *pm = f->params[pi2];

            if (p->modules & 0x01) { /* XSS */
                if (probe_reflect(p, f->url, pm))
                    for (int xi=0; xi<_px_xss_count && !p->stop_requested; xi++)
                        if (test_xss(p, f->url, pm, xi)) break;
                UPD_PROG();
            }
            if (p->modules & 0x02) { /* SQLi */
                for (int si=0; si<_px_sqli_count && !p->stop_requested; si++)
                    if (test_sqli(p, f->url, pm, si)) break;
                UPD_PROG();
            }
            if (p->modules & 0x04) { /* LFI */
                for (int li=0; li<_px_lfi_count && !p->stop_requested; li++)
                    if (test_lfi(p, f->url, pm, li)) break;
                UPD_PROG();
            }
            if (p->modules & 0x08) { /* RCE */
                test_rce(p, f->url, pm);
                UPD_PROG();
            }
            if (p->modules & 0x10) { /* SSRF */
                test_ssrf(p, f->url, pm);
                UPD_PROG();
            }
        }
    }
#undef UPD_PROG

done:
    set_progress(p, 100);
    tlog(p, "[Done]", RGB(100,220,100));

    free(queue); free(in_queue); free(pages);
    free(forms); free(queue_depth);

    PostMessage(p->hwnd, WM_SCAN_DONE, 0, 0);
    return 0;
}
