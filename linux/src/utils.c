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
#include <ctype.h>
#include <stdarg.h>

/* ── URL encode ───────────────────────────────────────────── */
char *url_encode(const char *s) {
    if (!s) return strdup("");
    size_t len = strlen(s);
    char  *out = malloc(len * 3 + 1);
    char  *p   = out;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c=='-' || c=='_' || c=='.' || c=='~') *p++ = c;
        else p += sprintf(p, "%%%02X", c);
    }
    *p = '\0';
    return out;
}

/* ── str_replace (first occurrence) ──────────────────────── */
char *str_replace(const char *src, const char *from, const char *to) {
    const char *pos = strstr(src, from);
    if (!pos) return strdup(src);
    size_t flen = strlen(from), tlen = strlen(to);
    char *out = malloc(strlen(src) - flen + tlen + 1);
    size_t before = (size_t)(pos - src);
    memcpy(out, src, before);
    memcpy(out + before, to, tlen);
    strcpy(out + before + tlen, pos + flen);
    return out;
}

/* ── case-insensitive substring ───────────────────────────── */
bool str_contains_icase(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;
    size_t hl = strlen(haystack), nl = strlen(needle);
    if (nl > hl) return false;
    for (size_t i = 0; i <= hl - nl; i++)
        if (strncasecmp(haystack + i, needle, nl) == 0) return true;
    return false;
}

/* ── extract host (no port) from URL ─────────────────────── */
static void extract_host(const char *url, char *host, size_t hsz) {
    host[0] = '\0';
    const char *p = strstr(url, "://");
    if (!p) { strncpy(host, url, hsz-1); return; }
    p += 3;
    size_t i = 0;
    while (*p && *p != '/' && *p != '?' && *p != '#' && i < hsz-1) {
        /* strip port */
        if (*p == ':') break;
        host[i++] = *p++;
    }
    host[i] = '\0';
}

/* ── extract base domain (last two labels, handles .gov.ua etc.) ──
 * Examples:
 *   www.nerc.gov.ua  → gov.ua  (3-label ccTLD)  NO — use 2nd-level
 *   nerc.gov.ua      → nerc.gov.ua
 *   sub.nerc.gov.ua  → nerc.gov.ua
 *   example.com      → example.com
 *   sub.example.com  → example.com
 *
 * Rule: keep everything from the last occurrence of a label that has
 *       >= 3 chars AND the remaining suffix has <= 2 labels.
 *       Simple heuristic: strip leading "www." only, then compare hosts.
 * ─────────────────────────────────────────────────────────────── */
static void extract_base_domain(const char *host, char *base, size_t bsz) {
    /* strip leading www. */
    const char *h = host;
    if (strncasecmp(h, "www.", 4) == 0) h += 4;

    /* Count dots */
    int dots = 0;
    for (const char *p = h; *p; p++) if (*p == '.') dots++;

    if (dots <= 1) {
        /* already base: example.com, localhost */
        strncpy(base, h, bsz-1);
        return;
    }

    /* For >2 dots: check if it's a known 3-part TLD (.gov.ua, .co.uk, .com.au)
     * Simple check: if last two labels are both <= 3 chars, keep 3 labels */
    const char *last_dot  = strrchr(h, '.');
    const char *second_dot = NULL;
    if (last_dot) {
        /* find dot before last */
        for (const char *p = h; p < last_dot; p++)
            if (*p == '.') second_dot = p;
    }

    size_t last_label_len   = last_dot  ? strlen(last_dot + 1)   : 0;
    size_t second_label_len = second_dot && last_dot
                              ? (size_t)(last_dot - second_dot - 1) : 0;

    int keep_three = (last_label_len <= 3 && second_label_len <= 4 && dots >= 2);

    /* find the dot that separates host prefix from base */
    const char *split = h;
    if (keep_three && second_dot) {
        /* keep 3 labels: find dot before second_dot */
        for (const char *p = h; p < second_dot; p++)
            if (*p == '.') split = p + 1;
        if (split == h) split = h; /* only 3 labels total */
    } else if (!keep_three && last_dot) {
        /* keep 2 labels: use second_dot as split */
        split = second_dot ? second_dot + 1 : h;
    }
    strncpy(base, split, bsz-1);
}

/* ── url_in_scope ─────────────────────────────────────────── */
bool url_in_scope(const char *base_url, const char *url, const char *scope) {
    if (!base_url || !url) return false;
    if (!url[0] || url[0] == '#') return false;

    /* skip obviously non-HTTP */
    if (strncmp(url, "mailto:", 7) == 0) return false;
    if (strncmp(url, "javascript:", 11) == 0) return false;
    if (strncmp(url, "data:", 5) == 0) return false;
    if (strncmp(url, "tel:", 4) == 0) return false;

    if (strcmp(scope, "url") == 0)
        return strcmp(base_url, url) == 0;

    if (strcmp(scope, "page") == 0)
        return strncmp(base_url, url, strlen(base_url)) == 0;

    char bhost[256]={0}, uhost[256]={0};
    extract_host(base_url, bhost, sizeof(bhost));
    extract_host(url,      uhost, sizeof(uhost));

    if (strcmp(scope, "domain") == 0) {
        /* exact host match (ignoring www. prefix on both sides) */
        char bh[256]={0}, uh[256]={0};
        const char *b = bhost; if (strncasecmp(b,"www.",4)==0) b+=4;
        const char *u = uhost; if (strncasecmp(u,"www.",4)==0) u+=4;
        strncpy(bh, b, 255); strncpy(uh, u, 255);
        return strcasecmp(bh, uh) == 0;
    }

    if (strcmp(scope, "subdomain") == 0) {
        /* allow any subdomain of the base domain */
        char bbase[256]={0}, ubase[256]={0};
        extract_base_domain(bhost, bbase, sizeof(bbase));
        extract_base_domain(uhost, ubase, sizeof(ubase));
        return strcasecmp(bbase, ubase) == 0;
    }

    /* default: folder scope */
    char bfolder[MAX_URL_LEN] = {0};
    strncpy(bfolder, base_url, sizeof(bfolder)-1);
    char *last = strrchr(bfolder, '/');
    if (last && last > bfolder + 8) *(last+1) = '\0';
    return strncmp(bfolder, url, strlen(bfolder)) == 0;
}

/* ── Logging ──────────────────────────────────────────────── */
void log_info(int verbose, int color, const char *fmt, ...) {
    if (!verbose) return;
    va_list ap; va_start(ap, fmt);
    if (color) fprintf(stdout, COL_CYAN "[*] " COL_RESET);
    else       fprintf(stdout, "[*] ");
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    va_end(ap);
}

void log_vuln(int color, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    if (color) fprintf(stdout, COL_RED "[!] " COL_RESET);
    else       fprintf(stdout, "[!] ");
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    va_end(ap);
}

void log_warn(int color, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    if (color) fprintf(stdout, COL_YELLOW "[~] " COL_RESET);
    else       fprintf(stdout, "[~] ");
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    va_end(ap);
}

/* ── html_strip ───────────────────────────────────────────── */
char *html_strip(const char *html) {
    if (!html) return strdup("");
    char *out = malloc(strlen(html)+1);
    const char *p = html; char *q = out; int in_tag = 0;
    while (*p) {
        if (*p == '<') in_tag = 1;
        else if (*p == '>') { in_tag = 0; }
        else if (!in_tag) *q++ = *p;
        p++;
    }
    *q = '\0';
    return out;
}

/* ── base_url: up to and including last '/' ───────────────── */
char *base_url(const char *url) {
    char *copy = strdup(url);
    char *hs = strstr(copy, "://");
    if (!hs) { free(copy); return strdup(url); }
    char *ps = strchr(hs+3, '/');
    if (!ps) { free(copy); return strdup(url); }
    char *last = strrchr(ps, '/');
    if (last) *(last+1) = '\0';
    char *r = strdup(copy); free(copy); return r;
}

/* ── resolve_url ──────────────────────────────────────────── */
char *resolve_url(const char *base, const char *href) {
    if (!href || !href[0]) return strdup(base);
    if (strncmp(href,"http://",7)==0 || strncmp(href,"https://",8)==0)
        return strdup(href);
    if (strncmp(href,"//",2)==0) {
        char scheme[16]="https"; sscanf(base,"%15[^:]",scheme);
        char *out = malloc(strlen(scheme)+strlen(href)+2);
        sprintf(out,"%s:%s",scheme,href); return out;
    }
    if (href[0]=='/') {
        char origin[MAX_URL_LEN]={0};
        const char *hs=strstr(base,"://");
        if (hs) { hs+=3; const char *ps=strchr(hs,'/');
            if (ps) { size_t n=ps-base; strncpy(origin,base,n); }
            else strncpy(origin,base,MAX_URL_LEN-1); }
        char *out=malloc(strlen(origin)+strlen(href)+1);
        sprintf(out,"%s%s",origin,href); return out;
    }
    char *bb = base_url(base);
    char *out = malloc(strlen(bb)+strlen(href)+1);
    sprintf(out,"%s%s",bb,href); free(bb); return out;
}
