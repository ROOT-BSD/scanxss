/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 *
 * config.c — Parse scanxss.conf, send email reports via /usr/sbin/sendmail
 *            or curl SMTP (no external library required)
 */
#include "scanxss.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

/* ── Config defaults ─────────────────────────────────────── */
void config_init(ScanXSSConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    /* smtp_host empty = not configured, user must run --setup-email */
    cfg->smtp_port = 587;
    cfg->smtp_tls  = true;
    cfg->email_only_vulns   = true;
    cfg->email_attach_html  = true;
    cfg->email_enabled      = false;
    strncpy(cfg->email_subject,
            "[ScanXSS] Report: %h — %v vuln(s) found (%d)",
            sizeof(cfg->email_subject)-1);
}

/* ── Trim whitespace ─────────────────────────────────────── */
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)*(e-1))) *--e = '\0';
    return s;
}

/* ── Parse one KEY = VALUE line ──────────────────────────── */
static void parse_line(ScanXSSConfig *cfg, const char *line) {
    if (!line || line[0] == '#' || line[0] == '\0') return;

    char key[64]={0}, val[512]={0};
    const char *eq = strchr(line, '=');
    if (!eq) return;

    size_t klen = (size_t)(eq - line);
    if (klen >= sizeof(key)) return;
    memcpy(key, line, klen);
    strncpy(val, eq+1, sizeof(val)-1);

    char *k = trim(key);
    char *v = trim(val);

    #define SSET(field) strncpy(cfg->field, v, sizeof(cfg->field)-1)
    #define BSET(field) cfg->field = (strcmp(v,"true")==0||strcmp(v,"1")==0)
    #define ISET(field) cfg->field = atoi(v)

    if      (!strcmp(k,"email_enabled"))    BSET(email_enabled);
    else if (!strcmp(k,"smtp_host"))        SSET(smtp_host);
    else if (!strcmp(k,"smtp_port"))        ISET(smtp_port);
    else if (!strcmp(k,"smtp_tls"))         BSET(smtp_tls);
    else if (!strcmp(k,"smtp_user"))        SSET(smtp_user);
    else if (!strcmp(k,"smtp_pass"))        SSET(smtp_pass);
    else if (!strcmp(k,"email_to"))         SSET(email_to);
    else if (!strcmp(k,"email_from"))       SSET(email_from);
    else if (!strcmp(k,"email_subject"))    SSET(email_subject);
    else if (!strcmp(k,"email_only_vulns")) BSET(email_only_vulns);
    else if (!strcmp(k,"email_attach_html"))BSET(email_attach_html);
    else if (!strcmp(k,"default_depth"))    ISET(default_depth);
    else if (!strcmp(k,"default_rate"))     ISET(default_rate);
    else if (!strcmp(k,"default_timeout"))  ISET(default_timeout);
    else if (!strcmp(k,"default_scope"))    SSET(default_scope);
    else if (!strcmp(k,"default_modules"))  SSET(default_modules);
    else if (!strcmp(k,"report_dir"))       SSET(report_dir_override);
    #undef SSET
    #undef BSET
    #undef ISET
}

/* ── Load config from file ───────────────────────────────── */
static int load_file(ScanXSSConfig *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    int keys_found = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        /* Count non-comment, non-empty lines with = */
        char *eq = strchr(line, '=');
        if (eq && line[0] != '#') keys_found++;
        parse_line(cfg, line);
    }
    fclose(f);
    /* Return 0 (found) only if file had actual config keys */
    return keys_found > 0 ? 0 : -1;
}

/* ── Search config in standard locations ─────────────────── */
int config_load(ScanXSSConfig *cfg) {
    config_init(cfg);

    /* 1. Current directory */
    if (load_file(cfg, "scanxss.conf") == 0) return 0;

    /* 2. User home */
    const char *home = getenv("HOME");
    if (home) {
        char path[512];
        snprintf(path, sizeof(path), "%s/.scanxss/scanxss.conf", home);
        if (load_file(cfg, path) == 0) return 0;
    }

    /* 3. System-wide */
    if (load_file(cfg, "/etc/scanxss/scanxss.conf") == 0) return 0;

    return 1; /* no config found — use defaults */
}

