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
#include <sys/stat.h>
#include <getopt.h>

static void print_banner(void) {
    printf(COL_CYAN
" ____                 __  ______ ____  ____\n"
"/\\  _`\\             /\\ \\/\\  ___/\\  _`\\/\\  _`\\\n"
"\\ \\ \\/\\ \\    ___   _\\_\\ \\ \\ \\__\\ \\ \\L\\ \\ \\L\\ \\\n"
" \\ \\ \\ \\ \\  / __`\\/\\`'__\\ \\  __\\\\ \\  _ <\\ \\ ,  /\n"
"  \\ \\ \\_\\ \\/\\ \\L\\ \\ \\ \\/ \\ \\ \\_/ \\ \\ \\L\\ \\ \\ \\\\ \\\n"
"   \\ \\____/\\ \\____/\\ \\_\\  \\ \\_\\   \\ \\____/\\ \\_\\ \\_\\\n"
"    \\/___/  \\/___/  \\/_/   \\/_/    \\/___/  \\/_/\\/ /\n"
COL_RESET
COL_BOLD
"\n"
"╔══════════════════════════════════════════════╗\n"
"║  ScanXSS v1.3.1.1 — Web Vulnerability Scanner  ║\n"
"║   © 2026 root_bsd <root_bsd@itprof.net.ua>   ║\n"
"║                   GPL-2.0                    ║\n"
"╚══════════════════════════════════════════════╝\n\n"
COL_RESET);
}

static void print_usage(const char *prog) {
    printf("Використання: %s -u URL [опції]\n\n", prog);
    printf("Обов'язково:\n"
           "  -u URL              Ціль сканування\n\n");
    printf("Режими сканування:\n"
           "  (без прапорів)      Повне сканування (crawl + всі модулі)\n"
           "  --resume            Продовжити перерване сканування\n"
           "  --rescan            Новий запуск атак на збережений crawl\n"
           "  --retarget          Перевірити тільки раніше знайдені вразливості\n"
           "  --rescan-from ID    Rescan від конкретного scan_id\n\n");
    printf("Параметри:\n"
           "  -d N                Глибина crawling (за замовч. 3)\n"
           "  -t N                Таймаут HTTP у секундах (за замовч. 10)\n"
           "  -l N                Макс. кількість URL (за замовч. 256)\n"
           "  -r N                Rate limit запитів/сек (за замовч. 10)\n"
           "  -m MODULES          xss,sqli,lfi,rce,ssrf,redirect,crlf\n"
           "  -s SCOPE            url|page|folder|domain\n\n");
    printf("Вивід:\n"
           "  -o FILE             Файл звіту\n"
           "  -f FORMAT           html|txt\n"
           "  -v                  Детальний вивід\n"
           "  --no-color          Без кольору\n\n");
    printf("База даних:\n"
           "  --db FILE           Шлях до SQLite-файлу\n"
           "  --session-dir DIR   Директорія для .db файлів\n"
           "  --list-scans        Показати список попередніх сканувань\n"
           "  --show-scan ID      Показати знахідки конкретного сканування\n"
           "  --delete-scan ID    Видалити сканування з БД\n"
           "  --wipe              Видалити ВСІ дані цілі з БД\n\n");
    printf("Мережа:\n"
           "  -p URL              Проксі\n"
           "  -c COOKIE           Cookies\n"
           "  -a USER_AGENT       User-Agent\n"
           "  --endpoint URL      SSRF callback\n\n");
    printf("Приклади:\n"
           "  %s -u http://site.com/ -f html -o rep.html\n"
           "  %s -u http://site.com/ --rescan -f html -o new.html\n"
           "  %s -u http://site.com/ --retarget\n"
           "  %s -u http://site.com/ --list-scans\n"
           "  %s -u http://site.com/ --wipe\n\n", prog,prog,prog,prog,prog);
}

static VulnType parse_modules(const char *s) {
    if (!s) return VULN_ALL;
    VulnType t = VULN_NONE;
    char buf[512]; strncpy(buf, s, 511);
    char *tok = strtok(buf, ",");
    while (tok) {
        if      (!strcmp(tok,"xss"))      t |= VULN_XSS;
        else if (!strcmp(tok,"sqli"))     t |= VULN_SQLI;
        else if (!strcmp(tok,"lfi"))      t |= VULN_LFI;
        else if (!strcmp(tok,"rce"))      t |= VULN_RCE;
        else if (!strcmp(tok,"ssrf"))     t |= VULN_SSRF;
        else if (!strcmp(tok,"redirect")) t |= VULN_OPEN_REDIR;
        else if (!strcmp(tok,"crlf"))     t |= VULN_CRLF;
        else fprintf(stderr, "Unknown module: %s\n", tok);
        tok = strtok(NULL, ",");
    }
    return t ? t : VULN_ALL;
}

static void print_summary(const ScanContext *ctx) {
    double elapsed = difftime(ctx->end_time, ctx->start_time);
    double rps = elapsed > 0 ? ctx->requests_made / elapsed : 0;
    printf("\n" COL_BOLD
           "╔══════════════════════════════════════╗\n"
           "║           ПІДСУМОК СКАНУВАННЯ        ║\n"
           "╚══════════════════════════════════════╝\n" COL_RESET);
    printf("  Ціль:         %s\n",  ctx->config.target_url);
    printf("  Scan ID:      #%lld\n", (long long)ctx->scan_id);
    printf("  Тривалість:   %.0f сек (%.1f req/s)\n", elapsed, rps);
    printf("  HTTP запитів: %d\n",  ctx->requests_made);
    printf("  URL:          %d\n",  ctx->crawl.url_count);
    printf("  Форм:         %d\n",  ctx->crawl.form_count);
    if (ctx->vuln_count == 0) {
        printf("  Вразливості:  " COL_GREEN "не знайдено\n" COL_RESET);
    } else {
        printf("  Вразливості:  " COL_RED "%d знайдено!\n" COL_RESET, ctx->vuln_count);
        int cnt[256] = {0};
        for (int i = 0; i < ctx->vuln_count; i++) cnt[(int)ctx->vulns[i].type]++;
        struct { VulnType t; const char *n; const char *c; } tbl[] = {
            {VULN_XSS,"XSS",COL_RED},{VULN_SQLI,"SQLi",COL_RED},
            {VULN_LFI,"LFI",COL_RED},{VULN_RCE,"RCE",COL_RED},
            {VULN_SSRF,"SSRF",COL_RED},{VULN_OPEN_REDIR,"Redirect",COL_YELLOW},
            {VULN_CRLF,"CRLF",COL_YELLOW},{0,NULL,NULL}
        };
        for (int i = 0; tbl[i].n; i++)
            if (cnt[(int)tbl[i].t])
                printf("    %s• %-12s %d\n" COL_RESET, tbl[i].c, tbl[i].n, cnt[(int)tbl[i].t]);
    }
    printf("\n");
}

/* ── Long options ─────────────────────────────────────────── */
enum {
    OPT_NO_COLOR=256, OPT_LIST_MODS, OPT_DB, OPT_SESSION_DIR, OPT_REPORT_DIR,
    OPT_RESUME, OPT_RESCAN, OPT_RETARGET, OPT_RESCAN_FROM,
    OPT_LIST_SCANS, OPT_SHOW_SCAN, OPT_DELETE_SCAN, OPT_WIPE, OPT_NO_BROWSER,
    OPT_ENDPOINT,
    OPT_SETUP_EMAIL,
    OPT_EMAIL_HISTORY,
};
static struct option long_opts[] = {
    {"url",          required_argument,0,'u'},
    {"depth",        required_argument,0,'d'},
    {"timeout",      required_argument,0,'t'},
    {"max-links",    required_argument,0,'l'},
    {"scope",        required_argument,0,'s'},
    {"rate",         required_argument,0,'r'},
    {"modules",      required_argument,0,'m'},
    {"output",       required_argument,0,'o'},
    {"format",       required_argument,0,'f'},
    {"verbose",      no_argument,      0,'v'},
    {"proxy",        required_argument,0,'p'},
    {"cookie",       required_argument,0,'c'},
    {"user-agent",   required_argument,0,'a'},
    {"no-color",     no_argument,      0,OPT_NO_COLOR},
    {"list-modules", no_argument,      0,OPT_LIST_MODS},
    {"db",           required_argument,0,OPT_DB},
    {"session-dir",  required_argument,0,OPT_SESSION_DIR},
    {"report-dir",   required_argument,0,OPT_REPORT_DIR},
    {"resume",       no_argument,      0,OPT_RESUME},
    {"rescan",       no_argument,      0,OPT_RESCAN},
    {"retarget",     no_argument,      0,OPT_RETARGET},
    {"rescan-from",  required_argument,0,OPT_RESCAN_FROM},
    {"list-scans",   no_argument,      0,OPT_LIST_SCANS},
    {"show-scan",    required_argument,0,OPT_SHOW_SCAN},
    {"delete-scan",  required_argument,0,OPT_DELETE_SCAN},
    {"wipe",         no_argument,      0,OPT_WIPE},
    {"no-browser",   no_argument,      0,OPT_NO_BROWSER},
    {"endpoint",     required_argument,0,OPT_ENDPOINT},
    {"setup-email",  no_argument,      0,OPT_SETUP_EMAIL},
    {"email-history",no_argument,     0,OPT_EMAIL_HISTORY},
    {"help",         no_argument,      0,'h'},
    {"version",      no_argument,      0,'V'},
    {0,0,0,0}
};

/* Forward declarations */
static void smtp_setup_wizard(ScanXSSConfig *cfg);
static void cmd_email_history(ScanContext *ctx, ScanXSSConfig *cfg);
static int generate_report_for_scan(ScanContext *ctx, int64_t scan_id,
    char *html_out, char *txt_out, size_t outsz);
static void interactive_email_menu(ScanXSSConfig *cfg,
    const char *html_path, const char *txt_path,
    const char *target_host, int vuln_count);

int main(int argc, char *argv[]) {
    ScanContext *ctx = calloc(1, sizeof(ScanContext));
    if (!ctx) { fprintf(stderr,"Out of memory\n"); return 1; }
    ScanConfig *cfg = &ctx->config;

    /* defaults */
    cfg->depth        = 3;
    cfg->timeout      = DEFAULT_TIMEOUT;
    cfg->modules      = VULN_ALL;
    cfg->color        = 1;
    cfg->max_links    = 256;
    cfg->follow_redirects = true;
    cfg->rate         = DEFAULT_RATE;
    cfg->scan_mode    = SCAN_MODE_FULL;
    strncpy(cfg->output_format,"html",15);
    strncpy(cfg->scope,"subdomain",31);

    /* parse CLI */
    int64_t show_scan_id = 0, delete_scan_id = 0;
    bool do_list = false, do_show = false, do_delete = false, do_wipe = false;

    /* Allow standalone commands without -u */
    bool _standalone = false;
    for (int _j=1;_j<argc;_j++) {
        if (strcmp(argv[_j],"--email-history")==0 ||
            strcmp(argv[_j],"--setup-email")==0 ||
            strcmp(argv[_j],"--list-modules")==0) { _standalone=true; break; }
    }
    if (argc < 2 && !_standalone) { print_banner(); print_usage(argv[0]); free(ctx); return 1; }
    int opt, idx=0;
    while ((opt=getopt_long(argc,argv,"u:d:t:l:s:r:m:o:f:vp:c:a:hV",
                            long_opts,&idx)) != -1) {
        switch (opt) {
        case 'u': strncpy(cfg->target_url,   optarg,MAX_URL_LEN-1); break;
        case 'd': cfg->depth      = atoi(optarg); break;
        case 't': cfg->timeout    = atoi(optarg); break;
        case 'l': cfg->max_links  = atoi(optarg); break;
        case 's': strncpy(cfg->scope,        optarg,31); break;
        case 'r': cfg->rate       = atoi(optarg); break;
        case 'm': cfg->modules    = parse_modules(optarg); break;
        case 'o': strncpy(cfg->output_file,  optarg,511); break;
        case 'f': strncpy(cfg->output_format,optarg,15); break;
        case 'v': cfg->verbose    = 1; break;
        case 'p': strncpy(cfg->proxy,        optarg,MAX_URL_LEN-1); break;
        case 'c': strncpy(cfg->cookies,      optarg,MAX_URL_LEN-1); break;
        case 'a': strncpy(cfg->user_agent,   optarg,255); break;
        case OPT_NO_COLOR:    cfg->color = 0; break;
        case OPT_LIST_MODS:
            printf("xss sqli lfi rce ssrf redirect crlf\n"); free(ctx); return 0;
        case OPT_DB:          strncpy(cfg->db_path,     optarg,511); break;
        case OPT_SESSION_DIR: strncpy(cfg->session_dir, optarg,511); break;
        case OPT_REPORT_DIR:  strncpy(cfg->report_dir,  optarg,511); break;
        case OPT_RESUME:   cfg->scan_mode = SCAN_MODE_RESUME;   break;
        case OPT_RESCAN:   cfg->scan_mode = SCAN_MODE_RESCAN;   break;
        case OPT_RETARGET: cfg->scan_mode = SCAN_MODE_RETARGET; break;
        case OPT_RESCAN_FROM:
            cfg->rescan_id = (int64_t)atoll(optarg);
            cfg->scan_mode = SCAN_MODE_RESCAN; break;
        case OPT_LIST_SCANS:  do_list   = true; break;
        case OPT_SHOW_SCAN:   do_show   = true; show_scan_id   = atoll(optarg); break;
        case OPT_DELETE_SCAN: do_delete = true; delete_scan_id = atoll(optarg); break;
        case OPT_WIPE:        do_wipe   = true; break;
        case OPT_NO_BROWSER:  /* handled below */ break;
        case OPT_ENDPOINT:    strncpy(cfg->endpoint,optarg,MAX_URL_LEN-1); break;
        case 'V': printf("%s %s\n",SCANXSS_NAME,SCANXSS_VERSION); free(ctx); return 0;
        case 'h': print_banner(); print_usage(argv[0]); free(ctx); return 0;
        case OPT_SETUP_EMAIL:   break; /* handled after getopt */
        case OPT_EMAIL_HISTORY: break; /* handled after getopt */
        default:  print_usage(argv[0]); free(ctx); return 1;
        }
    }

    if (!cfg->target_url[0] && !_standalone) {
        fprintf(stderr,"Error: specify target with -u URL\n"); free(ctx); return 1;
    }

    /* resolve binary location → default DB directory */
    db_set_exe_dir(ctx, argv[0]);

    /* open DB first for all operations */
    if (db_open(ctx) < 0) { free(ctx); return 1; }

    /* ── DB query commands (no scanning) ── */
    if (do_list)   { db_list_scans(ctx); db_close(ctx); free(ctx); return 0; }
    if (do_show)   { db_show_scan(ctx, show_scan_id); db_close(ctx); free(ctx); return 0; }
    if (do_delete) { db_flush_scan(ctx, delete_scan_id); db_close(ctx); free(ctx); return 0; }
    if (do_wipe)   {
        printf(COL_YELLOW "Wipe all data for %s? [y/N] " COL_RESET, cfg->target_url);
        char ans[8]={0}; if (fgets(ans,sizeof(ans),stdin) && (ans[0]=='y'||ans[0]=='Y'))
            db_flush_all(ctx);
        else printf("Cancelled.\n");
        db_close(ctx); free(ctx); return 0;
    }

    print_banner();

    /* Load config file */
    ScanXSSConfig email_cfg;
    config_load(&email_cfg);

    /* --setup-email: launch wizard and exit */
    for (int _i=1; _i<argc; _i++) {
        if (strcmp(argv[_i], "--setup-email") == 0) {
            smtp_setup_wizard(&email_cfg);
            free(ctx); return 0;
        }
        if (strcmp(argv[_i], "--email-history") == 0) {
            /* DB path uses target_url — set placeholder to open global DB */
            if (!cfg->target_url[0])
                strncpy(cfg->target_url, "scanxss://history",
                        MAX_URL_LEN-1);
            if (db_open(ctx) != 0) {
                fprintf(stderr, "Cannot open DB\n");
                free(ctx); return 1;
            }
            cmd_email_history(ctx, &email_cfg);
            db_close(ctx); free(ctx); return 0;
        }
    }

    /* Apply config defaults if not set by args */
    if (cfg->depth   == 0 && email_cfg.default_depth   > 0)
        cfg->depth   = email_cfg.default_depth;
    if (cfg->rate    == 0 && email_cfg.default_rate    > 0)
        cfg->rate    = email_cfg.default_rate;
    if (cfg->timeout == 0 && email_cfg.default_timeout > 0)
        cfg->timeout = email_cfg.default_timeout;
    if (!cfg->scope[0] && email_cfg.default_scope[0])
        strncpy(cfg->scope, email_cfg.default_scope, sizeof(cfg->scope)-1);
    if (!cfg->report_dir[0] && email_cfg.report_dir_override[0])
        strncpy(cfg->report_dir, email_cfg.report_dir_override, sizeof(cfg->report_dir)-1);
    printf(COL_CYAN "Target: %s\n" COL_RESET, cfg->target_url);
    const char *mode_name[] = {"FULL","RESUME","RESCAN","RETARGET"};
    printf("Mode:   %s%s%s  |  depth:%d  timeout:%ds  rate:%d/s\n",
           COL_BOLD, mode_name[cfg->scan_mode], COL_RESET,
           cfg->depth, cfg->timeout, cfg->rate);

    rate_init(&ctx->rate, cfg->rate);
    ctx->start_time = time(NULL);
    db_scan_begin(ctx);

    /* ── RETARGET: skip crawl entirely ── */
    if (cfg->scan_mode == SCAN_MODE_RETARGET) {
        int64_t prev = cfg->rescan_id > 0 ? cfg->rescan_id : 0;
        attack_run_retarget(ctx, prev);

    } else {
        /* ── CRAWL PHASE ── */
        if (cfg->scan_mode == SCAN_MODE_RESCAN) {
            /* reuse crawl from previous scan */
            printf(COL_BOLD "\n[Crawl] Reusing saved crawl data\n" COL_RESET);
            if (db_load_crawl(ctx) == 0) {
                printf("[Crawl] No saved data — running fresh crawl\n");
                crawler_run(ctx);
            }
        } else if (cfg->scan_mode == SCAN_MODE_RESUME) {
            int loaded = db_load_crawl(ctx);
            printf(COL_YELLOW "[Resume] Loaded %d URLs + %d forms\n" COL_RESET,
                   ctx->crawl.url_count, ctx->crawl.form_count);
            if (loaded == 0) crawler_run(ctx);
            else {
                /* crawl only new pages */
                printf("[Resume] Crawling for new pages...\n");
                crawler_run(ctx);
            }
        } else {
            /* FULL: fresh crawl */
            crawler_run(ctx);
        }

        /* ── ATTACK PHASE ── */
        attack_run_all(ctx);
    }

    ctx->end_time = time(NULL);
    db_scan_finish(ctx);

    /* ── REPORT ── */
    printf(COL_BOLD "\n[Reports]\n" COL_RESET);
    if (cfg->output_file[0]) {
        /* legacy: explicit -o FILE still works */
        int rc = strcmp(cfg->output_format,"txt")==0 ? report_txt(ctx,cfg->output_file)
               :                                       report_html(ctx,cfg->output_file);
        if (rc==0) printf(COL_GREEN "  File: %s\n" COL_RESET, cfg->output_file);
        else       fprintf(stderr,"Report write failed: %s\n", cfg->output_file);
    } else {
        /* default: all formats into reports/ directory */
        report_generate(ctx);

#ifdef __APPLE__
        /* macOS: auto-open HTML report in default browser
         * Skipped if --no-browser passed (e.g. when launched from GUI) */
        {
        bool _no_browser = false;
        for (int _i=1;_i<argc;_i++)
            if (strcmp(argv[_i],"--no-browser")==0) { _no_browser=true; break; }
        if (!_no_browser)
        {
            /* find last generated HTML report */
            char find_cmd[768] = {0};
            const char *home = getenv("HOME");
            if (!home) home = "/tmp";

            /* build path to report dir */
            char rdir[512] = {0};
            char host[256] = {0};
            const char *u = ctx->config.target_url;
            if (strncmp(u,"http://",7)==0)  u+=7;
            if (strncmp(u,"https://",8)==0) u+=8;
            size_t hi=0;
            for (;*u&&*u!='/'&&*u!=':'&&hi<255;u++) host[hi++]=*u;

            if (ctx->config.report_dir[0])
                snprintf(rdir,sizeof(rdir),"%s",ctx->config.report_dir);
            else if (strstr(ctx->config.exe_dir,".app/Contents/MacOS"))
                snprintf(rdir,sizeof(rdir),"%s/Desktop/report/%s",home,host);
            else {
                const char *base=ctx->config.exe_dir[0]?ctx->config.exe_dir:".";
                snprintf(rdir,sizeof(rdir),"%s/../report/%s",base,host);
            }

            /* find newest .html in report dir */
            snprintf(find_cmd, sizeof(find_cmd),
                "ls -t \"%s\"/*.html 2>/dev/null | head -1", rdir);
            FILE *fp = popen(find_cmd, "r");
            if (fp) {
                char html_path[768] = {0};
                if (fgets(html_path, sizeof(html_path)-1, fp)) {
                    /* strip newline */
                    size_t ln = strlen(html_path);
                    if (ln > 0 && html_path[ln-1]=='\n') html_path[ln-1]='\0';
                    if (html_path[0]) {
                        char open_cmd[800];
                        snprintf(open_cmd, sizeof(open_cmd),
                                 "open \"%s\" &", html_path);
                        printf(COL_CYAN "[macOS] Opening report in browser...\n" COL_RESET);
                        system(open_cmd);
                    }
                }
                pclose(fp);
            }
        } /* if (!_no_browser) */
        } /* extra block */
#endif
    }

    print_summary(ctx);

    /* ── Інтерактивне меню e-mail при знайдених вразливостях ── */
    if (ctx->vuln_count > 0) {
        /* Знайти останні звіти */
        char _html[768]={0}, _txt[768]={0}, _host[256]={0};
        const char *_u = ctx->config.target_url;
        if (strncmp(_u,"https://",8)==0) _u+=8;
        else if (strncmp(_u,"http://",7)==0) _u+=7;
        size_t _hi=0;
        for(;*_u&&*_u!="/"[0]&&_hi<255;_u++) _host[_hi++]=*_u;
        const char *_home = getenv("HOME"); if(!_home) _home="/tmp";
        char _rdir[512]={0};
        if (ctx->config.report_dir[0])
            snprintf(_rdir,sizeof(_rdir),"%s",ctx->config.report_dir);
#ifdef __APPLE__
        else snprintf(_rdir,sizeof(_rdir),"%s/Desktop/report/%s",_home,_host);
#else
        else { const char *_b=ctx->config.exe_dir[0]?ctx->config.exe_dir:".";
               snprintf(_rdir,sizeof(_rdir),"%s/../report/%s",_b,_host); }
#endif
        char _fc[800]={0};
        snprintf(_fc,sizeof(_fc),"ls -t \"%s\"/*.html 2>/dev/null|head -1",_rdir);
        FILE *_fp=popen(_fc,"r");
        if (_fp) {
            if (fgets(_html, sizeof(_html)-1, _fp))
                _html[strcspn(_html, "\n")] = '\0';
            pclose(_fp);
        }
        snprintf(_fc,sizeof(_fc),"ls -t \"%s\"/*.txt 2>/dev/null|head -1",_rdir);
        _fp=popen(_fc,"r");
        if (_fp) {
            if (fgets(_txt, sizeof(_txt)-1, _fp))
                _txt[strcspn(_txt, "\n")] = '\0';
            pclose(_fp);
        }
        interactive_email_menu(&email_cfg, _html, _txt,
                               _host, ctx->vuln_count);
    }

    /* ── Auto-send email if configured AND vulns=0 (interactive menu handles vuln case) ── */
    if (email_cfg.email_enabled && ctx->vuln_count == 0) {
        /* Find latest reports in report directory */
        char html_p[768]={0}, txt_p[768]={0};
        char host2[256]={0};
        const char *u2 = ctx->config.target_url;
        if (strncmp(u2,"https://",8)==0) u2+=8;
        else if (strncmp(u2,"http://",7)==0) u2+=7;
        size_t h2i=0;
        for(;*u2&&*u2!="/"[0]&&h2i<255;u2++) host2[h2i++]=*u2;
        const char *home2 = getenv("HOME"); if(!home2) home2="/tmp";
        char rdir2[512]={0};
        if (ctx->config.report_dir[0])
            snprintf(rdir2,sizeof(rdir2),"%s",ctx->config.report_dir);
#ifdef __APPLE__
        else snprintf(rdir2,sizeof(rdir2),"%s/Desktop/report/%s",home2,host2);
#else
        else { const char *b=ctx->config.exe_dir[0]?ctx->config.exe_dir:".";
               snprintf(rdir2,sizeof(rdir2),"%s/../report/%s",b,host2); }
#endif
        /* Newest HTML */
        char fc[800]={0};
        snprintf(fc,sizeof(fc),"ls -t \"%s\"/*.html 2>/dev/null | head -1",rdir2);
        FILE *fp2=popen(fc,"r");
        if(fp2){fgets(html_p,sizeof(html_p)-1,fp2);
                html_p[strcspn(html_p,"\n")]="\0"[0]; pclose(fp2);}
        /* Newest TXT */
        snprintf(fc,sizeof(fc),"ls -t \"%s\"/*.txt 2>/dev/null | head -1",rdir2);
        FILE *fp3=popen(fc,"r");
        if(fp3){fgets(txt_p,sizeof(txt_p)-1,fp3);
                txt_p[strcspn(txt_p,"\n")]="\0"[0]; pclose(fp3);}
        email_send_report(&email_cfg, host2, ctx->vuln_count,
                          html_p[0]?html_p:NULL, txt_p[0]?txt_p:NULL);
    }

    db_close(ctx);
    int rc = ctx->vuln_count > 0 ? 2 : 0;
    free(ctx);
    return rc;
}

/* ── SMTP setup wizard ───────────────────────────────────────
 * Запитує параметри поштового сервера і зберігає в конфіг    */
static void smtp_setup_wizard(ScanXSSConfig *cfg) {
    printf("\n");
    printf(COL_BOLD "╔══════════════════════════════════════════════╗\n" COL_RESET);
    printf(COL_BOLD "║       Налаштування поштового сервера         ║\n" COL_RESET);
    printf(COL_BOLD "╚══════════════════════════════════════════════╝\n\n" COL_RESET);
    printf("  Підтримується будь-який SMTP сервер з STARTTLS.\n");
    printf("  Натисніть Enter для залишення поточного значення.\n\n");

    char buf[512];

    /* smtp_host */
    printf("  SMTP сервер [%s]: ",
           cfg->smtp_host[0] ? cfg->smtp_host : "mail.example.com");
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) { /* smtp_host */
        buf[strcspn(buf, "\r\n")] = '\0';
        if (buf[0]) strncpy(cfg->smtp_host, buf, sizeof(cfg->smtp_host)-1);
    }

    /* smtp_port */
    printf("  Порт [%d] (587=STARTTLS, 25=plain): ", cfg->smtp_port ? cfg->smtp_port : 587);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\r\n")] = '\0';
        if (buf[0]) cfg->smtp_port = atoi(buf);
        else if (!cfg->smtp_port) cfg->smtp_port = 587;
    }

    /* smtp_tls */
    cfg->smtp_tls = (cfg->smtp_port == 587);
    printf("  STARTTLS: %s\n", cfg->smtp_tls ? "так (порт 587)" : "ні");

    /* smtp_user */
    printf("  Логін (smtp_user) [%s]: ", cfg->smtp_user[0] ? cfg->smtp_user : "");
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\r\n")] = '\0';
        if (buf[0]) strncpy(cfg->smtp_user, buf, sizeof(cfg->smtp_user)-1);
    }

    /* smtp_pass — не виводимо поточне значення */
    printf("  Пароль (smtp_pass) [%s]: ",
           cfg->smtp_pass[0] ? "****" : "");
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\r\n")] = '\0';
        if (buf[0]) strncpy(cfg->smtp_pass, buf, sizeof(cfg->smtp_pass)-1);
    }

    /* email_from */
    const char *def_from = cfg->email_from[0] ? cfg->email_from : cfg->smtp_user;
    printf("  Відправник email_from [%s]: ", def_from);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\r\n")] = '\0';
        if (buf[0]) strncpy(cfg->email_from, buf, sizeof(cfg->email_from)-1);
        else if (!cfg->email_from[0])
            strncpy(cfg->email_from, cfg->smtp_user, sizeof(cfg->email_from)-1);
    }

    /* Зберегти в ~/.scanxss/scanxss.conf */
    const char *home = getenv("HOME");
    if (home) {
        char dir[512], path[512];
        snprintf(dir,  sizeof(dir),  "%s/.scanxss", home);
        snprintf(path, sizeof(path), "%s/.scanxss/scanxss.conf", home);

        mkdir(dir, 0700);

        FILE *cf = fopen(path, "w");
        if (cf) {
            fprintf(cf, "# ScanXSS v1.3.1.1 — автоматично збережений конфіг\n");
            fprintf(cf, "email_enabled    = false\n");
            fprintf(cf, "smtp_host        = %s\n", cfg->smtp_host);
            fprintf(cf, "smtp_port        = %d\n", cfg->smtp_port);
            fprintf(cf, "smtp_tls         = %s\n", cfg->smtp_tls ? "true" : "false");
            fprintf(cf, "smtp_user        = %s\n", cfg->smtp_user);
            fprintf(cf, "smtp_pass        = %s\n", cfg->smtp_pass);
            fprintf(cf, "email_from       = %s\n", cfg->email_from);
            fprintf(cf, "email_to         = \n");
            fprintf(cf, "email_subject    = [ScanXSS] Report: %%h — %%v vuln(s) found (%%d)\n");
            fprintf(cf, "email_only_vulns = true\n");
            fprintf(cf, "email_attach_html = true\n");
            fprintf(cf, "default_depth    = 3\n");
            fprintf(cf, "default_rate     = 10\n");
            fprintf(cf, "default_timeout  = 10\n");
            fprintf(cf, "default_scope    = subdomain\n");
            fclose(cf);
            printf(COL_GREEN "\n  ✅  Збережено: %s\n" COL_RESET, path);
        }
    }

    cfg->email_enabled = true;
    printf(COL_GREEN "  Налаштування завершено.\n\n" COL_RESET);
}

/* ── Інтерактивне меню відправки після сканування ───────────
 * Викликається якщо знайдено вразливості                      */
static void interactive_email_menu(ScanXSSConfig *cfg,
                                   const char *html_path,
                                   const char *txt_path,
                                   const char *target_host,
                                   int vuln_count) {
    printf("\n");
    printf(COL_BOLD "╔══════════════════════════════════════════════╗\n" COL_RESET);
    printf(COL_BOLD "║           Відправка звіту на e-mail          ║\n" COL_RESET);
    printf(COL_BOLD "╚══════════════════════════════════════════════╝\n" COL_RESET);
    printf("  Знайдено " COL_RED "%d" COL_RESET " вразливість(ей) на " COL_CYAN "%s\n\n" COL_RESET,
           vuln_count, target_host);

    /* Перевірити чи налаштований SMTP */
    bool smtp_ok = cfg->smtp_host[0] && cfg->smtp_user[0];

    printf("  [1] Відправити звіт на e-mail\n");
    printf("  [2] Налаштувати поштовий сервер\n");
    printf("  [3] Пропустити\n");
    printf("\n  Вибір [1-3]: ");
    fflush(stdout);

    char choice[8] = {0};
    if (!fgets(choice, sizeof(choice), stdin)) return;
    choice[strcspn(choice, "\r\n")] = '\0';

    if (choice[0] == '3' || choice[0] == '\0') return;

    if (choice[0] == '2') {
        smtp_setup_wizard(cfg);
        smtp_ok = cfg->smtp_host[0] && cfg->smtp_user[0];
        /* Після налаштування запропонувати відправити */
        printf("  Відправити зараз? [y/N]: ");
        fflush(stdout);
        char yn[8]={0};
        if (!fgets(yn, sizeof(yn), stdin)) return;
        if (yn[0] != 'y' && yn[0] != 'Y') return;
        choice[0] = '1'; /* fall through to send */
    }

    if (choice[0] == '1') {
        if (!smtp_ok) {
            printf(COL_YELLOW "  ⚠  SMTP не налаштований. Запускаємо майстер...\n" COL_RESET);
            smtp_setup_wizard(cfg);
        }

        /* Ввід email отримувача */
        char email_to[512] = {0};
        printf("\n  Отримувач (e-mail): ");
        fflush(stdout);
        if (!fgets(email_to, sizeof(email_to), stdin)) return;
        email_to[strcspn(email_to, "\r\n")] = '\0';

        if (!email_to[0]) {
            printf(COL_YELLOW "  Email не введено — скасовано.\n" COL_RESET);
            return;
        }

        /* Перевірити мінімальний формат */
        if (!strchr(email_to, '@')) {
            printf(COL_RED "  Невірний формат e-mail.\n" COL_RESET);
            return;
        }

        /* Можна ввести кілька через кому */
        printf("  Відправник [%s]: ",
               cfg->email_from[0] ? cfg->email_from : cfg->smtp_user);
        fflush(stdout);
        char email_from[256] = {0};
        if (fgets(email_from, sizeof(email_from), stdin)) {
            email_from[strcspn(email_from, "\r\n")] = '\0';
            if (email_from[0])
                strncpy(cfg->email_from, email_from, sizeof(cfg->email_from)-1);
            else if (!cfg->email_from[0])
                strncpy(cfg->email_from, cfg->smtp_user, sizeof(cfg->email_from)-1);
        }

        /* Тема листа */
        char subj_tpl[512];
        snprintf(subj_tpl, sizeof(subj_tpl),
                 "[ScanXSS] Report: %s — %d vuln(s) found", target_host, vuln_count);
        printf("  Тема [%s]: ", subj_tpl);
        fflush(stdout);
        char subj_in[512] = {0};
        if (fgets(subj_in, sizeof(subj_in), stdin)) {
            subj_in[strcspn(subj_in, "\r\n")] = '\0';
        }
        const char *final_subj = subj_in[0] ? subj_in : subj_tpl;

        /* Прикріпити HTML? */
        printf("  Прикріпити HTML звіт? [Y/n]: ");
        fflush(stdout);
        char attach[8]={0};
        if (fgets(attach, sizeof(attach), stdin)) {
            attach[strcspn(attach, "\r\n")] = '\0';
        }
        cfg->email_attach_html = !(attach[0]=='n' || attach[0]=='N');

        /* Встановити отримувача і тему для цього відправлення */
        ScanXSSConfig tmp_cfg = *cfg;
        strncpy(tmp_cfg.email_to, email_to, sizeof(tmp_cfg.email_to)-1);
        strncpy(tmp_cfg.email_subject, final_subj, sizeof(tmp_cfg.email_subject)-1);
        tmp_cfg.email_enabled    = true;
        tmp_cfg.email_only_vulns = false; /* відправляємо завжди */

        printf("\n  Відправляємо звіт на: " COL_CYAN "%s" COL_RESET "\n", email_to);
        int rc = email_send_report(&tmp_cfg, target_host, vuln_count,
                                   html_path[0] ? html_path : NULL,
                                   txt_path[0]  ? txt_path  : NULL);
        if (rc == 0)
            printf(COL_GREEN "  ✅  Звіт відправлено!\n\n" COL_RESET);
        else
            printf(COL_RED "  ❌  Помилка відправки. Перевірте параметри SMTP.\n\n" COL_RESET);
    }
}

/* Генерувати HTML звіт для сканування з БД */
static int generate_report_for_scan(ScanContext *ctx, int64_t scan_id,
                                     char *html_out, char *txt_out,
                                     size_t outsz) {
    /* Завантажити вразливості з БД */
    ctx->vuln_count = 0;
    db_load_findings(ctx, scan_id);
    if (ctx->vuln_count == 0) return -1;

    /* Визначити директорію */
    const char *home = getenv("HOME"); if (!home) home = "/tmp";
    char host[256] = {0};
    const char *u = ctx->config.target_url;
    if (strncmp(u,"https://",8)==0) u+=8;
    else if (strncmp(u,"http://",7)==0) u+=7;
    size_t hi=0; for(;*u&&*u!='/'&&hi<255;u++) host[hi++]=*u;

    char rdir[512]={0};
#ifdef __APPLE__
    snprintf(rdir,sizeof(rdir),"%s/Desktop/report/%s",home,host);
#else
    const char *b=ctx->config.exe_dir[0]?ctx->config.exe_dir:".";
    snprintf(rdir,sizeof(rdir),"%s/../report/%s",b,host);
#endif
    /* Створити директорію */
    char tmp[512]={0}; strncpy(tmp,rdir,511);
    for (char *p=tmp+1;*p;p++)
        if(*p=='/'){ *p=0; mkdir(tmp,0755); *p='/'; }
    mkdir(tmp,0755);

    /* Шляхи файлів */
    time_t now=time(NULL); char ts[32];
    strftime(ts,sizeof(ts),"%Y%m%d_%H%M%S",localtime(&now));
    snprintf(html_out, outsz, "%s/%s_resend_%s.html", rdir, host, ts);
    snprintf(txt_out,  outsz, "%s/%s_resend_%s.txt",  rdir, host, ts);

    /* Генерувати звіти */
    report_html(ctx, html_out);
    report_txt(ctx, txt_out);
    return 0;
}

/* ════════════════════════════════════════════════════════════
 * КОМАНДА: --email-history
 * Показує всі відскановані хости з вразливостями з БД
 * і дозволяє відправити звіт на e-mail
 * ════════════════════════════════════════════════════════════ */

/* Головна функція: --email-history */
static void cmd_email_history(ScanContext *ctx, ScanXSSConfig *cfg) {
    printf("\n");
    printf(COL_BOLD "╔══════════════════════════════════════════════════╗\n" COL_RESET);
    printf(COL_BOLD "║    Відправка звітів з архіву сканувань           ║\n" COL_RESET);
    printf(COL_BOLD "╚══════════════════════════════════════════════════╝\n\n" COL_RESET);

    ScanEntry entries[50];
    int n = load_all_vuln_scans(ctx, entries, 50);

    if (n == 0) {
        printf(COL_YELLOW "  Немає збережених сканувань з вразливостями.\n\n" COL_RESET);
        return;
    }

    /* Показати список */
    printf(COL_BOLD "  %-4s  %-35s  %-19s  %-5s\n" COL_RESET,
           "ID", "Хост", "Дата", "Vulns");
    printf("  %-4s  %-35s  %-19s  %-5s\n",
           "----","-----------------------------------","-------------------","-----");

    for (int i = 0; i < n; i++) {
        /* Витягти hostname з URL */
        char host[64]={0};
        const char *u = entries[i].target;
        if (strncmp(u,"https://",8)==0) u+=8;
        else if (strncmp(u,"http://",7)==0) u+=7;
        int hi=0; while(*u&&*u!='/'&&hi<63) host[hi++]=*u++;

        printf("  " COL_CYAN "%-4lld" COL_RESET "  %-35s  %-19s  "
               COL_RED "%-5d\n" COL_RESET,
               (long long)entries[i].scan_id,
               host,
               entries[i].started,
               entries[i].vuln_count);
    }

    printf("\n  Введіть ID сканування (або 'all' для всіх, 'q' для виходу): ");
    fflush(stdout);

    char input[64]={0};
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input,"\r\n")] = '\0';

    if (input[0]=='q' || input[0]=='\0') return;

    /* Перевірити чи налаштований SMTP */
    if (!cfg->smtp_host[0] || !cfg->smtp_user[0]) {
        printf(COL_YELLOW "\n  SMTP не налаштований. Запускаємо майстер...\n" COL_RESET);
        smtp_setup_wizard(cfg);
    }

    /* Ввід email */
    printf("\n  Отримувач (e-mail): ");
    fflush(stdout);
    char email_to[512]={0};
    if (!fgets(email_to, sizeof(email_to), stdin)) return;
    email_to[strcspn(email_to,"\r\n")] = '\0';
    if (!email_to[0] || !strchr(email_to,'@')) {
        printf(COL_RED "  Невірний e-mail.\n" COL_RESET); return;
    }

    /* Визначити які скани відправляти */
    bool send_all = (strcmp(input,"all")==0);
    int64_t target_id = send_all ? 0 : (int64_t)atoll(input);

    /* Підготувати конфіг відправки */
    ScanXSSConfig send_cfg = *cfg;
    strncpy(send_cfg.email_to, email_to, sizeof(send_cfg.email_to)-1);
    send_cfg.email_enabled    = true;
    send_cfg.email_only_vulns = false;

    int sent=0, failed=0;

    for (int i = 0; i < n; i++) {
        if (!send_all && entries[i].scan_id != target_id) continue;

        /* Встановити URL цілі для завантаження вразливостей */
        strncpy(ctx->config.target_url, entries[i].target,
                sizeof(ctx->config.target_url)-1);

        printf("\n  [%lld] %s (%d vulns) → генеруємо звіт...\n",
               (long long)entries[i].scan_id,
               entries[i].target, entries[i].vuln_count);

        char html_p[768]={0}, txt_p[768]={0};
        if (generate_report_for_scan(ctx, entries[i].scan_id,
                                     html_p, txt_p, sizeof(html_p)) < 0) {
            printf(COL_YELLOW "  ⚠  Не вдалося завантажити вразливості.\n" COL_RESET);
            failed++;
            continue;
        }

        /* Тема з назвою хосту */
        char host2[256]={0};
        const char *u2 = entries[i].target;
        if (strncmp(u2,"https://",8)==0) u2+=8;
        else if (strncmp(u2,"http://",7)==0) u2+=7;
        int h2i=0; while(*u2&&*u2!='/'&&h2i<255) host2[h2i++]=*u2++;

        char subj[512];
        snprintf(subj, sizeof(subj),
                 "[ScanXSS] Archived Report: %s — %d vuln(s) [scan #%lld]",
                 host2, entries[i].vuln_count,
                 (long long)entries[i].scan_id);
        strncpy(send_cfg.email_subject, subj, sizeof(send_cfg.email_subject)-1);

        int rc = email_send_report(&send_cfg, host2,
                                   entries[i].vuln_count,
                                   html_p[0] ? html_p : NULL,
                                   txt_p[0]  ? txt_p  : NULL);
        if (rc == 0) {
            printf(COL_GREEN "  ✅  Відправлено: %s\n" COL_RESET, email_to);
            sent++;
        } else {
            printf(COL_RED "  ❌  Помилка відправки scan #%lld\n" COL_RESET,
                   (long long)entries[i].scan_id);
            failed++;
        }

        if (!send_all) break;
    }

    printf("\n");
    if (sent > 0)
        printf(COL_GREEN "  Відправлено: %d звіт(ів) на %s\n" COL_RESET, sent, email_to);
    if (failed > 0)
        printf(COL_RED "  Помилок: %d\n" COL_RESET, failed);
    printf("\n");
}
