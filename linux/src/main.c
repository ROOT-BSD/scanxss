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
COL_BOLD "  %s v%s — Web Vulnerability Scanner | GPL-2.0\n\n" COL_RESET,
SCANXSS_NAME, SCANXSS_VERSION);
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
           "  -f FORMAT           html|json|txt\n"
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
           "  %s -u http://site.com/ --rescan -f json -o new.json\n"
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
    {"help",         no_argument,      0,'h'},
    {"version",      no_argument,      0,'V'},
    {0,0,0,0}
};

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

    if (argc < 2) { print_banner(); print_usage(argv[0]); free(ctx); return 1; }
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
        default:  print_usage(argv[0]); free(ctx); return 1;
        }
    }

    if (!cfg->target_url[0]) {
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
        int rc = strcmp(cfg->output_format,"json")==0 ? report_json(ctx,cfg->output_file)
               : strcmp(cfg->output_format,"txt") ==0 ? report_txt (ctx,cfg->output_file)
               :                                        report_html(ctx,cfg->output_file);
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
                snprintf(rdir,sizeof(rdir),"%s/.scanxss/report/%s",home,host);
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
    db_close(ctx);
    int rc = ctx->vuln_count > 0 ? 2 : 0;
    free(ctx);
    return rc;
}
