#include "scanxss.h"
#include "vuln_info.h"
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

/* ══════════════════════════════════════════════════════════
 * Helpers
 * ══════════════════════════════════════════════════════════ */
static const char *severity_name(int s) {
    switch (s) {
        case 1: return "Інформаційна"; case 2: return "Низька";
        case 3: return "Середня";      case 4: return "Висока";
        case 5: return "Критична";     default: return "Невідома";
    }
}
static const char *severity_en(int s) {
    switch (s) {
        case 1: return "Informational"; case 2: return "Low";
        case 3: return "Medium";        case 4: return "High";
        case 5: return "Critical";      default: return "Unknown";
    }
}
static const char *vuln_type_name(VulnType t) {
    switch (t) {
        case VULN_XSS:        return "Cross-Site Scripting (XSS)";
        case VULN_SQLI:       return "SQL Injection";
        case VULN_LFI:        return "Local File Inclusion";
        case VULN_RCE:        return "Remote Code Execution";
        case VULN_SSRF:       return "Server-Side Request Forgery (SSRF)";
        case VULN_OPEN_REDIR: return "Open Redirect";
        case VULN_CRLF:       return "CRLF Injection";
        case VULN_XXE:        return "XXE Injection";
        default:              return "Невідомо";
    }
}

/* HTML escape */
static void html_esc(FILE *f, const char *s) {
    if (!s) return;
    for (; *s; s++) switch (*s) {
        case '<':  fputs("&lt;",   f); break;
        case '>':  fputs("&gt;",   f); break;
        case '&':  fputs("&amp;",  f); break;
        case '"':  fputs("&quot;", f); break;
        case '\'': fputs("&#39;",  f); break;
        default:   fputc(*s, f);
    }
}
/* JSON escape */
static void json_esc(FILE *f, const char *s) {
    if (!s) return;
    for (; *s; s++) switch (*s) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n",  f); break;
        case '\r': fputs("\\r",  f); break;
        case '\t': fputs("\\t",  f); break;
        default:
            if ((unsigned char)*s < 0x20) fprintf(f,"\\u%04x",(unsigned char)*s);
            else fputc(*s, f);
    }
}

/* ── sanitise hostname for directory name ──────────────────── */
static void host_to_dirname(const char *target_url, char *out, size_t sz) {
    const char *u = target_url;
    if (strncmp(u, "http://",  7) == 0) u += 7;
    if (strncmp(u, "https://", 8) == 0) u += 8;
    size_t i = 0;
    for (; *u && *u != '/' && i < sz-1; u++) {
        char c = *u;
        if (c==':'||c=='\\'||c=='*'||c=='?'||c=='"'||c=='<'||c=='>'||c=='|') c='_';
        out[i++] = c;
    }
    if (!out[0]) strncpy(out, "scan", sz-1);
}

/* ── ensure ../report/{hostname}/ directory ────────────────── */
static int ensure_report_dir(const ScanContext *ctx, char *dir_out, size_t sz) {
    if (ctx->config.report_dir[0]) {
        snprintf(dir_out, sz, "%s", ctx->config.report_dir);
    } else {
        const char *base = ctx->config.exe_dir[0] ? ctx->config.exe_dir : ".";
        char hostname[256] = {0};
        host_to_dirname(ctx->config.target_url, hostname, sizeof(hostname));
        snprintf(dir_out, sz, "%s/../report/%s", base, hostname);
    }
    struct stat st;
    if (stat(dir_out, &st) == 0) return 0;
    /* mkdir -p */
    char tmp[640] = {0};
    snprintf(tmp, sizeof(tmp), "%s", dir_out);
    for (char *p = tmp+1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    if (mkdir(dir_out, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[report] Cannot create %s: %s\n", dir_out, strerror(errno));
        return -1;
    }
    return 0;
}

/* ── build report filename ─────────────────────────────────── */
static void make_report_path(const ScanContext *ctx, const char *dir,
                              const char *ext, char *out, size_t sz) {
    char host[128] = {0};
    host_to_dirname(ctx->config.target_url, host, sizeof(host));
    char ts[32] = {0};
    struct tm *tm = localtime(&ctx->start_time);
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm);
    snprintf(out, sz, "%s/%s_%s.%s", dir, host, ts, ext);
}

/* ══════════════════════════════════════════════════════════
 * JSON REPORT
 * ══════════════════════════════════════════════════════════ */
int report_json(const ScanContext *ctx, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) { perror(filename); return -1; }
    char tstart[64]={0}, tend[64]={0};
    struct tm *tm;
    tm = localtime(&ctx->start_time); strftime(tstart,sizeof(tstart),"%Y-%m-%dT%H:%M:%S",tm);
    tm = localtime(&ctx->end_time);   strftime(tend,  sizeof(tend),  "%Y-%m-%dT%H:%M:%S",tm);

    fprintf(f,"{\n");
    fprintf(f,"  \"scanner\": \"%s %s\",\n", SCANXSS_NAME, SCANXSS_VERSION);
    fprintf(f,"  \"target\": \""); json_esc(f,ctx->config.target_url);
    fprintf(f,"\",\n  \"scan_id\": %lld,\n",(long long)ctx->scan_id);
    fprintf(f,"  \"start_time\": \"%s\",\n", tstart);
    fprintf(f,"  \"end_time\": \"%s\",\n",   tend);
    fprintf(f,"  \"requests_made\": %d,\n",  ctx->requests_made);
    fprintf(f,"  \"urls_found\": %d,\n",     ctx->crawl.url_count);
    fprintf(f,"  \"forms_found\": %d,\n",    ctx->crawl.form_count);
    fprintf(f,"  \"vulnerabilities\": [\n");
    for (int i = 0; i < ctx->vuln_count; i++) {
        const Vuln *v = &ctx->vulns[i];
        const VulnInfo *vi = vuln_info_get(v->type, v->severity);
        fprintf(f,"    {\n");
        fprintf(f,"      \"id\": %lld,\n",(long long)v->db_id);
        fprintf(f,"      \"type\": \"");        json_esc(f,vuln_type_name(v->type));
        fprintf(f,"\",\n      \"module\": \""); json_esc(f,v->module);
        fprintf(f,"\",\n      \"severity\": \"%s\",\n", severity_en(v->severity));
        fprintf(f,"      \"severity_num\": %d,\n", v->severity);
        fprintf(f,"      \"url\": \"");         json_esc(f,v->url);
        fprintf(f,"\",\n      \"parameter\": \""); json_esc(f,v->parameter);
        fprintf(f,"\",\n      \"payload\": \""); json_esc(f,v->payload);
        fprintf(f,"\",\n      \"evidence\": \""); json_esc(f,v->evidence);
        fprintf(f,"\",\n      \"confirmed\": %s", v->confirmed?"true":"false");
        if (vi) {
            fprintf(f,",\n      \"cvss\": \"%s\"", vi->cvss_score);
            fprintf(f,",\n      \"references\": [");
            bool first=true;
            for(int r=0;vi->refs[r].label;r++) {
                if(!first) fprintf(f,",");
                fprintf(f,"\n        {\"label\":\"%s\",\"url\":\"%s\"}",
                        vi->refs[r].label, vi->refs[r].url);
                first=false;
            }
            fprintf(f,"\n      ]");
        }
        fprintf(f,"\n    }%s\n", i<ctx->vuln_count-1?",":"");
    }
    fprintf(f,"  ]\n}\n");
    fclose(f);
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * HTML REPORT — light theme + vulnerability explanations
 * ══════════════════════════════════════════════════════════ */
int report_html(const ScanContext *ctx, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) { perror(filename); return -1; }

    char tstart[64]={0};
    struct tm *tm = localtime(&ctx->start_time);
    strftime(tstart, sizeof(tstart), "%Y-%m-%d %H:%M:%S", tm);
    double elapsed = difftime(ctx->end_time, ctx->start_time);

    /* ── HEAD ── */
    fputs("<!DOCTYPE html>\n<html lang='uk'>\n<head>\n"
          "<meta charset='UTF-8'>\n"
          "<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
          "<meta http-equiv='Content-Security-Policy'"
          " content=\"default-src 'none'; style-src 'unsafe-inline';"
          " script-src 'unsafe-inline'\">\n", f);
    fprintf(f, "<title>ScanXSS \342\200\224 %s</title>\n", ctx->config.target_url);
    fputs(
"<style>\n"
"*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n"
"html{font-size:15px}\n"
"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
"background:#f1f5f9;color:#1e293b;line-height:1.6}\n"
/* header */
"header{background:linear-gradient(135deg,#1e3a8a 0%%,#1d4ed8 100%%);"
"padding:28px 40px;color:#fff;box-shadow:0 2px 8px rgba(0,0,0,.2)}\n"
".hdr-top{display:flex;align-items:center;gap:16px}\n"
".hdr-logo{font-size:2.2em}\n"
".hdr-title h1{font-size:1.5em;font-weight:700;letter-spacing:-.01em}\n"
".hdr-title p{color:#93c5fd;font-size:.88em;margin-top:2px}\n"
".hdr-meta{display:flex;gap:24px;margin-top:16px;flex-wrap:wrap}\n"
".hdr-meta .m{background:rgba(255,255,255,.12);border-radius:8px;"
"padding:8px 16px;font-size:.82em;color:#e0f2fe}\n"
".hdr-meta .m strong{display:block;font-size:1.3em;color:#fff;font-weight:700}\n"
/* layout */
".container{max-width:1280px;margin:0 auto;padding:28px 24px}\n"
/* summary cards */
".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));"
"gap:14px;margin-bottom:28px}\n"
".card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;"
"padding:18px 22px;box-shadow:0 1px 3px rgba(0,0,0,.06)}\n"
".card .num{font-size:2.2em;font-weight:800;color:#3b82f6;line-height:1}\n"
".card.danger .num{color:#dc2626}\n"
".card.warn .num{color:#f59e0b}\n"
".card .lbl{color:#64748b;font-size:.78em;text-transform:uppercase;"
"letter-spacing:.05em;font-weight:600;margin-top:5px}\n"
/* section headings */
".sec-title{font-size:.75em;font-weight:700;text-transform:uppercase;"
"letter-spacing:.08em;color:#94a3b8;margin:28px 0 12px;"
"padding-bottom:8px;border-bottom:1px solid #e2e8f0}\n"
/* vuln cards */
".vuln-card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;"
"margin-bottom:20px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.06)}\n"
".vuln-header{padding:16px 20px;display:flex;align-items:center;"
"gap:14px;cursor:pointer;user-select:none}\n"
".vuln-header:hover{background:#f8fafc}\n"
".sev-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}\n"
".sev-5 .sev-dot{background:#dc2626}\n"
".sev-4 .sev-dot{background:#f59e0b}\n"
".sev-3 .sev-dot{background:#f97316}\n"
".sev-2 .sev-dot{background:#3b82f6}\n"
".sev-1 .sev-dot{background:#94a3b8}\n"
".vuln-type{font-weight:700;font-size:.95em}\n"
".sev-5 .vuln-type{color:#dc2626}\n"
".sev-4 .vuln-type{color:#f59e0b}\n"
".sev-3 .vuln-type{color:#f97316}\n"
".sev-2 .vuln-type{color:#3b82f6}\n"
".badge-sev{display:inline-block;padding:2px 10px;border-radius:20px;"
"font-size:.73em;font-weight:700;margin-left:auto;white-space:nowrap}\n"
".sev-5 .badge-sev{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}\n"
".sev-4 .badge-sev{background:#fffbeb;color:#d97706;border:1px solid #fde68a}\n"
".sev-3 .badge-sev{background:#fff7ed;color:#ea580c;border:1px solid #fed7aa}\n"
".sev-2 .badge-sev{background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe}\n"
".sev-1 .badge-sev{background:#f8fafc;color:#64748b;border:1px solid #e2e8f0}\n"
".chevron{margin-left:8px;transition:transform .2s;color:#94a3b8;font-size:.8em}\n"
".open .chevron{transform:rotate(90deg)}\n"
/* vuln body */
".vuln-body{padding:0 20px 20px;border-top:1px solid #f1f5f9;display:none}\n"
".vuln-body.show{display:block}\n"
/* technical details table */
".detail-grid{display:grid;grid-template-columns:120px 1fr;"
"gap:6px 12px;margin:14px 0;font-size:.87em}\n"
".detail-grid .dk{color:#64748b;font-weight:600;padding-top:2px}\n"
".detail-grid .dv code{background:#f1f5f9;padding:2px 7px;border-radius:4px;"
"font-family:monospace;font-size:.9em;word-break:break-all}\n"
/* explanation section */
".expl{background:#f8fafc;border-left:4px solid #3b82f6;border-radius:0 8px 8px 0;"
"padding:14px 18px;margin:16px 0;font-size:.88em}\n"
".expl.crit{border-color:#dc2626;background:#fff5f5}\n"
".expl.high{border-color:#f59e0b;background:#fffdf0}\n"
".expl h4{font-size:.82em;text-transform:uppercase;letter-spacing:.05em;"
"color:#64748b;margin-bottom:8px;font-weight:700}\n"
".expl p{color:#374151;line-height:1.7;margin-bottom:8px}\n"
".expl p:last-child{margin-bottom:0}\n"
".impact-box{background:#fff;border:1px solid #fecaca;border-radius:6px;"
"padding:10px 14px;margin:8px 0;font-size:.85em;color:#991b1b}\n"
".fix-box{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;"
"padding:10px 14px;margin:8px 0;font-size:.85em;color:#166534}\n"
/* reference links */
".refs{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}\n"
".ref-link{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;"
"background:#fff;border:1px solid #e2e8f0;border-radius:20px;"
"font-size:.78em;color:#1d4ed8;text-decoration:none;font-weight:500;"
"transition:all .15s}\n"
".ref-link:hover{background:#eff6ff;border-color:#3b82f6;box-shadow:0 1px 4px rgba(59,130,246,.2)}\n"
".ref-icon{font-size:.9em}\n"
/* empty */
".empty{text-align:center;padding:60px;background:#fff;border:1px solid #e2e8f0;"
"border-radius:12px;color:#94a3b8;font-size:1.05em}\n"
".empty .big{font-size:3em;margin-bottom:12px}\n"
/* findings table */
"table{width:100%%;border-collapse:collapse;background:#fff;"
"border:1px solid #e2e8f0;border-radius:10px;overflow:hidden;"
"box-shadow:0 1px 3px rgba(0,0,0,.06);margin-bottom:28px;font-size:.87em}\n"
"th{background:#f1f5f9;padding:10px 14px;text-align:left;font-size:.74em;"
"font-weight:700;text-transform:uppercase;letter-spacing:.05em;"
"color:#64748b;border-bottom:2px solid #e2e8f0;white-space:nowrap}\n"
"td{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:top;"
"word-break:break-all}\n"
"tr:last-child td{border-bottom:none}\n"
"tbody tr:hover td{background:#f8fafc}\n"
"code{font-family:monospace;background:#f1f5f9;padding:2px 6px;"
"border-radius:4px;font-size:.85em}\n"
/* footer */
"footer{text-align:center;padding:24px;color:#94a3b8;font-size:.8em;"
"border-top:1px solid #e2e8f0;margin-top:8px;background:#fff}\n"
"</style>\n"
"<script>\n"
"function toggle(id){\n"
"  var b=document.getElementById('b'+id);\n"
"  var h=document.getElementById('h'+id);\n"
"  if(b.classList.contains('show')){\n"
"    b.classList.remove('show');\n"
"    h.classList.remove('open');\n"
"  } else {\n"
"    b.classList.add('show');\n"
"    h.classList.add('open');\n"
"  }\n"
"}\n"
"</script>\n"
"</head>\n<body>\n", f);

    /* ── Header ── */
    fprintf(f,
"<header>\n"
"<div class='hdr-top'>\n"
"<div class='hdr-logo'>🔍</div>\n"
"<div class='hdr-title'>\n"
"<h1>ScanXSS — Звіт сканування вразливостей</h1>\n"
"<p>");
    html_esc(f, ctx->config.target_url);
    fprintf(f, " &nbsp;·&nbsp; Scan #%lld &nbsp;·&nbsp; %s</p>\n"
"</div></div>\n"
"<div class='hdr-meta'>\n"
"<div class='m'><strong>%d</strong>вразливост%s</div>\n"
"<div class='m'><strong>%d</strong>URL знайдено</div>\n"
"<div class='m'><strong>%d</strong>Форм</div>\n"
"<div class='m'><strong>%d</strong>HTTP запитів</div>\n"
"<div class='m'><strong>%.0f сек</strong>тривалість</div>\n"
"</div>\n</header>\n",
        (long long)ctx->scan_id, tstart,
        ctx->vuln_count,
        ctx->vuln_count==1?"ь":ctx->vuln_count>=2&&ctx->vuln_count<=4?"і":"ей",
        ctx->crawl.url_count, ctx->crawl.form_count,
        ctx->requests_made, elapsed);

    fprintf(f, "<div class='container'>\n");

    /* ── Summary cards ── */
    int cnt[256]={0};
    for (int i=0;i<ctx->vuln_count;i++) cnt[(int)ctx->vulns[i].type]++;
    int crit=0,high=0,med=0;
    for (int i=0;i<ctx->vuln_count;i++) {
        if(ctx->vulns[i].severity==5) crit++;
        else if(ctx->vulns[i].severity==4) high++;
        else if(ctx->vulns[i].severity==3) med++;
    }
    fprintf(f,"<div class='cards'>\n");
    fprintf(f,"<div class='card %s'><div class='num'>%d</div>"
              "<div class='lbl'>Всього</div></div>\n",
              ctx->vuln_count>0?"danger":"", ctx->vuln_count);
    fprintf(f,"<div class='card %s'><div class='num'>%d</div>"
              "<div class='lbl'>Критичних</div></div>\n",
              crit>0?"danger":"", crit);
    fprintf(f,"<div class='card %s'><div class='num'>%d</div>"
              "<div class='lbl'>Високих</div></div>\n",
              high>0?"warn":"", high);
    fprintf(f,"<div class='card'><div class='num'>%d</div>"
              "<div class='lbl'>Середніх</div></div>\n", med);
    fprintf(f,"</div>\n");

    /* ── Detailed Vulnerabilities ── */
    fprintf(f,"<p class='sec-title'>Детальний опис вразливостей</p>\n");

    if (ctx->vuln_count == 0) {
        fprintf(f,"<div class='empty'><div class='big'>✅</div>"
                  "Вразливостей не виявлено</div>\n");
    } else {
        for (int i = 0; i < ctx->vuln_count; i++) {
            const Vuln *v = &ctx->vulns[i];
            int sev = (v->severity>=1&&v->severity<=5) ? v->severity : 1;
            const VulnInfo *vi = vuln_info_get(v->type, v->severity);

            const char *sev_cls = sev==5?"sev-5":sev==4?"sev-4":
                                  sev==3?"sev-3":sev==2?"sev-2":"sev-1";

            fprintf(f,"<div class='vuln-card %s'>\n", sev_cls);

            /* Clickable header */
            fprintf(f,"<div class='vuln-header' id='h%d' onclick='toggle(%d)'>\n",i,i);
            fprintf(f,"<span class='sev-dot'></span>\n");
            fprintf(f,"<span class='vuln-type'>%s</span>\n", vuln_type_name(v->type));
            fprintf(f,"<span style='color:#64748b;font-size:.82em;margin-left:8px'>");
            html_esc(f, v->url);
            fprintf(f," → <code>");
            html_esc(f, v->parameter);
            fprintf(f,"</code></span>\n");
            fprintf(f,"<span class='badge-sev'>%s</span>\n", severity_name(sev));
            fprintf(f,"<span class='chevron'>▶</span>\n");
            fprintf(f,"</div>\n");

            /* Expandable body */
            /* First vuln always open */
            fprintf(f,"<div class='vuln-body%s' id='b%d'>\n",
                    i==0?" show":"", i);

            /* Technical details */
            fprintf(f,"<div class='detail-grid'>\n");
            fprintf(f,"<span class='dk'>URL</span><span class='dv'><code>");
            html_esc(f, v->url);
            fprintf(f,"</code></span>\n");
            fprintf(f,"<span class='dk'>Параметр</span><span class='dv'><code>");
            html_esc(f, v->parameter);
            fprintf(f,"</code></span>\n");
            fprintf(f,"<span class='dk'>Payload</span><span class='dv'><code>");
            html_esc(f, v->payload);
            fprintf(f,"</code></span>\n");
            fprintf(f,"<span class='dk'>Доказ</span><span class='dv'>");
            html_esc(f, v->evidence);
            fprintf(f,"</span>\n");
            fprintf(f,"<span class='dk'>Модуль</span><span class='dv'>"
                      "<code>%s</code></span>\n", v->module);
            if (vi) fprintf(f,"<span class='dk'>CVSS</span><span class='dv'>"
                            "<strong>%s</strong></span>\n", vi->cvss_score);
            fprintf(f,"</div>\n");

            /* Explanation block (for Critical & High) */
            if (vi && v->severity >= 3) {
                const char *expl_cls = sev==5?"crit":sev==4?"high":"";
                fprintf(f,"<div class='expl %s'>\n", expl_cls);

                fprintf(f,"<h4>🔎 Що це таке</h4>\n");
                fprintf(f,"<p>%s</p>\n", vi->description);

                fprintf(f,"<h4 style='margin-top:12px'>💥 Можливий вплив</h4>\n");
                fprintf(f,"<div class='impact-box'>%s</div>\n", vi->impact);

                fprintf(f,"<h4 style='margin-top:12px'>🛡 Як виправити</h4>\n");
                fprintf(f,"<div class='fix-box'>%s</div>\n", vi->remediation);

                fprintf(f,"</div>\n");

                /* Reference links */
                fprintf(f,"<div class='refs'>\n");
                fprintf(f,"<span style='font-size:.8em;color:#64748b;"
                          "font-weight:600;align-self:center'>Детальніше:</span>\n");
                for (int r=0; vi->refs[r].label; r++) {
                    fprintf(f,"<a class='ref-link' href='");
                    html_esc(f, vi->refs[r].url);
                    fprintf(f,"' target='_blank' rel='noopener'>"
                              "<span class='ref-icon'>🔗</span>");
                    html_esc(f, vi->refs[r].label);
                    fprintf(f,"</a>\n");
                }
                fprintf(f,"</div>\n");
            }

            fprintf(f,"</div>\n</div>\n\n"); /* .vuln-body .vuln-card */
        }
    }

    /* ── Summary Table ── */
    if (ctx->vuln_count > 0) {
        fprintf(f,"<p class='sec-title'>Зведена таблиця</p>\n");
        fprintf(f,"<table>\n<thead><tr>\n"
                  "<th>#</th><th>Тип</th><th>Серйозність</th>"
                  "<th>URL</th><th>Параметр</th><th>Payload</th>\n"
                  "</tr></thead>\n<tbody>\n");
        for (int i=0;i<ctx->vuln_count;i++) {
            const Vuln *v=&ctx->vulns[i];
            int sev=(v->severity>=1&&v->severity<=5)?v->severity:1;
            const char *sev_col=sev>=5?"#dc2626":sev==4?"#f59e0b":
                                sev==3?"#f97316":sev==2?"#3b82f6":"#94a3b8";
            fprintf(f,"<tr>\n<td style='color:#94a3b8;font-weight:600'>%d</td>\n",i+1);
            fprintf(f,"<td style='font-weight:600'>%s</td>\n",vuln_type_name(v->type));
            fprintf(f,"<td><strong style='color:%s'>%s</strong></td>\n",
                    sev_col, severity_name(sev));
            fprintf(f,"<td><code>"); html_esc(f,v->url);       fprintf(f,"</code></td>\n");
            fprintf(f,"<td><code>"); html_esc(f,v->parameter); fprintf(f,"</code></td>\n");
            fprintf(f,"<td><code>"); html_esc(f,v->payload);   fprintf(f,"</code></td>\n");
            fprintf(f,"</tr>\n");
        }
        fprintf(f,"</tbody></table>\n");
    }

    fprintf(f,"</div>\n");
    fprintf(f,"<footer>%s %s &nbsp;·&nbsp; Web Vulnerability Scanner"
              " &nbsp;·&nbsp; GPL-2.0 &nbsp;·&nbsp; %s</footer>\n"
              "</body></html>\n",
            SCANXSS_NAME, SCANXSS_VERSION, tstart);
    fclose(f);
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * TXT REPORT
 * ══════════════════════════════════════════════════════════ */
int report_txt(const ScanContext *ctx, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) { perror(filename); return -1; }
    char tstart[64]={0};
    struct tm *tm=localtime(&ctx->start_time);
    strftime(tstart, sizeof(tstart), "%Y-%m-%d %H:%M:%S", tm);
    fprintf(f,"=========================================\n");
    fprintf(f,"  %s %s — ЗВІТ СКАНУВАННЯ\n", SCANXSS_NAME, SCANXSS_VERSION);
    fprintf(f,"=========================================\n");
    fprintf(f,"Ціль:          %s\n", ctx->config.target_url);
    fprintf(f,"Scan ID:       %lld\n", (long long)ctx->scan_id);
    fprintf(f,"Час:           %s\n", tstart);
    fprintf(f,"URL знайдено:  %d\n", ctx->crawl.url_count);
    fprintf(f,"Форм знайдено: %d\n", ctx->crawl.form_count);
    fprintf(f,"HTTP запитів:  %d\n", ctx->requests_made);
    fprintf(f,"Вразливостей:  %d\n\n", ctx->vuln_count);
    if (ctx->vuln_count==0) {
        fprintf(f,"Вразливостей не виявлено.\n");
    } else {
        for (int i=0;i<ctx->vuln_count;i++) {
            const Vuln *v=&ctx->vulns[i];
            const VulnInfo *vi=vuln_info_get(v->type,v->severity);
            fprintf(f,"[%d] %s (%s)\n",i+1,vuln_type_name(v->type),severity_name(v->severity));
            if(vi) fprintf(f,"    CVSS:        %s\n",vi->cvss_score);
            fprintf(f,"    URL:         %s\n",v->url);
            fprintf(f,"    Параметр:    %s\n",v->parameter);
            fprintf(f,"    Payload:     %s\n",v->payload);
            fprintf(f,"    Доказ:       %s\n",v->evidence);
            if(vi && v->severity>=3) {
                fprintf(f,"    Опис:        %s\n",vi->description);
                fprintf(f,"    Вплив:       %s\n",vi->impact);
                fprintf(f,"    Виправлення: %s\n",vi->remediation);
                fprintf(f,"    Посилання:\n");
                for(int r=0;vi->refs[r].label;r++)
                    fprintf(f,"      - %s: %s\n",vi->refs[r].label,vi->refs[r].url);
            }
            fprintf(f,"\n");
        }
    }
    fprintf(f,"=========================================\n");
    fclose(f);
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * AUTO REPORT — generates all formats into ../report/{host}/
 * ══════════════════════════════════════════════════════════ */
int report_generate(ScanContext *ctx) {
    char dir[640]={0};
    if (ensure_report_dir(ctx, dir, sizeof(dir)) < 0) return -1;

    char path_html[700], path_json[700], path_txt[700];
    make_report_path(ctx, dir, "html", path_html, sizeof(path_html));
    make_report_path(ctx, dir, "json", path_json, sizeof(path_json));
    make_report_path(ctx, dir, "txt",  path_txt,  sizeof(path_txt));

    int ok=0;
    if (report_html(ctx,path_html)==0) {
        printf(COL_GREEN "  HTML: %s\n" COL_RESET, path_html); ok++;
    } else fprintf(stderr,"  HTML: FAILED %s\n",path_html);
    if (report_json(ctx,path_json)==0) {
        printf(COL_GREEN "  JSON: %s\n" COL_RESET, path_json); ok++;
    } else fprintf(stderr,"  JSON: FAILED %s\n",path_json);
    if (report_txt(ctx,path_txt)==0) {
        printf(COL_GREEN "  TXT:  %s\n" COL_RESET, path_txt); ok++;
    } else fprintf(stderr,"  TXT:  FAILED %s\n",path_txt);

    return ok==3?0:-1;
}
