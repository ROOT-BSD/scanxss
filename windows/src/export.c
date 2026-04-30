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
#include <io.h>

static void html_esc_f(FILE *f, const char *s) {
    for(;*s;s++) switch(*s){
        case '<': fputs("&lt;",f); break;
        case '>': fputs("&gt;",f); break;
        case '&': fputs("&amp;",f); break;
        case '"': fputs("&quot;",f); break;
        default:  fputc(*s,f);
    }
}

int export_html(AppState *app, const wchar_t *path) {
    /* Convert wchar path to UTF-8 for fopen */
    FILE *f=_wfopen(path,L"wb");
    if(!f) return -1;
    /* UTF-8 BOM */
    fwrite("\xEF\xBB\xBF",1,3,f);
    fprintf(f,"<!DOCTYPE html><html lang='uk'><head><meta charset='UTF-8'>"
              "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
              "<title>ScanXSS Report</title><style>"
              "body{font-family:Segoe UI,Arial,sans-serif;background:#f8fafc;color:#1e293b;margin:0}"
              "header{background:#1e3a8a;padding:24px 40px;color:#fff}"
              "header h1{margin:0;font-size:1.4em} header p{margin:4px 0 0;color:#93c5fd;font-size:.9em}"
              ".container{max-width:1200px;margin:32px auto;padding:0 24px}"
              ".stats{display:flex;gap:16px;margin-bottom:24px}"
              ".card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px 24px;flex:1}"
              ".card .num{font-size:2em;font-weight:800;color:#3b82f6}"
              ".card.danger .num{color:#ef4444}"
              ".card .lbl{color:#64748b;font-size:.8em;text-transform:uppercase;margin-top:4px}"
              "table{width:100%%;border-collapse:collapse;background:#fff;"
              "border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;font-size:.88em}"
              "th{background:#f1f5f9;padding:10px 14px;text-align:left;font-size:.75em;"
              "text-transform:uppercase;color:#64748b;border-bottom:2px solid #e2e8f0}"
              "td{padding:10px 14px;border-bottom:1px solid #f1f5f9;word-break:break-all;vertical-align:top}"
              ".sev-5{color:#dc2626}.sev-4{color:#ea580c}.sev-3{color:#d97706}"
              ".sev-2{color:#2563eb}.sev-1{color:#64748b}"
              "code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:.85em}"
              "footer{text-align:center;padding:20px;color:#94a3b8;font-size:.8em}"
              "</style></head><body>\n");

    time_t now=time(NULL); char ts[64]; strftime(ts,63,"%Y-%m-%d %H:%M:%S",localtime(&now));
    const char *target_url = (app->scan_params && app->scan_params->url[0])
        ? app->scan_params->url : "—";
    fprintf(f,"<header><h1>\xf0\x9f\x94\x8d ScanXSS — Report</h1>"
              "<p>Target: %s</p><p>Generated: %s</p></header>\n",
              target_url, ts);
    fprintf(f,"<div class='container'>\n");
    fprintf(f,"<div class='stats'>"
              "<div class='card%s'><div class='num'>%d</div><div class='lbl'>Вразливостей</div></div>"
              "<div class='card'><div class='num'>—</div><div class='lbl'>URL перевірено</div></div>"
              "</div>\n",
              app->vuln_count>0?" danger":"", app->vuln_count);

    if(app->vuln_count==0) {
        fprintf(f,"<div style='text-align:center;padding:48px;color:#94a3b8;font-size:1.1em'>"
                  "✅ Вразливостей не виявлено</div>\n");
    } else {
        fprintf(f,"<table><thead><tr>"
                  "<th>#</th><th>Тип</th><th>Серйозність</th><th>URL</th>"
                  "<th>Параметр</th><th>Payload</th><th>Доказ</th>"
                  "</tr></thead><tbody>\n");
        for(int i=0;i<app->vuln_count;i++) {
            const VulnRecord *v=&app->vulns[i];
            fprintf(f,"<tr><td>%d</td>",i+1);
            fprintf(f,"<td>"); html_esc_f(f,v->type); fprintf(f,"</td>");
            fprintf(f,"<td class='sev-%d'>%s</td>",v->severity,
                v->severity>=5?"Critical":v->severity==4?"High":
                v->severity==3?"Medium":v->severity==2?"Low":"Info");
            fprintf(f,"<td><code>"); html_esc_f(f,v->url); fprintf(f,"</code></td>");
            fprintf(f,"<td><code>"); html_esc_f(f,v->parameter); fprintf(f,"</code></td>");
            fprintf(f,"<td><code>"); html_esc_f(f,v->payload); fprintf(f,"</code></td>");
            fprintf(f,"<td>"); html_esc_f(f,v->evidence); fprintf(f,"</td></tr>\n");
        }
        fprintf(f,"</tbody></table>\n");
    }
    fprintf(f,"</div>\n<footer>ScanXSS v1.3.3 | Web Vulnerability Scanner | © 2026 root_bsd</footer>"
              "\n</body></html>\n");
    fclose(f);
    return 0;
}

int export_csv(AppState *app, const wchar_t *path) {
    FILE *f=_wfopen(path,L"w,ccs=UTF-8");
    if(!f) return -1;
    fprintf(f,"#,Type,Severity,URL,Parameter,Payload,Evidence\r\n");
    for(int i=0;i<app->vuln_count;i++) {
        const VulnRecord *v=&app->vulns[i];
        fprintf(f,"%d,\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\"\r\n",
                i+1,v->type,v->severity,v->url,v->parameter,v->payload,v->evidence);
    }
    fclose(f); return 0;
}

int export_txt(AppState *app, const wchar_t *path) {
    FILE *f=_wfopen(path,L"wb");
    if(!f) return -1;
    fwrite("\xEF\xBB\xBF",1,3,f);

    time_t now = time(NULL);
    char ts[64]; strftime(ts, 63, "%Y-%m-%d %H:%M:%S", localtime(&now));
    const char *url = app->scan_target[0] ? app->scan_target
                   : (app->scan_params && app->scan_params->url[0]
                      ? app->scan_params->url : "N/A");

    fprintf(f, "ScanXSS v1.3.3 — Scan Report\n");
    fprintf(f, "==============================\n");
    fprintf(f, "Target:      %s\n", url);
    fprintf(f, "Generated:   %s\n", ts);
    fprintf(f, "Vulns found: %d\n\n", app->vuln_count);

    if (app->vuln_count == 0) {
        fprintf(f, "No vulnerabilities found.\n");
    } else {
        for (int i = 0; i < app->vuln_count; i++) {
            const VulnRecord *v = &app->vulns[i];
            fprintf(f, "[%d] %s  Severity:%d\n", i+1, v->type, v->severity);
            fprintf(f, "    URL:   %s\n", v->url);
            fprintf(f, "    Param: %s\n", v->parameter);
            fprintf(f, "    Payload: %s\n", v->payload);
            fprintf(f, "    Evidence: %s\n\n", v->evidence);
        }
    }
    fprintf(f, "\n© 2026 root_bsd | GPL-2.0\n");
    fclose(f);
    return 0;
}
