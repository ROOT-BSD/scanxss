/* export.c — HTML/JSON/CSV report export */
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
    FILE *f=_wfopen(path,L"w,ccs=UTF-8");
    if(!f) return -1;
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
    fprintf(f,"<header><h1>🔍 ScanXSS — Звіт вразливостей</h1>"
              "<p>Згенеровано: %s</p></header>\n",ts);
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
    fprintf(f,"</div>\n<footer>ScanXSS v1.3.0 | Web Vulnerability Scanner | GPL-2.0</footer>"
              "\n</body></html>\n");
    fclose(f);
    return 0;
}

static void json_esc_f(FILE *f, const char *s) {
    for(;*s;s++) switch(*s){
        case '"':  fputs("\\\"",f); break;
        case '\\': fputs("\\\\",f); break;
        case '\n': fputs("\\n",f);  break;
        case '\r': fputs("\\r",f);  break;
        default: if((unsigned char)*s<0x20) fprintf(f,"\\u%04x",(unsigned char)*s);
                 else fputc(*s,f);
    }
}

int export_json(AppState *app, const wchar_t *path) {
    FILE *f=_wfopen(path,L"w,ccs=UTF-8");
    if(!f) return -1;
    fprintf(f,"{\n  \"scanner\": \"ScanXSS 1.3.0\",\n");
    fprintf(f,"  \"vuln_count\": %d,\n", app->vuln_count);
    fprintf(f,"  \"vulnerabilities\": [\n");
    for(int i=0;i<app->vuln_count;i++) {
        const VulnRecord *v=&app->vulns[i];
        fprintf(f,"    {\n");
        fprintf(f,"      \"type\": \""); json_esc_f(f,v->type); fprintf(f,"\",\n");
        fprintf(f,"      \"severity\": %d,\n", v->severity);
        fprintf(f,"      \"module\": \""); json_esc_f(f,v->module); fprintf(f,"\",\n");
        fprintf(f,"      \"url\": \""); json_esc_f(f,v->url); fprintf(f,"\",\n");
        fprintf(f,"      \"parameter\": \""); json_esc_f(f,v->parameter); fprintf(f,"\",\n");
        fprintf(f,"      \"payload\": \""); json_esc_f(f,v->payload); fprintf(f,"\",\n");
        fprintf(f,"      \"evidence\": \""); json_esc_f(f,v->evidence); fprintf(f,"\"\n");
        fprintf(f,"    }%s\n", i<app->vuln_count-1?",":"");
    }
    fprintf(f,"  ]\n}\n");
    fclose(f); return 0;
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
