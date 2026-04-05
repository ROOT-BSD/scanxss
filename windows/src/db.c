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

static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "CREATE TABLE IF NOT EXISTS targets("
    "  id INTEGER PRIMARY KEY, url TEXT UNIQUE, first_seen INTEGER);"\
    "CREATE TABLE IF NOT EXISTS scans("
    "  id INTEGER PRIMARY KEY, target_id INTEGER, started_at INTEGER,"
    "  finished_at INTEGER, vuln_count INTEGER DEFAULT 0, status TEXT DEFAULT 'running');"\
    "CREATE TABLE IF NOT EXISTS findings("
    "  id INTEGER PRIMARY KEY, scan_id INTEGER, type TEXT, severity INTEGER,"
    "  url TEXT, parameter TEXT, payload TEXT, evidence TEXT, module TEXT,"
    "  found_at INTEGER);";

int db_open(AppState *app) {
    if (sqlite3_open(app->db_path, (sqlite3**)&app->db) != SQLITE_OK) return -1;
    char *err=NULL;
    sqlite3_exec((sqlite3*)app->db, SCHEMA, NULL, NULL, &err);
    sqlite3_free(err);
    return 0;
}

void db_close(AppState *app) {
    if (app->db) { sqlite3_close((sqlite3*)app->db); app->db=NULL; }
}

int db_new_scan(AppState *app, const char *target) {
    if (!app->db) return 0;
    sqlite3 *db=(sqlite3*)app->db;
    sqlite3_stmt *s;
    /* upsert target */
    sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO targets(url,first_seen) VALUES(?,strftime('%s','now'))",-1,&s,NULL);
    sqlite3_bind_text(s,1,target,-1,SQLITE_STATIC);
    sqlite3_step(s); sqlite3_finalize(s);
    /* get target id */
    sqlite3_prepare_v2(db,"SELECT id FROM targets WHERE url=?",-1,&s,NULL);
    sqlite3_bind_text(s,1,target,-1,SQLITE_STATIC);
    int tid=0;
    if(sqlite3_step(s)==SQLITE_ROW) tid=sqlite3_column_int(s,0);
    sqlite3_finalize(s);
    /* new scan */
    sqlite3_prepare_v2(db,"INSERT INTO scans(target_id,started_at) VALUES(?,strftime('%s','now'))",-1,&s,NULL);
    sqlite3_bind_int(s,1,tid);
    sqlite3_step(s); sqlite3_finalize(s);
    app->scan_count=(int)sqlite3_last_insert_rowid(db);
    return app->scan_count;
}

void db_finish_scan(AppState *app, int scan_id, int vuln_count) {
    if(!app->db) return;
    sqlite3_stmt *s;
    sqlite3_prepare_v2((sqlite3*)app->db,
        "UPDATE scans SET finished_at=strftime('%s','now'),vuln_count=?,status='done' WHERE id=?",
        -1,&s,NULL);
    sqlite3_bind_int(s,1,vuln_count);
    sqlite3_bind_int(s,2,scan_id);
    sqlite3_step(s); sqlite3_finalize(s);
}

int db_save_vuln(AppState *app, const VulnRecord *v,
                  const char *target, int scan_id) {
    if(!app->db) return 0;
    if(!scan_id) { db_new_scan(app,target); scan_id=app->scan_count; }
    sqlite3_stmt *s;
    sqlite3_prepare_v2((sqlite3*)app->db,
        "INSERT INTO findings(scan_id,type,severity,url,parameter,payload,evidence,module,found_at)"
        " VALUES(?,?,?,?,?,?,?,?,strftime('%s','now'))",-1,&s,NULL);
    sqlite3_bind_int (s,1,scan_id);
    sqlite3_bind_text(s,2,v->type,-1,SQLITE_STATIC);
    sqlite3_bind_int (s,3,v->severity);
    sqlite3_bind_text(s,4,v->url,-1,SQLITE_STATIC);
    sqlite3_bind_text(s,5,v->parameter,-1,SQLITE_STATIC);
    sqlite3_bind_text(s,6,v->payload,-1,SQLITE_STATIC);
    sqlite3_bind_text(s,7,v->evidence,-1,SQLITE_STATIC);
    sqlite3_bind_text(s,8,v->module,-1,SQLITE_STATIC);
    sqlite3_step(s); sqlite3_finalize(s);
    return 0;
}

/* History dialog */
static INT_PTR CALLBACK HistoryDlgProc(HWND h,UINT m,WPARAM w,LPARAM l) {
    if(m==WM_INITDIALOG) {
        AppState *app=(AppState*)l;
        SetWindowLongPtrW(h,DWLP_USER,(LONG_PTR)app);
        SetWindowTextW(h,L"Scan History");
        /* list */
        HWND lv=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,NULL,
            WS_CHILD|WS_VISIBLE|LVS_REPORT|0x0020,
            8,8,680,400,h,(HMENU)1001,NULL,NULL);
        ListView_SetExtendedListViewStyle(lv,0x00000020|0x00000001);
        LVCOLUMNW c={0}; c.mask=LVCF_TEXT|LVCF_WIDTH;
        const wchar_t *cols[]=
            {L"ID",L"Target",L"Started",L"Vulns",L"Status",NULL};
        int ws[]={40,300,150,60,80};
        for(int i=0;cols[i];i++){c.pszText=(wchar_t*)cols[i];c.cx=ws[i];
            ListView_InsertColumn(lv,i,&c);}
        /* fill from DB */
        if(app->db) {
            sqlite3_stmt *s;
            sqlite3_prepare_v2((sqlite3*)app->db,
                "SELECT s.id,t.url,datetime(s.started_at,'unixepoch'),s.vuln_count,s.status"
                " FROM scans s JOIN targets t ON t.id=s.target_id"
                " ORDER BY s.id DESC LIMIT 100",-1,&s,NULL);
            int idx=0;
            while(sqlite3_step(s)==SQLITE_ROW) {
                LVITEMW li={0}; li.mask=LVIF_TEXT; li.iItem=idx;
                wchar_t num[8]; _snwprintf(num,7,L"%d",sqlite3_column_int(s,0));
                li.pszText=num; ListView_InsertItem(lv,&li);
                const char *cols2[]={(const char*)sqlite3_column_text(s,1),
                    (const char*)sqlite3_column_text(s,2),NULL,
                    (const char*)sqlite3_column_text(s,4)};
                for(int c2=0;c2<4;c2++){
                    wchar_t w2[512]={0};
                    if(c2==2){_snwprintf(w2,31,L"%d",sqlite3_column_int(s,3));}
                    else if(cols2[c2]) MultiByteToWideChar(CP_UTF8,0,cols2[c2],-1,w2,511);
                    ListView_SetItemText(lv,idx,c2+1,w2);
                }
                idx++;
            }
            sqlite3_finalize(s);
        }
        CreateWindowW(L"BUTTON",L"Close",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            300,420,80,28,h,(HMENU)IDOK,NULL,NULL);
        return TRUE;
    }
    if(m==WM_COMMAND && LOWORD(w)==IDOK) EndDialog(h,0);
    if(m==WM_CLOSE) EndDialog(h,0);
    return FALSE;
}

void db_show_history(HWND parent, AppState *app) {
    /* Create modeless dialog manually */
    HWND dlg=CreateWindowExW(WS_EX_DLGMODALFRAME|WS_EX_TOPMOST,
        L"#32770",L"Scan History",
        WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_CENTER,
        100,100,710,480,parent,NULL,NULL,NULL);
    if(!dlg) return;
    HistoryDlgProc(dlg,WM_INITDIALOG,0,(LPARAM)app);
    ShowWindow(dlg,SW_SHOW);
    MSG msg;
    while(IsWindow(dlg) && GetMessageW(&msg,NULL,0,0)) {
        if(!IsDialogMessageW(dlg,&msg)) {
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
    }
}
