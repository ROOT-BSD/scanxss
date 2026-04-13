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

#ifndef SCANXSS_WIN_H
#define SCANXSS_WIN_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "../vendor/sqlite3.h"

/* ── Version ─────────────────────────────────────────────── */
#define APP_NAME     L"ScanXSS"
#define APP_VERSION  L"1.3.1"
#define APP_TITLE    L"ScanXSS v1.3.1 — Web Vulnerability Scanner"
#define APP_CLASS    L"ScanXSSMainWnd"

/* ── Window / Control IDs ─────────────────────────────────── */
#define IDI_APPICON     101
#define IDM_FILE_EXPORT 201
#define IDM_FILE_EXIT   202
#define IDM_SCAN_START  203
#define IDM_SCAN_STOP   204
#define IDM_DB_HISTORY  205
#define IDM_HELP_ABOUT  206

#define ID_EDIT_URL       1001
#define ID_EDIT_DEPTH     1002
#define ID_EDIT_RATE      1003
#define ID_EDIT_TIMEOUT   1004
#define ID_EDIT_COOKIES   1005
#define ID_EDIT_USERAGENT 1006
#define ID_COMBO_SCOPE    1007
#define ID_COMBO_FORMAT   1008
#define ID_BTN_SCAN       1009
#define ID_BTN_STOP       1010
#define ID_BTN_EXPORT     1011
#define ID_BTN_CLEAR      1012
#define ID_BTN_HISTORY    1013
#define ID_CHECK_XSS      1020
#define ID_CHECK_SQLI     1021
#define ID_CHECK_LFI      1022
#define ID_CHECK_RCE      1023
#define ID_CHECK_SSRF     1024
#define ID_CHECK_REDIR    1025
#define ID_CHECK_CRLF     1026
#define ID_LIST_VULNS     1030
#define ID_RICH_LOG       1031
#define ID_PROGRESS       1032
#define ID_STATUS_BAR     1033
#define ID_LABEL_STATS    1060
#define ID_TAB_MAIN       1061

/* ── Thread message codes ─────────────────────────────────── */
#define WM_SCAN_LOG     (WM_USER + 100)
#define WM_SCAN_VULN    (WM_USER + 101)
#define WM_SCAN_DONE    (WM_USER + 102)
#define WM_SCAN_PROGRESS (WM_USER + 103)

/* ── Severity colours ─────────────────────────────────────── */
#define COL_CRITICAL  RGB(220, 38,  38)
#define COL_HIGH      RGB(234,179,  8)
#define COL_MEDIUM    RGB(245,158, 11)
#define COL_LOW       RGB( 59,130,246)
#define COL_INFO      RGB(107,114,128)

/* ── Limits ───────────────────────────────────────────────── */
#define MAX_URL      2048
#define MAX_LOG_CHARS (1024*1024)   /* 1 MB log buffer */
#define MAX_VULNS_UI 4096

/* ── Vulnerability record ─────────────────────────────────── */
typedef struct {
    int      severity;
    char     module[32];
    char     type[64];
    char     url[MAX_URL];
    char     parameter[256];
    char     payload[256];
    char     evidence[512];
    time_t   found_at;
    bool     confirmed;
} VulnRecord;

/* ── Scan params (passed to worker thread) ────────────────── */
typedef struct {
    HWND     hwnd;
    char     url[MAX_URL];
    int      depth;
    int      rate;
    int      timeout;
    char     cookies[1024];
    char     user_agent[512];
    char     scope[32];
    unsigned modules;          /* bitmask */
    char     db_path[512];
    bool     stop_requested;
} ScanParams;

/* ── App state ────────────────────────────────────────────── */
typedef struct {
    HWND     hwnd_main;
    HWND     hwnd_log;
    HWND     hwnd_list;
    HWND     hwnd_progress;
    HWND     hwnd_blocks[20];   /* green progress blocks */
    int      block_count;
    HWND     hwnd_status;
    HWND     hwnd_tab;
    HFONT    font_ui;
    HFONT    font_mono;
    HICON    icon;
    sqlite3 *db;
    char     db_path[512];
    VulnRecord vulns[MAX_VULNS_UI];
    int      vuln_count;
    int      scan_count;
    bool     scanning;
    HANDLE   scan_thread;
    ScanParams *scan_params;
    char      scan_target[2048]; /* URL of current/last scan */
    HIMAGELIST img_list;
} AppState;

/* ── Function prototypes ──────────────────────────────────── */
/* gui.c */
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void    gui_log(AppState *app, const wchar_t *text, COLORREF color);
void    gui_log_a(AppState *app, const char *text, COLORREF color);
void    gui_add_vuln(AppState *app, const VulnRecord *v);
void    gui_set_status(AppState *app, const wchar_t *text);
void    gui_set_scanning(AppState *app, bool scanning);
void    gui_clear(AppState *app);

/* scanner.c */
DWORD WINAPI scan_thread(LPVOID param);

/* db.c */
int  db_open(AppState *app);
void db_close(AppState *app);
int  db_save_vuln(AppState *app, const VulnRecord *v, const char *target, int scan_id);
int  db_new_scan(AppState *app, const char *target);
void db_finish_scan(AppState *app, int scan_id, int vuln_count);
void db_show_history(HWND parent, AppState *app);

/* export.c */
int  export_html(AppState *app, const wchar_t *path);
int  export_txt (AppState *app, const wchar_t *path);
int  export_csv(AppState *app, const wchar_t *path);

#endif /* SCANXSS_WIN_H */
