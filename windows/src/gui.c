/*
 * Copyright (c) 2025 root_bsd (mglushak@gmail.com)
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
 * SPDX-License-Identifier: GPL-2.0
 */

#include "scanxss_win.h"
#include <richedit.h>

/* ── Colours (Windows 11 light theme) ────────────────────── */
#define BG_MAIN     RGB(249,250,251)
#define BG_PANEL    RGB(255,255,255)
#define BG_HEADER   RGB( 30, 58,138)   /* deep blue header */
#define BG_LOG      RGB( 15, 23, 42)   /* dark log */
#define FG_LOG      RGB(226,232,240)
#define FG_HEADER   RGB(255,255,255)
#define COL_ACCENT  RGB( 59,130,246)
#define COL_BORDER  RGB(229,231,235)
#define COL_SCAN_BTN RGB(22,163, 74)   /* green */
#define COL_STOP_BTN RGB(220, 38, 38)  /* red */

static AppState g_app;

/* ── Subclass proc for rounded button paint ───────────────── */
static WNDPROC g_orig_btn_proc = NULL;
static LRESULT CALLBACK BtnSubclass(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        int id = GetDlgCtrlID(h);
        COLORREF bg = (id == ID_BTN_SCAN)  ? COL_SCAN_BTN :
                      (id == ID_BTN_STOP)  ? COL_STOP_BTN :
                                             COL_ACCENT;
        bool pressed = (SendMessage(h, BM_GETSTATE, 0, 0) & BST_PUSHED);
        if (pressed) bg = RGB(GetRValue(bg)-20, GetGValue(bg)-20, GetBValue(bg)-20);

        HBRUSH br = CreateSolidBrush(bg);
        FillRect(dc, &rc, br);
        DeleteObject(br);

        /* rounded rect */
        HPEN pen = CreatePen(PS_NULL, 0, 0);
        HPEN old = SelectObject(dc, pen);
        SelectObject(dc, br);
        RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, 10, 10);
        SelectObject(dc, old);
        DeleteObject(pen);

        /* text */
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(255,255,255));
        SelectObject(dc, g_app.font_ui);
        wchar_t txt[64]; GetWindowTextW(h, txt, 63);
        DrawTextW(dc, txt, -1, &rc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        EndPaint(h, &ps);
        return 0;
    }
    return CallWindowProc(g_orig_btn_proc, h, msg, w, l);
}

/* ── Create fonts ─────────────────────────────────────────── */
static void create_fonts(AppState *app) {
    app->font_ui = CreateFontW(
        -16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    app->font_mono = CreateFontW(
        -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH | FF_MODERN, L"Cascadia Mono");
    if (!app->font_mono)
        app->font_mono = CreateFontW(
            -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            FIXED_PITCH | FF_MODERN, L"Consolas");
}

/* ── Helper: create labelled edit control ─────────────────── */
static HWND make_label(HWND par, HFONT f, const wchar_t *txt,
                        int x, int y, int w) {
    HWND h = CreateWindowW(L"STATIC", txt,
        WS_CHILD|WS_VISIBLE|SS_LEFT,
        x, y, w, 18, par, NULL, NULL, NULL);
    SendMessage(h, WM_SETFONT, (WPARAM)f, TRUE);
    return h;
}

static HWND make_edit(HWND par, HFONT f, int id,
                       const wchar_t *def, int x, int y, int w, int h) {
    HWND ctrl = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", def,
        WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
        x, y, w, h, par, (HMENU)(intptr_t)id, NULL, NULL);
    SendMessage(ctrl, WM_SETFONT, (WPARAM)f, TRUE);
    return ctrl;
}

static HWND make_check(HWND par, HFONT f, const wchar_t *txt,
                        int id, int x, int y, bool checked) {
    HWND h = CreateWindowW(L"BUTTON", txt,
        WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,
        x, y, 80, 20, par, (HMENU)(intptr_t)id, NULL, NULL);
    SendMessage(h, WM_SETFONT, (WPARAM)f, TRUE);
    SendMessage(h, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    return h;
}

static HWND make_btn(HWND par, HFONT f, const wchar_t *txt,
                      int id, int x, int y, int w, int h) {
    HWND btn = CreateWindowW(L"BUTTON", txt,
        WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,
        x, y, w, h, par, (HMENU)(intptr_t)id, NULL, NULL);
    SendMessage(btn, WM_SETFONT, (WPARAM)f, TRUE);
    return btn;
}

/* ── Build the main window layout ────────────────────────── */
static void build_ui(HWND hwnd) {
    AppState *app = &g_app;
    HFONT f  = app->font_ui;
    HINSTANCE hi = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

    /* ── Left panel: Scan Config ── */
    /* DPI-aware coordinate scaling */
    UINT dpi = GetDpiForWindow(hwnd);
    if (!dpi) dpi = 96;
#define S(x) MulDiv((x), dpi, 96)

    int px = S(12), py = S(66);
    int pw = S(306);

    /* URL */
    make_label(hwnd, f, L"Target URL:", px, py, pw); py += S(18);
    make_edit(hwnd, f, ID_EDIT_URL, L"https://", px, py, pw, S(24)); py += S(30);

    /* Depth / Rate / Timeout */
    make_label(hwnd, f, L"Depth:", px,        py, S(78));
    make_label(hwnd, f, L"Rate/s:", px+S(86), py, S(78));
    make_label(hwnd, f, L"Timeout:", px+S(172),py, S(78)); py += S(16);
    make_edit(hwnd, f, ID_EDIT_DEPTH,   L"3",  px,        py, S(78), S(24));
    make_edit(hwnd, f, ID_EDIT_RATE,    L"10", px+S(86),  py, S(78), S(24));
    make_edit(hwnd, f, ID_EDIT_TIMEOUT, L"15", px+S(172), py, S(78), S(24)); py += S(30);

    /* Scope */
    make_label(hwnd, f, L"Scope:", px, py, pw); py += S(16);
    HWND scope = CreateWindowW(L"COMBOBOX", NULL,
        WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST,
        px, py, S(220), S(160), hwnd, (HMENU)ID_COMBO_SCOPE, hi, NULL);
    SendMessage(scope, WM_SETFONT, (WPARAM)f, TRUE);
    SendMessageW(scope, CB_ADDSTRING, 0, (LPARAM)L"subdomain (recommended)");
    SendMessageW(scope, CB_ADDSTRING, 0, (LPARAM)L"domain");
    SendMessageW(scope, CB_ADDSTRING, 0, (LPARAM)L"folder");
    SendMessageW(scope, CB_ADDSTRING, 0, (LPARAM)L"url");
    SendMessage(scope, CB_SETCURSEL, 0, 0);
    py += S(30);

    /* Cookies */
    make_label(hwnd, f, L"Cookies (optional):", px, py, pw); py += S(16);
    make_edit(hwnd, f, ID_EDIT_COOKIES, L"", px, py, pw, S(24)); py += S(30);

    /* User-Agent */
    make_label(hwnd, f, L"User-Agent:", px, py, pw); py += S(16);
    make_edit(hwnd, f, ID_EDIT_USERAGENT,
              L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
              px, py, pw, S(24)); py += S(30);

    /* Attack modules */
    make_label(hwnd, f, L"Attack Modules:", px, py, pw); py += S(20);
    make_check(hwnd, f, L"XSS",      ID_CHECK_XSS,   px,        py, true);
    make_check(hwnd, f, L"SQLi",     ID_CHECK_SQLI,  px+S(82),  py, true);
    make_check(hwnd, f, L"LFI",      ID_CHECK_LFI,   px+S(164), py, true);
    py += S(22);
    make_check(hwnd, f, L"RCE",      ID_CHECK_RCE,   px,        py, true);
    make_check(hwnd, f, L"SSRF",     ID_CHECK_SSRF,  px+S(82),  py, true);
    make_check(hwnd, f, L"Redirect", ID_CHECK_REDIR, px+S(164), py, false);
    py += S(22);
    make_check(hwnd, f, L"CRLF",     ID_CHECK_CRLF,  px,        py, false);
    py += S(26);

    /* ── Buttons ── always visible at bottom of config panel ── */
    make_btn(hwnd, f, L"▶ Start", ID_BTN_SCAN, px,          py, S(140), S(36));
    make_btn(hwnd, f, L"■ Stop",  ID_BTN_STOP, px+S(146),   py, S(76),  S(36));
    py += S(42);
    make_btn(hwnd, f, L"Export",  ID_BTN_EXPORT,  px,        py, S(92), S(28));
    make_btn(hwnd, f, L"History", ID_BTN_HISTORY, px+S(98),  py, S(92), S(28));
    make_btn(hwnd, f, L"Clear",   ID_BTN_CLEAR,   px+S(196), py, S(78), S(28));

    /* subclass the coloured buttons */
    HWND hScan = GetDlgItem(hwnd, ID_BTN_SCAN);
    HWND hStop = GetDlgItem(hwnd, ID_BTN_STOP);
    g_orig_btn_proc = (WNDPROC)SetWindowLongPtrW(hScan, GWLP_WNDPROC,
                                                  (LONG_PTR)BtnSubclass);
    SetWindowLongPtrW(hStop, GWLP_WNDPROC, (LONG_PTR)BtnSubclass);

    /* ── Right: Tab control ── */
    int tx = S(330), ty = S(66);
    int tw = S(860), th_tab = S(30);

    /* Progress bar */
    HWND prog = CreateWindowExW(0, PROGRESS_CLASS, NULL,
        WS_CHILD|WS_VISIBLE|PBS_SMOOTH|PBS_SMOOTHREVERSE,
        tx, ty, tw, S(8), hwnd, (HMENU)ID_PROGRESS, hi, NULL);
    SendMessage(prog, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessage(prog, PBM_SETPOS, 0, 0);
    app->hwnd_progress = prog;

    ty += S(14);

    /* Stats label */
    HWND stats = CreateWindowW(L"STATIC", L"Готово до сканування",
        WS_CHILD|WS_VISIBLE|SS_LEFT,
        tx, ty, tw, S(20), hwnd, (HMENU)ID_LABEL_STATS, hi, NULL);
    SendMessage(stats, WM_SETFONT, (WPARAM)f, TRUE);
    ty += S(24);

    /* Tab control */
    HWND tab = CreateWindowExW(0, WC_TABCONTROLW, NULL,
        WS_CHILD|WS_VISIBLE|WS_TABSTOP|TCS_FLATBUTTONS,
        tx, ty, tw, th_tab, hwnd, (HMENU)ID_TAB_MAIN, hi, NULL);
    SendMessage(tab, WM_SETFONT, (WPARAM)f, TRUE);
    TCITEMW ti = {0}; ti.mask = TCIF_TEXT;
    ti.pszText = L"  Vulnerabilities  "; TabCtrl_InsertItem(tab, 0, &ti);
    ti.pszText = L"  Scan Log  ";        TabCtrl_InsertItem(tab, 1, &ti);
    app->hwnd_tab = tab;
    ty += th_tab + S(4);

    /* panel height = fill remaining window space */
    RECT cr; GetClientRect(hwnd, &cr);
    int panel_h = cr.bottom - ty - S(28); /* 28 = status bar */
    if (panel_h < S(200)) panel_h = S(200);

    /* Vulnerabilities list */
    HWND list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
        WS_CHILD|WS_VISIBLE|LVS_REPORT|0x0020|
        0x0010|0x0004,
        tx, ty, tw, panel_h,
        hwnd, (HMENU)ID_LIST_VULNS, hi, NULL);
    SendMessage(list, WM_SETFONT, (WPARAM)f, TRUE);
    ListView_SetExtendedListViewStyle(list,
        0x00000020|0x00000001|0x00010000);

    /* columns */
    LVCOLUMNW lvc = {0}; lvc.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_FMT;
    const wchar_t *cols[] = {L"#", L"Severity", L"Type",
                              L"URL", L"Parameter", L"Payload", NULL};
    int widths[]           = {36, 90, 180, 280, 120, 140};
    for (int i = 0; cols[i]; i++) {
        lvc.pszText = (wchar_t *)cols[i]; lvc.cx = widths[i];
        lvc.fmt = (i == 0) ? LVCFMT_CENTER : LVCFMT_LEFT;
        ListView_InsertColumn(list, i, &lvc);
    }
    app->hwnd_list = list;

    /* Log panel (RichEdit) */
    LoadLibraryW(L"Msftedit.dll");
    HWND log_wnd = CreateWindowExW(WS_EX_CLIENTEDGE,
        L"RICHEDIT50W", NULL,
        WS_CHILD|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL,
        tx, ty, tw, panel_h,
        hwnd, (HMENU)ID_RICH_LOG, hi, NULL);
    SendMessage(log_wnd, WM_SETFONT, (WPARAM)app->font_mono, TRUE);
    SendMessage(log_wnd, EM_SETBKGNDCOLOR, 0, (LPARAM)BG_LOG);
    app->hwnd_log = log_wnd;
    ShowWindow(log_wnd, SW_HIDE);

    /* Status bar */
    HWND sb = CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready",
        WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP,
        0, 0, 0, 0, hwnd, (HMENU)ID_STATUS_BAR, hi, NULL);
    SendMessage(sb, WM_SETFONT, (WPARAM)f, TRUE);
    int parts[] = {300, 600, -1};
    SendMessage(sb, SB_SETPARTS, 3, (LPARAM)parts);
    app->hwnd_status = sb;

    /* Set initial state */
    EnableWindow(GetDlgItem(hwnd, ID_BTN_STOP), FALSE);
    db_open(app);
}

/* ── Log a coloured line to the RichEdit ─────────────────── */
void gui_log(AppState *app, const wchar_t *text, COLORREF color) {
    if (!app->hwnd_log) return;
    CHARFORMAT2W cf = {0};
    cf.cbSize    = sizeof(cf);
    cf.dwMask    = CFM_COLOR|CFM_FACE|CFM_SIZE;
    cf.crTextColor = color;
    cf.yHeight   = 200; /* 10pt */
    wcscpy(cf.szFaceName, L"Consolas");

    /* move to end */
    GETTEXTLENGTHEX tl = {GTL_DEFAULT, 1200};
    long len = SendMessage(app->hwnd_log, EM_GETTEXTLENGTHEX,
                           (WPARAM)&tl, 0);
    SendMessage(app->hwnd_log, EM_SETSEL, len, len);
    SendMessage(app->hwnd_log, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

    /* append */
    wchar_t line[4096];
    /* timestamp */
    SYSTEMTIME st; GetLocalTime(&st);
    _snwprintf(line, 4095, L"[%02d:%02d:%02d] %s\r\n",
               st.wHour, st.wMinute, st.wSecond, text);
    SendMessage(app->hwnd_log, EM_REPLACESEL, FALSE, (LPARAM)line);
    SendMessage(app->hwnd_log, WM_VSCROLL, SB_BOTTOM, 0);
}

void gui_log_a(AppState *app, const char *text, COLORREF color) {
    wchar_t w[2048] = {0};
    MultiByteToWideChar(CP_UTF8, 0, text, -1, w, 2047);
    gui_log(app, w, color);
}

/* ── Add vulnerability row to ListView ───────────────────── */
void gui_add_vuln(AppState *app, const VulnRecord *v) {
    if (!app->hwnd_list) return;
    int idx = ListView_GetItemCount(app->hwnd_list);

    LVITEMW li = {0};
    li.mask    = LVIF_TEXT | LVIF_PARAM;
    li.iItem   = idx;
    li.lParam  = (LPARAM)idx;

    wchar_t num[8]; _snwprintf(num, 7, L"%d", idx+1);
    li.pszText = num;
    ListView_InsertItem(app->hwnd_list, &li);

    const char *cols[] = {
        NULL, /* #0 already set */
        v->severity == 5 ? "Critical" :
        v->severity == 4 ? "High" :
        v->severity == 3 ? "Medium" :
        v->severity == 2 ? "Low" : "Info",
        v->type, v->url, v->parameter, v->payload
    };
    for (int c = 1; c <= 5; c++) {
        wchar_t w[1024] = {0};
        MultiByteToWideChar(CP_UTF8, 0, cols[c], -1, w, 1023);
        ListView_SetItemText(app->hwnd_list, idx, c, w);
    }

    /* colour row by severity */
    /* (custom draw handled in WM_NOTIFY / NM_CUSTOMDRAW) */

    /* copy to app state */
    if (app->vuln_count < MAX_VULNS_UI)
        app->vulns[app->vuln_count++] = *v;

    /* update stats label */
    wchar_t stats[256];
    _snwprintf(stats, 255,
        L"⚠ %d vulnerability(ies) found", app->vuln_count);
    SetWindowTextW(GetDlgItem(app->hwnd_main, ID_LABEL_STATS), stats);
}

/* ── Status bar helpers ───────────────────────────────────── */
void gui_set_status(AppState *app, const wchar_t *text) {
    if (app->hwnd_status)
        SendMessage(app->hwnd_status, SB_SETTEXTW, 0, (LPARAM)text);
}

void gui_set_scanning(AppState *app, bool scanning) {
    app->scanning = scanning;
    EnableWindow(GetDlgItem(app->hwnd_main, ID_BTN_SCAN), !scanning);
    EnableWindow(GetDlgItem(app->hwnd_main, ID_BTN_STOP),  scanning);
    EnableWindow(GetDlgItem(app->hwnd_main, ID_EDIT_URL),  !scanning);
    if (!scanning) {
        SendMessage(app->hwnd_progress, PBM_SETPOS, 100, 0);
        gui_set_status(app, L"Scan complete");
    } else {
        SendMessage(app->hwnd_progress, PBM_SETPOS, 0, 0);
        gui_set_status(app, L"Scanning...");
    }
}

void gui_clear(AppState *app) {
    if (app->hwnd_list) ListView_DeleteAllItems(app->hwnd_list);
    if (app->hwnd_log)  SetWindowTextW(app->hwnd_log, L"");
    app->vuln_count = 0;
    SetWindowTextW(GetDlgItem(app->hwnd_main, ID_LABEL_STATS),
                   L"Готово до сканування");
    SendMessage(app->hwnd_progress, PBM_SETPOS, 0, 0);
}

/* ── Custom draw for ListView severity colouring ────────── */
static LRESULT handle_custom_draw(HWND hwnd, LPARAM lp) {
    AppState *app = &g_app;
    LPNMLVCUSTOMDRAW pCD = (LPNMLVCUSTOMDRAW)lp;
    if (pCD->nmcd.dwDrawStage == CDDS_PREPAINT)
        return CDRF_NOTIFYITEMDRAW;
    if (pCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
        int idx = (int)pCD->nmcd.dwItemSpec;
        if (idx >= 0 && idx < app->vuln_count) {
            int sev = app->vulns[idx].severity;
            pCD->clrTextBk = (sev >= 5) ? RGB(255,241,242) :
                             (sev == 4) ? RGB(255,247,237) :
                             (sev == 3) ? RGB(255,251,235) :
                                          RGB(239,246,255);
            pCD->clrText   = (sev >= 4) ? COL_CRITICAL :
                             (sev == 3) ? COL_MEDIUM : COL_LOW;
        }
        return CDRF_NEWFONT;
    }
    return CDRF_DODEFAULT;
}

/* ── Tab switching ────────────────────────────────────────── */
static void switch_tab(AppState *app, int tab) {
    if (tab == 0) {
        ShowWindow(app->hwnd_list, SW_SHOW);
        ShowWindow(app->hwnd_log,  SW_HIDE);
    } else {
        ShowWindow(app->hwnd_list, SW_HIDE);
        ShowWindow(app->hwnd_log,  SW_SHOW);
    }
}

/* ── Draw header banner ───────────────────────────────────── */
static void paint_header(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc = {0, 0, 1400, 62};
    HBRUSH br = CreateSolidBrush(BG_HEADER);
    FillRect(dc, &rc, br);
    DeleteObject(br);

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255,255,255));

    /* title */
    HFONT big = CreateFontW(-22,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_SWISS,L"Segoe UI Semibold");
    HFONT old = SelectObject(dc, big);
    RECT tr = {16, 12, 600, 40};
    DrawTextW(dc, L"🔍 ScanXSS", -1, &tr, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, old);
    DeleteObject(big);

    HFONT sm = CreateFontW(-13,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_SWISS,L"Segoe UI");
    SelectObject(dc, sm);
    SetTextColor(dc, RGB(180,200,255));
    RECT sr = {16, 38, 600, 58};
    DrawTextW(dc, L"Web Vulnerability Scanner v1.3.0", -1, &sr,
              DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, old);
    DeleteObject(sm);

    EndPaint(hwnd, &ps);
}

/* ── Build ScanParams from UI ────────────────────────────── */
static ScanParams *collect_params(HWND hwnd) {
    ScanParams *p = calloc(1, sizeof(ScanParams));
    p->hwnd = hwnd;

    wchar_t buf[MAX_URL];
    GetDlgItemTextW(hwnd, ID_EDIT_URL, buf, MAX_URL-1);
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, p->url, MAX_URL-1, NULL, NULL);

    GetDlgItemTextW(hwnd, ID_EDIT_DEPTH, buf, 7);
    p->depth   = _wtoi(buf);
    GetDlgItemTextW(hwnd, ID_EDIT_RATE, buf, 7);
    p->rate    = _wtoi(buf);
    GetDlgItemTextW(hwnd, ID_EDIT_TIMEOUT, buf, 7);
    p->timeout = _wtoi(buf);

    GetDlgItemTextW(hwnd, ID_EDIT_COOKIES, buf, 1023);
    WideCharToMultiByte(CP_UTF8,0,buf,-1,p->cookies,1023,NULL,NULL);

    GetDlgItemTextW(hwnd, ID_EDIT_USERAGENT, buf, 511);
    WideCharToMultiByte(CP_UTF8,0,buf,-1,p->user_agent,511,NULL,NULL);

    int sel = SendDlgItemMessage(hwnd, ID_COMBO_SCOPE, CB_GETCURSEL, 0, 0);
    const char *scopes[] = {"subdomain","domain","folder","url"};
    strncpy(p->scope, scopes[sel < 4 ? sel : 0], 31);

    if (SendDlgItemMessage(hwnd, ID_CHECK_XSS,  BM_GETCHECK,0,0)) p->modules |= 0x01;
    if (SendDlgItemMessage(hwnd, ID_CHECK_SQLI, BM_GETCHECK,0,0)) p->modules |= 0x02;
    if (SendDlgItemMessage(hwnd, ID_CHECK_LFI,  BM_GETCHECK,0,0)) p->modules |= 0x04;
    if (SendDlgItemMessage(hwnd, ID_CHECK_RCE,  BM_GETCHECK,0,0)) p->modules |= 0x08;
    if (SendDlgItemMessage(hwnd, ID_CHECK_SSRF, BM_GETCHECK,0,0)) p->modules |= 0x10;
    if (SendDlgItemMessage(hwnd, ID_CHECK_REDIR,BM_GETCHECK,0,0)) p->modules |= 0x20;
    if (SendDlgItemMessage(hwnd, ID_CHECK_CRLF, BM_GETCHECK,0,0)) p->modules |= 0x40;
    if (!p->modules) p->modules = 0xFF;

    snprintf(p->db_path, sizeof(p->db_path), "%s", g_app.db_path);
    if (!p->depth)   p->depth   = 3;
    if (!p->rate)    p->rate    = 10;
    if (!p->timeout) p->timeout = 15;

    return p;
}

/* ── Export dialog ───────────────────────────────────────── */
static void do_export(HWND hwnd) {
    wchar_t path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = hwnd;
    ofn.lpstrFilter  = L"HTML Report\0*.html\0JSON Report\0*.json\0CSV\0*.csv\0";
    ofn.lpstrFile    = path;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrDefExt  = L"html";
    ofn.Flags        = OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;

    int rc = -1;
    if (ofn.nFilterIndex == 2)      rc = export_json(&g_app, path);
    else if (ofn.nFilterIndex == 3) rc = export_csv(&g_app, path);
    else                             rc = export_html(&g_app, path);

    if (rc == 0) {
        wchar_t msg[MAX_PATH + 64];
        _snwprintf(msg, MAX_PATH+63, L"Report saved:\n%s", path);
        MessageBoxW(hwnd, msg, L"Export OK", MB_OK|MB_ICONINFORMATION);
        ShellExecuteW(hwnd, L"open", path, NULL, NULL, SW_SHOWNORMAL);
    } else {
        MessageBoxW(hwnd, L"Export failed.", L"Error", MB_OK|MB_ICONERROR);
    }
}

/* ── Main Window Procedure ───────────────────────────────── */
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    AppState *app = &g_app;

    switch (msg) {
    case WM_CREATE:
        app->hwnd_main = hwnd;
        create_fonts(app);
        build_ui(hwnd);
        return 0;

    case WM_PAINT:
        paint_header(hwnd);
        return 0;

    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BTN_SCAN:
        case IDM_SCAN_START:
            if (!app->scanning) {
                if (!GetDlgItemTextW(hwnd, ID_EDIT_URL, (wchar_t[16]){0}, 8)) {
                    MessageBoxW(hwnd, L"Enter target URL.", L"ScanXSS", MB_OK|MB_ICONWARNING);
                    break;
                }
                gui_clear(app);
                app->scan_params = collect_params(hwnd);
                app->scan_params->stop_requested = false;
                app->scan_thread = CreateThread(NULL, 0, scan_thread,
                                                app->scan_params, 0, NULL);
                gui_set_scanning(app, true);
                gui_log(app, L"Scan started...", RGB(100,200,100));
                /* switch to log tab */
                TabCtrl_SetCurSel(app->hwnd_tab, 1);
                switch_tab(app, 1);
            }
            break;

        case ID_BTN_STOP:
        case IDM_SCAN_STOP:
            if (app->scanning && app->scan_params)
                app->scan_params->stop_requested = true;
            break;

        case ID_BTN_EXPORT:
        case IDM_FILE_EXPORT:
            do_export(hwnd);
            break;

        case ID_BTN_HISTORY:
        case IDM_DB_HISTORY:
            db_show_history(hwnd, app);
            break;

        case ID_BTN_CLEAR:
            gui_clear(app);
            break;

        case IDM_FILE_EXIT:
            PostMessage(hwnd, WM_CLOSE, 0, 0);
            break;

        case IDM_HELP_ABOUT:
            MessageBoxW(hwnd,
                L"ScanXSS v1.3.0\n"
                L"Web Vulnerability Scanner\n\n"
                L"Modules: XSS, SQLi, LFI, RCE, SSRF,\n"
                L"Open Redirect, CRLF Injection\n\n"
                L"GPL-2.0 License",
                L"About ScanXSS", MB_OK|MB_ICONINFORMATION);
            break;
        }
        return 0;

    case WM_NOTIFY: {
        NMHDR *hdr = (NMHDR *)lp;
        if (hdr->idFrom == ID_LIST_VULNS &&
            hdr->code   == NM_CUSTOMDRAW)
            return handle_custom_draw(hwnd, lp);
        if (hdr->idFrom == ID_TAB_MAIN &&
            hdr->code   == TCN_SELCHANGE)
            switch_tab(app, TabCtrl_GetCurSel(app->hwnd_tab));
        return 0;
    }

    case WM_SCAN_LOG: {
        COLORREF col = (COLORREF)wp;
        char    *txt = (char *)lp;
        gui_log_a(app, txt, col);
        free(txt);
        return 0;
    }

    case WM_SCAN_VULN: {
        VulnRecord *v = (VulnRecord *)lp;
        gui_add_vuln(app, v);
        db_save_vuln(app, v, app->scan_params ? app->scan_params->url : "",
                     app->scan_count);
        free(v);
        /* switch to vulns tab if it's first find */
        if (app->vuln_count == 1) {
            TabCtrl_SetCurSel(app->hwnd_tab, 0);
            switch_tab(app, 0);
        }
        return 0;
    }

    case WM_SCAN_PROGRESS: {
        int pct = (int)wp;
        SendMessage(app->hwnd_progress, PBM_SETPOS, pct, 0);
        return 0;
    }

    case WM_SCAN_DONE:
        gui_set_scanning(app, false);
        CloseHandle(app->scan_thread);
        app->scan_thread = NULL;
        db_finish_scan(app, app->scan_count, app->vuln_count);
        {
            wchar_t msg[128];
            _snwprintf(msg, 127,
                L"Scan complete. Found: %d vulnerability(ies).",
                app->vuln_count);
            gui_log(app, msg,
                    app->vuln_count > 0 ? COL_CRITICAL : RGB(100,200,100));
            gui_set_status(app, msg);
        }
        free(app->scan_params);
        app->scan_params = NULL;
        return 0;

    case WM_SIZE: {
        /* reflow status bar */
        if (app->hwnd_status)
            SendMessage(app->hwnd_status, WM_SIZE, 0, 0);
        return 0;
    }

    case WM_DESTROY:
        db_close(app);
        DeleteObject(app->font_ui);
        DeleteObject(app->font_mono);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ── WinMain ─────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hi, HINSTANCE hpi, LPSTR cmd, int show) {
    (void)hpi; (void)cmd;

    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_WIN95_CLASSES|ICC_LISTVIEW_CLASSES|ICC_TAB_CLASSES|ICC_BAR_CLASSES};
    InitCommonControlsEx(&icc);

    /* DPI awareness */
    typedef BOOL (WINAPI *SetDpiAware_t)(void);
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    if (u32) {
        SetDpiAware_t fn = (SetDpiAware_t)GetProcAddress(u32,"SetProcessDPIAware");
        if (fn) fn();
    }

    memset(&g_app, 0, sizeof(g_app));

    /* DB path: same dir as exe */
    wchar_t exepath[MAX_PATH];
    GetModuleFileNameW(NULL, exepath, MAX_PATH);
    wchar_t *sl = wcsrchr(exepath, L'\\');
    if (sl) *(sl+1) = L'\0';
    WideCharToMultiByte(CP_UTF8, 0, exepath, -1,
                        g_app.db_path, 511, NULL, NULL);
    strncat(g_app.db_path, "scan.db", 511 - strlen(g_app.db_path));

    /* Register window class */
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(BG_MAIN);
    wc.lpszClassName = APP_CLASS;
    wc.hIcon         = LoadIcon(hi, MAKEINTRESOURCE(IDI_APPICON));
    wc.hIconSm       = wc.hIcon;
    RegisterClassExW(&wc);

    /* Create menu */
    HMENU menu = CreateMenu();
    HMENU mFile = CreatePopupMenu();
    AppendMenuW(mFile, MF_STRING, IDM_FILE_EXPORT, L"Export Report\tCtrl+S");
    AppendMenuW(mFile, MF_SEPARATOR, 0, NULL);
    AppendMenuW(mFile, MF_STRING, IDM_FILE_EXIT,   L"Exit\tAlt+F4");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)mFile, L"File");

    HMENU mScan = CreatePopupMenu();
    AppendMenuW(mScan, MF_STRING, IDM_SCAN_START,  L"Start Scan\tF5");
    AppendMenuW(mScan, MF_STRING, IDM_SCAN_STOP,   L"Stop\tF6");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)mScan, L"Scan");

    HMENU mDB = CreatePopupMenu();
    AppendMenuW(mDB, MF_STRING, IDM_DB_HISTORY, L"Scan History");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)mDB, L"Database");

    HMENU mHelp = CreatePopupMenu();
    AppendMenuW(mHelp, MF_STRING, IDM_HELP_ABOUT, L"About");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)mHelp, L"Help");

    /* Create window */
    HWND hwnd = CreateWindowExW(0, APP_CLASS, APP_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1220, 780,
        NULL, menu, hi, NULL);
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    /* Message loop with accelerators */
    ACCEL accel[] = {
        {FVIRTKEY,        VK_F5,  IDM_SCAN_START},
        {FVIRTKEY,        VK_F6,  IDM_SCAN_STOP},
        {FVIRTKEY|FCONTROL, 'S',  IDM_FILE_EXPORT},
    };
    HACCEL hAccel = CreateAcceleratorTableW(accel, 3);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!TranslateAcceleratorW(hwnd, hAccel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    DestroyAcceleratorTable(hAccel);
    return (int)msg.wParam;
}
