/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * ScanXSS macOS GUI — AppDelegate.m
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 */
#import "AppDelegate.h"
#import <objc/runtime.h>

// ── Colors ────────────────────────────────────────────────
#define RGB(r,g,b) [NSColor colorWithRed:(r)/255.0 green:(g)/255.0 blue:(b)/255.0 alpha:1.0]
#define BG_DARK    [NSColor blackColor]
#define BG_PANEL   RGB(18,18,18)
#define BG_INPUT   RGB(30,30,30)
#define COL_GREEN  RGB(0,255,100)
#define COL_RED    RGB(255,80,80)
#define COL_YELLOW RGB(255,210,0)
#define COL_CYAN   RGB(0,210,255)
#define COL_WHITE  [NSColor whiteColor]
#define COL_GRAY   RGB(150,150,150)
#define COL_BLUE   RGB(60,140,255)
#define COL_ORANGE RGB(255,160,50)
#define COL_BORDER RGB(50,50,50)

// ══════════════════════════════════════════════════════════
// ScanHistoryHelper — DataSource + Delegate для NSTableView
// ══════════════════════════════════════════════════════════
@interface ScanHistoryHelper : NSObject
    <NSTableViewDataSource, NSTableViewDelegate>
- (instancetype)initWithData:(NSArray<NSDictionary *>*)data
                       table:(NSTableView *)table
                  detailText:(NSTextField *)detail
                    onSelect:(void(^)(NSInteger))onSelect;
- (void)updateData:(NSArray<NSDictionary *>*)data;
@end

@implementation ScanHistoryHelper {
    NSArray<NSDictionary *> *_data;
    NSTableView             *_table;
    NSTextField             *_detail;
    void (^_onSelect)(NSInteger);
    NSFont *_mono;
    NSFont *_ui;
}

- (instancetype)initWithData:(NSArray<NSDictionary *>*)data
                       table:(NSTableView *)table
                  detailText:(NSTextField *)detail
                    onSelect:(void(^)(NSInteger))onSelect {
    self = [super init];
    _data     = data;
    _table    = table;
    _detail   = detail;
    _onSelect = [onSelect copy];
    _mono = [NSFont fontWithName:@"Menlo" size:14] ?:
            [NSFont monospacedSystemFontOfSize:14 weight:NSFontWeightRegular];
    _ui   = [NSFont systemFontOfSize:15];
    return self;
}

- (void)updateData:(NSArray<NSDictionary *>*)data { _data = data; }

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tv { return (NSInteger)_data.count; }

- (id)tableView:(NSTableView *)tv objectValueForTableColumn:(NSTableColumn *)col row:(NSInteger)row {
    if (row < 0 || row >= (NSInteger)_data.count) return @"";
    return _data[row][col.identifier] ?: @"";
}

- (NSView *)tableView:(NSTableView *)tv viewForTableColumn:(NSTableColumn *)col row:(NSInteger)row {
    if (row < 0 || row >= (NSInteger)_data.count) return nil;
    NSDictionary *scan = _data[row];
    NSString *val = scan[col.identifier] ?: @"";
    NSTextField *cell = [tv makeViewWithIdentifier:@"cell" owner:self];
    if (!cell) {
        cell = [[NSTextField alloc] initWithFrame:NSZeroRect];
        cell.identifier = @"cell";
        cell.editable = NO; cell.bezeled = NO; cell.drawsBackground = NO;
        cell.font = _ui;
    }
    cell.stringValue = val;
    NSColor *col_white  = [NSColor whiteColor];
    NSColor *col_gray   = [NSColor colorWithRed:.6 green:.6 blue:.6 alpha:1];
    NSColor *col_green  = [NSColor colorWithRed:0 green:.9 blue:.35 alpha:1];
    NSColor *col_red    = [NSColor colorWithRed:1 green:.3 blue:.3 alpha:1];
    NSColor *col_yellow = [NSColor colorWithRed:1 green:.82 blue:0 alpha:1];
    NSColor *col_cyan   = [NSColor colorWithRed:0 green:.82 blue:1 alpha:1];
    if ([col.identifier isEqual:@"id"])             cell.textColor = col_cyan;
    else if ([col.identifier isEqual:@"status"]) {
        if ([val isEqual:@"done"])          cell.textColor = col_green;
        else if ([val isEqual:@"running"])  cell.textColor = col_yellow;
        else                                cell.textColor = col_gray;
    } else if ([col.identifier isEqual:@"vulns"])
        cell.textColor = val.intValue > 0 ? col_red : col_green;
    else if ([col.identifier isEqual:@"mode"])      cell.textColor = col_yellow;
    else if ([col.identifier isEqual:@"started"])   cell.textColor = col_gray;
    else                                            cell.textColor = col_white;
    return cell;
}

- (void)tableViewSelectionDidChange:(NSNotification *)n {
    NSInteger row = _table.selectedRow;
    if (_onSelect) _onSelect(row);
    if (row < 0 || row >= (NSInteger)_data.count) {
        _detail.stringValue = @"  \u2190 Оберіть сканування";
        return;
    }
    NSDictionary *s = _data[row];
    int vulns = [s[@"vulns"] intValue];
    _detail.stringValue = [NSString stringWithFormat:
        @"  Scan #%@   режим: %@   статус: %@   urls: %@   forms: %@   запитів: %@\n"
        @"  %@\n  Початок: %@",
        s[@"id"], s[@"mode"], s[@"status"], s[@"urls"], s[@"forms"], s[@"reqs"],
        vulns > 0
            ? [NSString stringWithFormat:@"\u26a0  %d ВРАЗЛИВОСТЕЙ ЗНАЙДЕНО!", vulns]
            : @"\u2705  Вразливостей не знайдено",
        s[@"started"]];
    _detail.textColor = vulns > 0
        ? [NSColor colorWithRed:1 green:.3 blue:.3 alpha:1]
        : [NSColor colorWithRed:.6 green:.6 blue:.6 alpha:1];
}
@end

// ══════════════════════════════════════════════════════════
// ButtonBlockTarget
// ══════════════════════════════════════════════════════════
@interface ButtonBlockTarget : NSObject
- (void)registerBlock:(void(^)(void))block forButton:(NSButton *)btn;
- (IBAction)invoke:(id)sender;
@end
@implementation ButtonBlockTarget {
    NSMutableDictionary<NSValue *, void(^)(void)> *_map;
}
- (instancetype)init { self = [super init]; _map = [NSMutableDictionary dictionary]; return self; }
- (void)registerBlock:(void(^)(void))block forButton:(NSButton *)btn {
    if (block && btn) _map[[NSValue valueWithNonretainedObject:btn]] = [block copy];
}
- (IBAction)invoke:(id)sender {
    void(^b)(void) = _map[[NSValue valueWithNonretainedObject:sender]];
    if (b) b();
}
@end

@implementation AppDelegate {
    NSFont *_mono;
    NSFont *_ui;
    NSFont *_label;
    BOOL    _scanning;
    BOOL    _reportOpened;
    NSView *_progressBlocksView;
}

- (void)applicationDidFinishLaunching:(NSNotification *)n {
    _mono  = [NSFont fontWithName:@"Menlo" size:15] ?:
             [NSFont monospacedSystemFontOfSize:15 weight:NSFontWeightRegular];
    _ui    = [NSFont systemFontOfSize:16];
    _label = [NSFont systemFontOfSize:13 weight:NSFontWeightMedium];
    [self buildMenuBar];
    [self buildWindow];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)a { return YES; }

// ══════════════════════════════════════════════════════════
// MENU BAR
// ══════════════════════════════════════════════════════════
- (void)buildMenuBar {
    NSMenu *menuBar = [[NSMenu alloc] init];
    [NSApp setMainMenu:menuBar];

    // ── App menu (ScanXSS) ────────────────────────────────
    NSMenuItem *appItem = [[NSMenuItem alloc] init];
    [menuBar addItem:appItem];
    NSMenu *appMenu = [[NSMenu alloc] init];
    appItem.submenu = appMenu;
    [appMenu addItemWithTitle:@"Про ScanXSS"
                       action:@selector(orderFrontStandardAboutPanel:)
                keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"Приховати ScanXSS"
                       action:@selector(hide:)
                keyEquivalent:@"h"];
    [appMenu addItemWithTitle:@"Показати всі"
                       action:@selector(unhideAllApplications:)
                keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quit = [appMenu addItemWithTitle:@"Вийти із ScanXSS"
                                          action:@selector(terminate:)
                                   keyEquivalent:@"q"];
    quit.target = NSApp;

    // ── Scan menu ─────────────────────────────────────────
    NSMenuItem *scanItem = [[NSMenuItem alloc] init];
    [menuBar addItem:scanItem];
    NSMenu *scanMenu = [[NSMenu alloc] initWithTitle:@"Сканування"];
    scanItem.submenu = scanMenu;

    NSMenuItem *startItem = [scanMenu addItemWithTitle:@"▶  Почати сканування"
                                                action:@selector(startScan:)
                                         keyEquivalent:@"r"];
    startItem.target = self;
    startItem.keyEquivalentModifierMask = NSEventModifierFlagCommand;

    NSMenuItem *stopItem = [scanMenu addItemWithTitle:@"■  Зупинити"
                                               action:@selector(stopScan:)
                                        keyEquivalent:@"."];
    stopItem.target = self;
    stopItem.keyEquivalentModifierMask = NSEventModifierFlagCommand;

    [scanMenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *historyItem = [scanMenu addItemWithTitle:@"🗄  Історія сканувань..."
                                                  action:@selector(showScanHistory:)
                                           keyEquivalent:@"h"];
    historyItem.target = self;
    historyItem.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagShift;

    [scanMenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *reportItem = [scanMenu addItemWithTitle:@"📄  Відкрити звіт"
                                                 action:@selector(openReport:)
                                          keyEquivalent:@"o"];
    reportItem.target = self;

    // ── Payloads menu ─────────────────────────────────────
    NSMenuItem *plItem = [[NSMenuItem alloc] init];
    [menuBar addItem:plItem];
    NSMenu *plMenu = [[NSMenu alloc] initWithTitle:@"Payload-и"];
    plItem.submenu = plMenu;

    /* Головний пункт — оновити з усіх джерел */
    NSMenuItem *dlAll = [plMenu addItemWithTitle:@"⬇  Завантажити payload-и (всі джерела)"
                                          action:@selector(downloadPayloads:)
                                   keyEquivalent:@"u"];
    dlAll.target = self;
    dlAll.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagShift;
    dlAll.tag = 0;  /* tag 0 = всі джерела */

    [plMenu addItem:[NSMenuItem separatorItem]];
    [plMenu addItemWithTitle:@"Джерела:" action:nil keyEquivalent:@""].enabled = NO;

    /* Вибіркові джерела */
    struct { NSString *title; int tag; } sources[] = {
        { @"  PayloadsAllTheThings", 1 },
        { @"  SecLists",             2 },
        { @"  NVD CVE Feed",         3 },
    };
    for (int i = 0; i < 3; i++) {
        NSMenuItem *item = [plMenu addItemWithTitle:sources[i].title
                                            action:@selector(downloadPayloadsSource:)
                                     keyEquivalent:@""];
        item.target = self;
        item.tag    = sources[i].tag;
    }

    [plMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *statsItem = [plMenu addItemWithTitle:@"📊  Статистика бази"
                                              action:@selector(showPayloadsStats:)
                                       keyEquivalent:@""];
    statsItem.target = self;

    // ── Window menu ───────────────────────────────────────
    NSMenuItem *winItem = [[NSMenuItem alloc] init];
    [menuBar addItem:winItem];
    NSMenu *winMenu = [[NSMenu alloc] initWithTitle:@"Вікно"];
    winItem.submenu = winMenu;
    [NSApp setWindowsMenu:winMenu];
    [winMenu addItemWithTitle:@"Звернути"
                       action:@selector(performMiniaturize:)
                keyEquivalent:@"m"];
    [winMenu addItemWithTitle:@"На передній план"
                       action:@selector(makeKeyAndOrderFront:)
                keyEquivalent:@""];
}

// ══════════════════════════════════════════════════════════
// BUILD WINDOW
// ══════════════════════════════════════════════════════════
- (void)buildWindow {
    // Use autolayout-friendly approach: build from bottom up
    NSRect fr = NSMakeRect(0,0,1100,720);
    self.window = [[NSWindow alloc]
        initWithContentRect:fr
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|
                  NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    self.window.title      = @"ScanXSS v1.3.3";
    self.window.minSize    = NSMakeSize(900,600);
    self.window.backgroundColor = [NSColor blackColor];
    [self.window center];

    NSView *cv = self.window.contentView;
    CGFloat W = fr.size.width;
    CGFloat H = fr.size.height;
    CGFloat PW = 320;   // left panel width

    // ── Header (top) ──────────────────────────────────────
    CGFloat HDR = 50;
    NSView *hdr = [[NSView alloc] initWithFrame:NSMakeRect(0, H-HDR, W, HDR)];
    hdr.wantsLayer = YES;
    hdr.layer.backgroundColor = RGB(10,10,10).CGColor;
    hdr.autoresizingMask = NSViewWidthSizable|NSViewMinYMargin;

    // Left: logo
    NSTextField *logo = [self mkLabel:NSMakeRect(14,10,180,30)
        text:@"🔍  ScanXSS"
        font:[NSFont systemFontOfSize:22 weight:NSFontWeightBold]
        color:COL_WHITE parent:hdr];
    (void)logo;

    // Center: subtitle
    NSTextField *sub = [self mkLabel:NSMakeRect(200,16,340,18)
        text:@"Web Vulnerability Scanner v1.3.3"
        font:[NSFont systemFontOfSize:14] color:COL_GRAY parent:hdr];
    (void)sub;

    // Right: copyright
    NSTextField *cpr = [self mkLabel:NSMakeRect(W-420,16,410,18)
        text:@"© 2026 root_bsd <root_bsd@itprof.net.ua>"
        font:[NSFont systemFontOfSize:13] color:COL_GRAY parent:hdr];
    cpr.alignment = NSTextAlignmentRight;
    cpr.autoresizingMask = NSViewMinXMargin;
    [cv addSubview:hdr];

    // ── Left panel — plain view, no scroll ───────────────
    CGFloat PH = H - HDR;
    NSView *panel = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, PW, PH)];
    panel.wantsLayer = YES;
    panel.layer.backgroundColor = [NSColor blackColor].CGColor;
    panel.autoresizingMask = NSViewMaxXMargin|NSViewHeightSizable;
    [cv addSubview:panel];

    // CV_H matches panel height so coords stay consistent
    CGFloat CV_H = PH;

    // ── Fixed pixel layout from TOP to BOTTOM ──────────
    // All Y coordinates are absolute from bottom of CV_H=780
    // Row heights are fixed so nothing overlaps.
    CGFloat PX = 14;
    CGFloat FW = PW - PX*2;   // 292

    // Row positions (Y = bottom edge of control)
    // Working from top (760) downward with fixed steps:
    // Label = 14px, Input = 30px, gap = 10px between rows

    // ── URL ──────────────────────────────────────────────
    [self secLabel:@"TARGET URL" x:PX y:618 parent:panel];
    self.urlField = [self mkInput:NSMakeRect(PX,582,FW,24)
        ph:@"https://example.com/" parent:panel];

    // ── Depth / Rate / Timeout ───────────────────────────
    /* Single row: Depth + Rate + Timeout with correct labels */
    CGFloat EW = (FW-16)/3;
    [self secLabel:@"DEPTH"   x:PX            y:560 parent:panel];
    [self secLabel:@"RATE/s"  x:PX+EW+8       y:560 parent:panel];
    [self secLabel:@"TIMEOUT" x:PX+EW*2+16    y:560 parent:panel];
    self.depthField   = [self mkInput:NSMakeRect(PX,          524,EW,26) ph:@"3"  parent:panel];
    self.rateField    = [self mkInput:NSMakeRect(PX+EW+8,     524,EW,26) ph:@"10" parent:panel];
    self.timeoutField = [self mkInput:NSMakeRect(PX+EW*2+16,  524,EW,26) ph:@"15" parent:panel];

    // ── Scan Mode ─────────────────────────────────────────
    [self secLabel:@"РЕЖИМ СКАНУВАННЯ" x:PX y:498 parent:panel];
    self.scanModePopup=[[NSPopUpButton alloc]initWithFrame:NSMakeRect(PX,468,FW,28)];
    [self.scanModePopup addItemsWithTitles:@[
        @"🔍  Full — повне сканування",
        @"🔄  Rescan — повторна атака",
        @"⏩  Resume — продовжити",
        @"🎯  Retarget — перевірка виправлень"]];
    self.scanModePopup.font=_ui;
    self.scanModePopup.appearance=[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    [panel addSubview:self.scanModePopup];

    // ── Scope ─────────────────────────────────────────────
    [self secLabel:@"SCOPE" x:PX y:436 parent:panel];
    self.scopePopup = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(PX,406,FW,28)];
    [self.scopePopup addItemsWithTitles:@[
        @"subdomain (рекомендовано)", @"domain", @"folder", @"url"]];
    self.scopePopup.font = _ui;
    self.scopePopup.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    [panel addSubview:self.scopePopup];

    // ── Cookies ───────────────────────────────────────────
    [self secLabel:@"COOKIES (опційно)" x:PX y:382 parent:panel];
    self.cookiesField = [self mkInput:NSMakeRect(PX,356,FW,24)
        ph:@"session=abc; csrf=xyz" parent:panel];

    // ── Attack Modules ────────────────────────────────────
    [self secLabel:@"ATTACK MODULES" x:PX y:330 parent:panel];
    NSArray *mods  = @[@"XSS",@"SQLi",@"LFI",@"RCE",@"SSRF",@"Redirect",@"CRLF"];
    BOOL     defs[]= {YES,   YES,     YES,   YES,   YES,    NO,          NO};
    NSMutableArray *cbs = [NSMutableArray array];
    CGFloat cbW = (FW-8)/2;
    for (int i=0;i<7;i++) {
        int c=i%2, r=i/2;
        NSButton *cb=[self mkCheck:NSMakeRect(PX+c*(cbW+8), 308-r*28, cbW, 26)
            title:mods[i] parent:panel];
        cb.state=defs[i]?NSControlStateValueOn:NSControlStateValueOff;
        [cbs addObject:cb];
    }
    self.chkXSS=cbs[0]; self.chkSQLi=cbs[1]; self.chkLFI=cbs[2];
    self.chkRCE=cbs[3]; self.chkSSRF=cbs[4];
    self.chkRedirect=cbs[5]; self.chkCRLF=cbs[6];

    // ── Scan / Stop buttons ───────────────────────────────
    CGFloat btnY = 162;
    self.scanButton=[self mkBtn:NSMakeRect(PX,btnY,FW*0.62,42)
        title:@"▶  Start Scan" sel:@selector(startScan:)
        bg:COL_BLUE fg:COL_WHITE parent:panel];
    self.stopButton=[self mkBtn:NSMakeRect(PX+FW*0.62+8,btnY,FW*0.38-8,42)
        title:@"■  Stop" sel:@selector(stopScan:)
        bg:RGB(55,65,81) fg:COL_WHITE parent:panel];
    self.stopButton.enabled=NO;

    // ── Open Report button ────────────────────────────────
    self.reportButton=[self mkBtn:NSMakeRect(PX,118,FW,34)
        title:@"📄  Open Report" sel:@selector(openReport:)
        bg:RGB(4,120,87) fg:COL_WHITE parent:panel];
    self.reportButton.enabled=NO;

    // ── Progress bar — custom green blocks ───────────────
    [self secLabel:@"PROGRESS" x:PX y:96 parent:panel];
    /* Container — dark track */
    NSView *progTrack=[[NSView alloc]initWithFrame:NSMakeRect(PX,72,FW,16)];
    progTrack.wantsLayer=YES;
    progTrack.layer.backgroundColor=RGB(20,20,20).CGColor;
    progTrack.layer.cornerRadius=4;
    progTrack.layer.borderColor=RGB(50,50,50).CGColor;
    progTrack.layer.borderWidth=1;
    [panel addSubview:progTrack];
    /* Custom progress using NSProgressIndicator (hidden) for value tracking */
    self.progress=[[NSProgressIndicator alloc]initWithFrame:NSMakeRect(PX,72,FW,16)];
    self.progress.style=NSProgressIndicatorStyleBar;
    self.progress.indeterminate=NO;
    self.progress.minValue=0; self.progress.maxValue=100;
    self.progress.doubleValue=0;
    self.progress.hidden=YES; /* hidden — we draw blocks manually */
    [panel addSubview:self.progress];
    /* Green blocks view */
    _progressBlocksView=[[NSView alloc]initWithFrame:NSMakeRect(PX,72,FW,16)];
    _progressBlocksView.wantsLayer=YES;
    _progressBlocksView.layer.backgroundColor=[NSColor clearColor].CGColor;
    [panel addSubview:_progressBlocksView];

    // ── Status label ──────────────────────────────────────
    self.statusLabel=[self mkLabel:NSMakeRect(PX,48,FW,18)
        text:@"Готово до сканування"
        font:[NSFont systemFontOfSize:14] color:COL_GRAY parent:panel];

    // ── Divider between panels ───────────────────────────
    NSView *div = [[NSView alloc] initWithFrame:NSMakeRect(PW,0,1,PH)];
    div.wantsLayer = YES;
    div.layer.backgroundColor = RGB(40,40,40).CGColor;
    div.autoresizingMask = NSViewHeightSizable|NSViewMinXMargin;
    [cv addSubview:div];

    // ── Right panel: terminal output ─────────────────────
    self.scrollView = [[NSScrollView alloc]
        initWithFrame:NSMakeRect(PW+1, 0, W-PW-1, PH)];
    self.scrollView.hasVerticalScroller   = YES;
    self.scrollView.hasHorizontalScroller = YES;
    self.scrollView.autohidesScrollers    = YES;
    self.scrollView.autoresizingMask      = NSViewWidthSizable|NSViewHeightSizable;
    self.scrollView.wantsLayer = YES;
    self.scrollView.layer.backgroundColor = BG_DARK.CGColor;
    [cv addSubview:self.scrollView];

    self.outputView = [[NSTextView alloc]
        initWithFrame:NSMakeRect(0,0,W-PW-1,PH)];
    self.outputView.editable  = NO;
    self.outputView.selectable= YES;
    self.outputView.drawsBackground = YES;
    self.outputView.backgroundColor = [NSColor blackColor];
    self.outputView.textContainerInset = NSMakeSize(10,10);
    self.outputView.autoresizingMask = NSViewWidthSizable|NSViewHeightSizable;
    /* Disable line wrapping — terminal-style output */
    [self.outputView.textContainer setWidthTracksTextView:NO];
    [self.outputView.textContainer setContainerSize:
        NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX)];
    self.outputView.horizontallyResizable = YES;
    self.outputView.verticallyResizable   = YES;
    [self.outputView setTypingAttributes:@{
        NSForegroundColorAttributeName: COL_WHITE,
        NSFontAttributeName: _mono,
        NSBackgroundColorAttributeName: BG_DARK
    }];
    self.scrollView.documentView = self.outputView;

    [self printBanner];
}

// ── Banner ────────────────────────────────────────────────
- (void)printBanner {
    [self appendLine:@"╔══════════════════════════════════════════════════╗" color:COL_BLUE];
    [self appendLine:@"║  ScanXSS v1.3.3 — Web Vulnerability Scanner      ║" color:COL_CYAN];
    [self appendLine:@"║    © 2026 root_bsd <root_bsd@itprof.net.ua>      ║" color:COL_GRAY];
    [self appendLine:@"║                   GPL-2.0                        ║" color:COL_GRAY];
    [self appendLine:@"╚══════════════════════════════════════════════════╝" color:COL_BLUE];
    [self appendLine:@"" color:COL_GRAY];
    [self appendLine:@"  Введіть URL та натисніть ▶ Start Scan" color:COL_GRAY];
    [self appendLine:@"  Результати зберігаються в ~/.scanxss/report/" color:COL_GRAY];
    [self appendLine:@"" color:COL_GRAY];
}

// ── Start scan ────────────────────────────────────────────
- (IBAction)startScan:(id)sender {
    NSString *url = [self.urlField.stringValue
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    if (!url.length) {
        [self appendLine:@"❌  Вкажіть Target URL" color:COL_RED]; return;
    }
    NSString *bin = [self findBinary];
    if (!bin) {
        [self appendLine:@"❌  scanxss не знайдено" color:COL_RED];
        [self appendLine:@"   Запустіть: sudo bash INSTALL.sh" color:COL_YELLOW];
        return;
    }

    NSMutableArray *args = [NSMutableArray array];
    [args addObject:@"-u"]; [args addObject:url];
    NSString *d=self.depthField.stringValue, *r=self.rateField.stringValue,
             *t=self.timeoutField.stringValue, *c=self.cookiesField.stringValue;
    if (d.length){[args addObject:@"-d"];[args addObject:d];}
    if (r.length){[args addObject:@"-r"];[args addObject:r];}
    if (t.length){[args addObject:@"-t"];[args addObject:t];}
    if (c.length){[args addObject:@"-c"];[args addObject:c];}

    /* Scan mode */
    NSInteger mi=self.scanModePopup.indexOfSelectedItem;
    if(mi==1) [args addObject:@"--rescan"];
    else if(mi==2) [args addObject:@"--resume"];
    else if(mi==3) [args addObject:@"--retarget"];
    /* (mi==0 = full scan, no extra flag) */

    NSArray *sc=@[@"subdomain",@"domain",@"folder",@"url"];
    NSInteger si=self.scopePopup.indexOfSelectedItem;
    [args addObject:@"-s"]; [args addObject:sc[MIN((NSUInteger)si,3)]];

    NSMutableArray *mods=[NSMutableArray array];
    if(self.chkXSS.state)     [mods addObject:@"xss"];
    if(self.chkSQLi.state)    [mods addObject:@"sqli"];
    if(self.chkLFI.state)     [mods addObject:@"lfi"];
    if(self.chkRCE.state)     [mods addObject:@"rce"];
    if(self.chkSSRF.state)    [mods addObject:@"ssrf"];
    if(self.chkRedirect.state)[mods addObject:@"redirect"];
    if(self.chkCRLF.state)    [mods addObject:@"crlf"];
    if(mods.count){[args addObject:@"-m"];[args addObject:[mods componentsJoinedByString:@","]];}
    [args addObject:@"-v"];
    [args addObject:@"--no-browser"]; /* GUI opens report itself */

    // Clear
    [self.outputView.textStorage setAttributedString:[[NSAttributedString alloc]initWithString:@""]];
    [self printBanner];
    _reportOpened = NO;
    self.lastReportPath = nil;

    [self appendLine:[NSString stringWithFormat:@"▶  scanxss %@",
        [args componentsJoinedByString:@" "]] color:COL_CYAN];
    [self appendLine:@"──────────────────────────────────────────────────" color:COL_GRAY];

    self.scanTask = [[NSTask alloc] init];
    self.scanTask.executableURL = [NSURL fileURLWithPath:bin];
    self.scanTask.arguments = args;

    NSPipe *outP=[NSPipe pipe], *errP=[NSPipe pipe];
    self.scanTask.standardOutput=outP;
    self.scanTask.standardError=errP;

    __weak typeof(self) ws=self;
    void(^rd)(NSFileHandle*)=^(NSFileHandle *fh){
        NSData *data=fh.availableData;
        if(!data.length) return;
        NSString *s=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
        if(!s) return;
        dispatch_async(dispatch_get_main_queue(),^{ [ws processOutput:s]; });
    };
    outP.fileHandleForReading.readabilityHandler=rd;
    errP.fileHandleForReading.readabilityHandler=rd;

    self.scanTask.terminationHandler=^(NSTask *tk){
        dispatch_async(dispatch_get_main_queue(),^{ [ws scanFinished:tk.terminationStatus]; });
    };

    _scanning=YES;
    self.scanButton.enabled=NO; self.stopButton.enabled=YES;
    self.reportButton.enabled=NO;
    self.progress.indeterminate=YES; [self.progress startAnimation:nil];
    [self updateProgressBlocks:0];
    self.statusLabel.stringValue=@"⏳ Сканування...";
    self.statusLabel.textColor=COL_YELLOW;

    NSError *err=nil;
    [self.scanTask launchAndReturnError:&err];
    if(err){[self appendLine:[NSString stringWithFormat:@"❌  %@",err.localizedDescription] color:COL_RED];[self scanFinished:1];}
}

- (IBAction)stopScan:(id)sender {
    [self.scanTask terminate];
    [self appendLine:@"⏹  Зупинено" color:COL_YELLOW];
}
- (IBAction)openReport:(id)sender {
    if(self.lastReportPath)
        [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:self.lastReportPath]];
}

// ── Output processing ─────────────────────────────────────
- (void)processOutput:(NSString *)raw {
    NSString *clean=[self stripANSI:raw];
    /* Split on both \n and \r\n */
    NSMutableArray *lines=[NSMutableArray array];
    for(NSString *part in [clean componentsSeparatedByString:@"\n"]) {
        /* Handle carriage return: take only the last segment */
        NSArray *cr=[part componentsSeparatedByString:@"\r"];
        NSString *last=[cr lastObject];
        if(last) [lines addObject:last];
    }
    for(NSString *line in lines) {
        if(!line.length) continue;   /* skip truly empty lines */
        NSColor *col=COL_WHITE;
        if([line containsString:@"[XSS]"]||[line containsString:@"[SQLi]"]||
           [line containsString:@"[RCE]"]||[line containsString:@"[LFI]"]) col=COL_RED;
        else if([line containsString:@"[SSRF]"]||[line containsString:@"[REDIR]"]||
                [line containsString:@"[CRLF]"])  col=COL_ORANGE;
        else if([line containsString:@"✓ http"])  col=COL_GREEN;
        else if([line hasPrefix:@"[Crawl]"])      col=COL_GREEN;
        else if([line hasPrefix:@"[Attack]"]||[line containsString:@"Testing"]) col=COL_CYAN;
        else if([line hasPrefix:@"["])             col=COL_CYAN;
        else if([line containsString:@"⚠"]||[line containsString:@"error"]) col=COL_YELLOW;
        else if([line containsString:@"✅"]||[line containsString:@"[Done]"]) col=COL_GREEN;
        else if([line hasPrefix:@"╔"]||[line hasPrefix:@"║"]||
                [line hasPrefix:@"╚"]||[line hasPrefix:@"═"]||
                [line hasPrefix:@"─"]) col=COL_BLUE;

        // Progress updates
        if([line containsString:@"Pages:"]){
            dispatch_async(dispatch_get_main_queue(),^{
                self.progress.indeterminate=NO; self.progress.doubleValue=35;
                [self updateProgressBlocks:35];});
        } else if([line containsString:@"[Attack]"]){
            dispatch_async(dispatch_get_main_queue(),^{
                self.progress.indeterminate=NO; self.progress.doubleValue=55;
                [self updateProgressBlocks:55];});
        } else if([line containsString:@"[Done]"]||[line containsString:@"Scan complete"]){
            dispatch_async(dispatch_get_main_queue(),^{
                self.progress.indeterminate=NO; self.progress.doubleValue=100;
                [self updateProgressBlocks:100];});
        }

        /* Track report path — only capture once */
        if(!self.lastReportPath && [line containsString:@".html"]) {
            for(NSString *prefix in @[@"/Users",@"/private",@"/tmp",@"/var"]) {
                NSRange r=[line rangeOfString:prefix];
                if(r.location!=NSNotFound){
                    NSString *p=[[line substringFromIndex:r.location]
                        stringByTrimmingCharactersInSet:
                            NSCharacterSet.whitespaceAndNewlineCharacterSet];
                    /* strip trailing garbage after .html */
                    NSRange he=[p rangeOfString:@".html"];
                    if(he.location!=NSNotFound)
                        p=[p substringToIndex:he.location+5];
                    if(p.length>5) { self.lastReportPath=p; break; }
                }
            }
        }
        [self appendLine:line color:col];
    }
}

- (void)updateProgressBlocks:(double)pct {
    if (!_progressBlocksView) return;
    /* Remove old blocks */
    for (NSView *v in _progressBlocksView.subviews.copy)
        [v removeFromSuperview];

    CGFloat W = _progressBlocksView.bounds.size.width;
    CGFloat H = _progressBlocksView.bounds.size.height;
    int totalBlocks = 20;
    int gap = 2;
    CGFloat blockW = floor((W - (totalBlocks-1)*gap) / totalBlocks);
    int filled = (int)round(pct / 100.0 * totalBlocks);

    for (int i=0;i<totalBlocks;i++) {
        NSView *blk=[[NSView alloc]initWithFrame:
            NSMakeRect(i*(blockW+gap), 0, (i==totalBlocks-1 ? W-i*(blockW+gap) : blockW), H)];
        blk.wantsLayer=YES;
        blk.layer.cornerRadius=2;
        if (i < filled) {
            /* Gradient: bright green for recent, darker for old */
            float brightness = 0.55f + 0.45f*(float)i/totalBlocks;
            blk.layer.backgroundColor=
                [NSColor colorWithRed:0 green:brightness blue:0.15f*brightness alpha:1].CGColor;
        } else {
            blk.layer.backgroundColor=RGB(30,30,30).CGColor;
        }
        [_progressBlocksView addSubview:blk];
    }
}

- (void)scanFinished:(int)status {
    _scanning=NO;
    self.scanButton.enabled=YES; self.stopButton.enabled=NO;
    [self.progress stopAnimation:nil]; self.progress.indeterminate=NO;
    /* Always update progress — 100% for success/vulns, 0 for error */
    double finalPct = (status == 0 || status == 2) ? 100.0 : 0.0;
    self.progress.doubleValue = finalPct;
    [self updateProgressBlocks:finalPct];
    [self appendLine:@"──────────────────────────────────────────────────" color:COL_GRAY];
    switch(status){
        case 0:
            self.progress.doubleValue=100; [self updateProgressBlocks:100];
            [self appendLine:@"✅  Вразливостей не знайдено" color:COL_GREEN];
            self.statusLabel.stringValue=@"✅ Чисто"; self.statusLabel.textColor=COL_GREEN; break;
        case 2:
            self.progress.doubleValue=100; [self updateProgressBlocks:100];
            [self appendLine:@"🚨  Знайдено вразливості!" color:COL_RED];
            self.statusLabel.stringValue=@"🚨 Знайдено!"; self.statusLabel.textColor=COL_RED; break;
        default:
            self.progress.doubleValue=0; [self updateProgressBlocks:0];
            self.statusLabel.stringValue=@"⏹ Зупинено"; self.statusLabel.textColor=COL_GRAY; break;
    }
    // Find report
    if(!self.lastReportPath){
        NSURL *u=[NSURL URLWithString:self.urlField.stringValue];
        NSString *host=u.host?:@"";
        NSString *cmd=[NSString stringWithFormat:
            @"ls -t \"%@/Desktop/report/%@\"/*.html 2>/dev/null | head -1",
            NSHomeDirectory(), host];
        FILE *fp=popen(cmd.UTF8String,"r");
        if(fp){char buf[1024]={0};
            if(fgets(buf,sizeof(buf)-1,fp)){
                NSString *p=[[NSString stringWithUTF8String:buf]
                    stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
                if(p.length) self.lastReportPath=p;
            }
            pclose(fp);}
    }
    if(self.lastReportPath&&!_reportOpened&&status!=1){
        _reportOpened=YES;
        self.reportButton.enabled=YES;
        [self appendLine:[NSString stringWithFormat:@"📄  %@",self.lastReportPath] color:COL_CYAN];
        /* Small delay to ensure file is fully written before opening */
        NSString *rp = self.lastReportPath;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.8*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:rp]];
        });
    }
}

// ── Helpers ───────────────────────────────────────────────
- (NSString *)findBinary {
    for(NSString *p in @[
        @"/usr/local/bin/scanxss/bin/scanxss",
        [[NSBundle mainBundle].bundlePath stringByAppendingString:@"/Contents/MacOS/scanxss"],
        @"/opt/homebrew/bin/scanxss",
        @"/usr/bin/scanxss/bin/scanxss"])
        if([[NSFileManager defaultManager] isExecutableFileAtPath:p]) return p;
    return nil;
}

- (NSString *)stripANSI:(NSString *)s {
    NSRegularExpression *re=[NSRegularExpression
        regularExpressionWithPattern:@"\033\\[[0-9;]*[mKHJABCDsu]" options:0 error:nil];
    NSString *r1=[re stringByReplacingMatchesInString:s options:0
        range:NSMakeRange(0,s.length) withTemplate:@""];
    // Handle \r — keep last segment (progress bar overwrite)
    NSArray *parts=[r1 componentsSeparatedByString:@"\r"];
    NSString *last=[parts lastObject];
    return last?:r1;
}

- (void)appendLine:(NSString *)line color:(NSColor *)color {
    if(!line) line=@"";
    NSMutableParagraphStyle *ps = [[NSMutableParagraphStyle alloc] init];
    ps.lineSpacing      = 6.0;
    ps.paragraphSpacing = 2.0;
    ps.lineBreakMode    = NSLineBreakByCharWrapping;
    NSAttributedString *as=[[NSAttributedString alloc]
        initWithString:[line stringByAppendingString:@"\n"]
        attributes:@{NSForegroundColorAttributeName:color,
                     NSFontAttributeName:_mono,
                     NSBackgroundColorAttributeName:[NSColor blackColor],
                     NSParagraphStyleAttributeName:ps}];
    [self.outputView.textStorage appendAttributedString:as];
    [self.outputView scrollRangeToVisible:
        NSMakeRange(self.outputView.textStorage.length,0)];
}

// ── UI factory ────────────────────────────────────────────
- (NSTextField *)mkLabel:(NSRect)r text:(NSString *)t font:(NSFont *)f
    color:(NSColor *)c parent:(NSView *)p {
    NSTextField *tf=[[NSTextField alloc]initWithFrame:r];
    tf.editable=NO; tf.selectable=NO; tf.bezeled=NO; tf.drawsBackground=NO;
    tf.stringValue=t; tf.font=f; tf.textColor=c;
    [p addSubview:tf]; return tf;
}

- (void)secLabel:(NSString *)t x:(CGFloat)x y:(CGFloat)y parent:(NSView *)p {
    NSTextField *lbl=[self mkLabel:NSMakeRect(x,y,286,14) text:t font:_label color:RGB(180,180,180) parent:p];
    (void)lbl;
}

- (NSTextField *)mkInput:(NSRect)r ph:(NSString *)ph parent:(NSView *)p {
    NSTextField *tf=[[NSTextField alloc]initWithFrame:r];
    tf.placeholderString=ph;
    tf.font=_ui;
    tf.textColor=COL_WHITE;
    tf.drawsBackground=YES;
    /* Use a dark but clearly visible background */
    tf.backgroundColor=RGB(28,28,28);
    tf.bezeled=NO;
    tf.wantsLayer=YES;
    tf.layer.backgroundColor=RGB(28,28,28).CGColor;
    tf.layer.cornerRadius=6;
    tf.layer.borderColor=RGB(71,85,105).CGColor;
    tf.layer.borderWidth=1.5;
    /* Placeholder text — slightly lighter gray */
    NSDictionary *phAttrs=@{NSForegroundColorAttributeName:RGB(100,100,100),
                             NSFontAttributeName:_ui};
    tf.placeholderAttributedString=[[NSAttributedString alloc]
        initWithString:ph attributes:phAttrs];
    [p addSubview:tf]; return tf;
}

- (NSButton *)mkCheck:(NSRect)r title:(NSString *)t parent:(NSView *)p {
    NSButton *cb=[[NSButton alloc]initWithFrame:r];
    [cb setButtonType:NSButtonTypeSwitch];
    cb.title=t;
    cb.font=_ui;
    /* White text always; green tint when checked */
    NSMutableAttributedString *attr=[[NSMutableAttributedString alloc]
        initWithString:t attributes:@{
            NSForegroundColorAttributeName: COL_WHITE,
            NSFontAttributeName: _ui
        }];
    cb.attributedTitle=attr;
    cb.contentTintColor=COL_GREEN;
    cb.appearance=[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    [p addSubview:cb]; return cb;
}

- (NSButton *)mkBtn:(NSRect)r title:(NSString *)t sel:(SEL)s
    bg:(NSColor *)bg fg:(NSColor *)fg parent:(NSView *)p {
    NSButton *btn=[[NSButton alloc]initWithFrame:r];
    btn.bezelStyle=NSBezelStyleRounded;
    btn.title=t; btn.font=[NSFont systemFontOfSize:16 weight:NSFontWeightMedium];
    btn.target=self; btn.action=s;
    btn.wantsLayer=YES;
    btn.layer.backgroundColor=bg.CGColor;
    btn.layer.cornerRadius=8;
    btn.contentTintColor=fg;
    [p addSubview:btn]; return btn;
}

// ══════════════════════════════════════════════════════════
// DOWNLOAD PAYLOADS
// ══════════════════════════════════════════════════════════

/* Запускаємо scanxss --update [--update-source SRC] у фоні */
- (void)runUpdate:(NSString *)source {
    NSString *bin = [self findBinary];
    if (!bin) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self appendLine:@"❌  scanxss не знайдено. Запустіть: sudo bash INSTALL.sh"
                       color:COL_RED];
        });
        return;
    }

    NSMutableArray *args = [NSMutableArray arrayWithObject:@"--update"];
    if (source.length) {
        [args addObject:@"--update-source"];
        [args addObject:source];
    }

    /* Оновлюємо UI */
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.outputView.textStorage
            setAttributedString:[[NSAttributedString alloc] initWithString:@""]];
        [self printBanner];
        NSString *src = source.length ? source : @"all";
        [self appendLine:[NSString stringWithFormat:
            @"⬇  Завантаження payload-ів  (джерело: %@)", src]
                   color:COL_CYAN];
        [self appendLine:@"──────────────────────────────────────────────────"
                   color:COL_GRAY];
        self.statusLabel.stringValue = @"⬇ Завантаження payload-ів...";
        self.statusLabel.textColor   = COL_YELLOW;
        self.scanButton.enabled  = NO;
        self.progress.indeterminate = YES;
        [self.progress startAnimation:nil];
    });

    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:bin];
    task.arguments     = args;

    NSPipe *outP = [NSPipe pipe];
    NSPipe *errP = [NSPipe pipe];
    task.standardOutput = outP;
    task.standardError  = errP;

    __weak typeof(self) ws = self;
    void(^rd)(NSFileHandle *) = ^(NSFileHandle *fh) {
        NSData   *data = fh.availableData;
        if (!data.length) return;
        NSString *s = [[NSString alloc] initWithData:data
                                            encoding:NSUTF8StringEncoding];
        if (!s) return;
        dispatch_async(dispatch_get_main_queue(), ^{ [ws processOutput:s]; });
    };
    outP.fileHandleForReading.readabilityHandler = rd;
    errP.fileHandleForReading.readabilityHandler = rd;

    task.terminationHandler = ^(NSTask *tk) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [ws.progress stopAnimation:nil];
            ws.progress.indeterminate = NO;
            ws.scanButton.enabled = YES;
            if (tk.terminationStatus == 0) {
                ws.statusLabel.stringValue = @"✅ Payload-и оновлено";
                ws.statusLabel.textColor   = COL_GREEN;
                [ws appendLine:@"✅  Payload-и успішно завантажено" color:COL_GREEN];
            } else {
                ws.statusLabel.stringValue = @"⚠ Частково недоступно";
                ws.statusLabel.textColor   = COL_YELLOW;
            }
        });
    };

    NSError *err = nil;
    [task launchAndReturnError:&err];
    if (err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self appendLine:[NSString stringWithFormat:@"❌  %@",
                err.localizedDescription] color:COL_RED];
            self.progress.indeterminate = NO;
            [self.progress stopAnimation:nil];
            self.scanButton.enabled = YES;
        });
    }
}

- (IBAction)downloadPayloads:(id)sender {
    [self runUpdate:nil];   /* всі джерела */
}

- (IBAction)downloadPayloadsSource:(id)sender {
    NSMenuItem *item = (NSMenuItem *)sender;
    NSArray *sources = @[@"", @"patt", @"seclists", @"nvd"];
    NSInteger tag = item.tag;
    if (tag < 0 || tag >= (NSInteger)sources.count) tag = 0;
    [self runUpdate:sources[tag]];
}

- (IBAction)showPayloadsStats:(id)sender {
    NSString *bin = [self findBinary];
    if (!bin) {
        [self appendLine:@"❌  scanxss не знайдено" color:COL_RED]; return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [self appendLine:@"📊  Статистика payload-ів:" color:COL_CYAN];
    });
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSTask *task = [[NSTask alloc] init];
        task.executableURL = [NSURL fileURLWithPath:bin];
        task.arguments     = @[@"--payloads-stats"];
        NSPipe *outP = [NSPipe pipe];
        task.standardOutput = outP;
        task.standardError  = outP;
        NSError *err = nil;
        [task launchAndReturnError:&err];
        if (!err) {
            [task waitUntilExit];
            NSData   *data = [outP.fileHandleForReading readDataToEndOfFile];
            NSString *s    = [[NSString alloc] initWithData:data
                                                   encoding:NSUTF8StringEncoding];
            dispatch_async(dispatch_get_main_queue(), ^{
                [self processOutput:s ?: @"(немає виводу)"];
            });
        }
    });
}

// ══════════════════════════════════════════════════════════
// SCAN HISTORY — перегляд БД сканувань
// ══════════════════════════════════════════════════════════

/* Розбираємо рядки виводу --list-scans у масив словників */
- (NSArray<NSDictionary *> *)parseListScans:(NSString *)output {
    NSMutableArray *result = [NSMutableArray array];
    NSArray *lines = [output componentsSeparatedByString:@"\n"];
    for (NSString *rawLine in lines) {
        /* Прибираємо ANSI-коди */
        NSString *line = [self stripANSI:rawLine];
        line = [line stringByTrimmingCharactersInSet:
                    NSCharacterSet.whitespaceCharacterSet];
        if (!line.length) continue;
        /* Рядок даних: перше поле — число (scan_id) */
        unichar first = [line characterAtIndex:0];
        if (first < '0' || first > '9') continue;
        /* Розбиваємо по пробілах зі зжиманням */
        NSArray *parts = [[line componentsSeparatedByCharactersInSet:
                               NSCharacterSet.whitespaceCharacterSet]
                          filteredArrayUsingPredicate:
                              [NSPredicate predicateWithFormat:@"length > 0"]];
        if (parts.count < 8) continue;
        NSArray *tail = [parts subarrayWithRange:NSMakeRange(7, parts.count - 7)];
        [result addObject:@{
            @"id":      parts[0],
            @"mode":    parts[1],
            @"status":  parts[2],
            @"urls":    parts[3],
            @"forms":   parts[4],
            @"vulns":   parts[5],
            @"reqs":    parts[6],
            @"started": [tail componentsJoinedByString:@" "],
        }];
    }
    return result;
}

/* Запускаємо бінарник і повертаємо stdout+stderr */
- (NSString *)runBin:(NSString *)bin args:(NSArray *)args {
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:bin];
    task.arguments     = args;
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError  = pipe;
    NSError *err = nil;
    [task launchAndReturnError:&err];
    if (err) return nil;
    [task waitUntilExit];
    NSData *data = [pipe.fileHandleForReading readDataToEndOfFile];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
}

- (IBAction)showScanHistory:(id)sender {
    NSString *bin = [self findBinary];
    if (!bin) {
        [self appendLine:@"❌  scanxss не знайдено" color:COL_RED]; return;
    }

    /* ── Отримуємо список сканувань ── */
    NSString *url = [self.urlField.stringValue
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    /* Якщо URL не заповнено — --list-scans все одно виведе всі для даного таргету.
       Якщо БД глобальна — передаємо тимчасовий фейковий URL.               */
    NSArray *listArgs = url.length
        ? @[@"-u", url, @"--list-scans"]
        : @[@"-u", @"https://dummy.scanxss.local/", @"--list-scans"];

    NSString *raw = [self runBin:bin args:listArgs];
    NSArray<NSDictionary *> *scans = [self parseListScans:raw ?: @""];

    /* ── Панель ──────────────────────────────────────────── */
    NSWindow *panel = [[NSWindow alloc]
        initWithContentRect:NSMakeRect(0, 0, 860, 520)
        styleMask:NSWindowStyleMaskTitled    |
                  NSWindowStyleMaskClosable  |
                  NSWindowStyleMaskResizable |
                  NSWindowStyleMaskMiniaturizable
        backing:NSBackingStoreBuffered defer:NO];
    panel.title           = @"ScanXSS — Історія сканувань";
    panel.minSize         = NSMakeSize(700, 400);
    panel.backgroundColor = RGB(12, 12, 12);
    panel.appearance      = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    panel.releasedWhenClosed = NO;
    [panel center];

    NSView *cv = panel.contentView;
    CGFloat W = 860, H = 520;

    /* ── Заголовок ── */
    NSView *hdr = [[NSView alloc] initWithFrame:NSMakeRect(0, H-44, W, 44)];
    hdr.wantsLayer = YES;
    hdr.layer.backgroundColor = RGB(18, 18, 18).CGColor;
    hdr.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;

    NSTextField *title = [[NSTextField alloc] initWithFrame:NSMakeRect(14, 12, 400, 22)];
    title.editable = NO; title.bezeled = NO; title.drawsBackground = NO;
    title.stringValue = @"🗄  Історія сканувань";
    title.font = [NSFont systemFontOfSize:18 weight:NSFontWeightBold];
    title.textColor = COL_WHITE;
    [hdr addSubview:title];

    NSTextField *countLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(W-200, 12, 186, 20)];
    countLabel.editable = NO; countLabel.bezeled = NO; countLabel.drawsBackground = NO;
    countLabel.alignment = NSTextAlignmentRight;
    countLabel.stringValue = [NSString stringWithFormat:@"%lu сканування", (unsigned long)scans.count];
    countLabel.font = [NSFont systemFontOfSize:14];
    countLabel.textColor = COL_GRAY;
    countLabel.autoresizingMask = NSViewMinXMargin;
    [hdr addSubview:countLabel];
    [cv addSubview:hdr];

    /* ── Таблиця ── */
    CGFloat tableH = H - 44 - 52 - 130;  /* header + toolbar + detail */

    NSScrollView *tableScroll = [[NSScrollView alloc]
        initWithFrame:NSMakeRect(0, 52 + 130, W, tableH)];
    tableScroll.hasVerticalScroller   = YES;
    tableScroll.hasHorizontalScroller = NO;
    tableScroll.autohidesScrollers    = YES;
    tableScroll.autoresizingMask      = NSViewWidthSizable | NSViewHeightSizable;
    tableScroll.wantsLayer = YES;
    tableScroll.layer.backgroundColor = RGB(16, 16, 16).CGColor;

    NSTableView *table = [[NSTableView alloc] initWithFrame:NSZeroRect];
    table.backgroundColor = RGB(16, 16, 16);
    table.gridStyleMask   = NSTableViewSolidHorizontalGridLineMask;
    table.gridColor       = RGB(35, 35, 35);
    table.rowHeight       = 34;
    table.usesAlternatingRowBackgroundColors = NO;
    table.selectionHighlightStyle = NSTableViewSelectionHighlightStyleRegular;
    table.allowsMultipleSelection = NO;
    table.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];

    /* Колонки */
    struct { NSString *id; NSString *title; CGFloat width; } cols[] = {
        { @"id",      @"ID",       52  },
        { @"mode",    @"Режим",    90  },
        { @"status",  @"Статус",   80  },
        { @"urls",    @"URLs",     52  },
        { @"forms",   @"Forms",    52  },
        { @"vulns",   @"Vulns",    52  },
        { @"reqs",    @"Reqs",     60  },
        { @"started", @"Початок",  240 },
    };
    for (int i = 0; i < 8; i++) {
        NSTableColumn *col = [[NSTableColumn alloc] initWithIdentifier:cols[i].id];
        col.title = cols[i].title;
        col.width = cols[i].width;
        col.minWidth = 40;
        col.headerCell.textColor = COL_GRAY;
        col.headerCell.font = [NSFont systemFontOfSize:14 weight:NSFontWeightMedium];
        [table addTableColumn:col];
    }

    /* DataSource + Delegate через блоки (NSTableView through ivar) */
    /* Зберігаємо дані у ivar через associated objects */
    __block NSArray<NSDictionary *> *tableData = scans;
    __block NSInteger selectedRow = -1;

    /* ── Detail view (нижня частина) ── */
    NSView *detailView = [[NSView alloc] initWithFrame:NSMakeRect(0, 52, W, 128)];
    detailView.wantsLayer = YES;
    detailView.layer.backgroundColor = RGB(10, 10, 10).CGColor;
    detailView.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;

    NSView *detailDivider = [[NSView alloc] initWithFrame:NSMakeRect(0, 127, W, 1)];
    detailDivider.wantsLayer = YES;
    detailDivider.layer.backgroundColor = RGB(45, 45, 45).CGColor;
    detailDivider.autoresizingMask = NSViewWidthSizable;
    [detailView addSubview:detailDivider];

    NSTextField *detailText = [[NSTextField alloc] initWithFrame:NSMakeRect(14, 8, W-28, 112)];
    detailText.editable = NO; detailText.bezeled = NO; detailText.drawsBackground = NO;
    detailText.font = [NSFont fontWithName:@"Menlo" size:14] ?:
                      [NSFont monospacedSystemFontOfSize:14 weight:NSFontWeightRegular];
    detailText.textColor = COL_GRAY;
    detailText.stringValue = @"  ← Оберіть сканування для перегляду деталей";
    detailText.autoresizingMask = NSViewWidthSizable;
    [detailView addSubview:detailText];
    [cv addSubview:detailView];

    /* ── Toolbar (кнопки дій) ── */
    NSView *toolbar = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, W, 52)];
    toolbar.wantsLayer = YES;
    toolbar.layer.backgroundColor = RGB(18, 18, 18).CGColor;
    toolbar.autoresizingMask = NSViewWidthSizable;

    NSView *toolDivider = [[NSView alloc] initWithFrame:NSMakeRect(0, 51, W, 1)];
    toolDivider.wantsLayer = YES;
    toolDivider.layer.backgroundColor = RGB(45, 45, 45).CGColor;
    toolDivider.autoresizingMask = NSViewWidthSizable;
    [toolbar addSubview:toolDivider];

    /* Допоміжна функція створення кнопки */
    __weak NSView *weakToolbar = toolbar;
    NSButton *(^makeBtn)(NSString *, NSColor *, CGFloat) =
        ^NSButton *(NSString *t, NSColor *bg, CGFloat x) {
            NSButton *b = [[NSButton alloc] initWithFrame:NSMakeRect(x, 10, 140, 32)];
            b.bezelStyle = NSBezelStyleRounded;
            b.title = t;
            b.font  = [NSFont systemFontOfSize:15 weight:NSFontWeightMedium];
            b.wantsLayer = YES;
            b.layer.backgroundColor = bg.CGColor;
            b.layer.cornerRadius = 7;
            b.contentTintColor = COL_WHITE;
            b.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
            [weakToolbar addSubview:b];
            return b;
        };

    NSButton *btnOpenReport = makeBtn(@"📄  Відкрити звіт", COL_BLUE,   14);
    NSButton *btnShowDetail = makeBtn(@"🔍  Показати деталі", RGB(55,65,81), 162);
    NSButton *btnDelete     = makeBtn(@"🗑  Видалити", RGB(127,29,29),  310);
    NSButton *btnClose = makeBtn(@"✕  Закрити", RGB(80,20,20), W - 154);
    btnClose.autoresizingMask = NSViewMinXMargin;
    [toolbar addSubview:btnClose];
    NSButton *btnRefresh = makeBtn(@"🔄  Оновити", RGB(30,60,30), 458);
    [toolbar addSubview:toolDivider];
    [cv addSubview:toolbar];

    /* ── DataSource / Delegate ─────────────────────────── */
    ScanHistoryHelper *helper = [[ScanHistoryHelper alloc]
        initWithData:tableData table:table detailText:detailText
        onSelect:^(NSInteger row){ selectedRow = row; }];
    table.dataSource = (id<NSTableViewDataSource>)helper;
    table.delegate   = (id<NSTableViewDelegate>)helper;
    objc_setAssociatedObject(panel, "helper", helper,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    tableScroll.documentView = table;
    [cv addSubview:tableScroll];

    /* ── ButtonBlockTarget — прив'язує блоки до кнопок ── */
    ButtonBlockTarget *bbt = [ButtonBlockTarget new];
    objc_setAssociatedObject(panel, "bbt", bbt, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    __weak typeof(self) ws = self;

    /* Відкрити звіт */
    [bbt registerBlock:^{
        if (selectedRow < 0 || selectedRow >= (NSInteger)tableData.count) {
            [ws appendLine:@"⚠  Оберіть сканування у таблиці" color:COL_YELLOW]; return;
        }
        NSString *scanId = tableData[selectedRow][@"id"];

        /* Запитуємо шлях через --get-report <id> — виводить тільки рядок з path */
        NSString *rawPath = [[ws runBin:bin
            args:@[@"-u", url.length ? url : @"https://dummy.scanxss.local/",
                   @"--get-report", scanId]]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];

        if (rawPath.length && [[NSFileManager defaultManager] fileExistsAtPath:rawPath]) {
            [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:rawPath]];
            [ws appendLine:[NSString stringWithFormat:@"📄  Відкрито: %@", rawPath]
                     color:COL_GREEN];
        } else {
            /* Fallback: якщо звіт ще не збережено у БД (старе сканування) —
             * шукаємо найновіший .html у ~/Desktop/report/<hostname>/         */
            NSString *hostname = @"scan";
            if (url.length) {
                NSString *u = url;
                if ([u hasPrefix:@"https://"]) u = [u substringFromIndex:8];
                else if ([u hasPrefix:@"http://"]) u = [u substringFromIndex:7];
                NSRange sl = [u rangeOfString:@"/"];
                hostname = sl.location != NSNotFound
                    ? [u substringToIndex:sl.location] : u;
                if (!hostname.length) hostname = @"scan";
            }
            NSString *reportDir = [NSHomeDirectory() stringByAppendingFormat:
                @"/Desktop/report/%@", hostname];
            NSArray *files = [[NSFileManager defaultManager]
                contentsOfDirectoryAtPath:reportDir error:nil];
            NSArray *htmlFiles = [[files filteredArrayUsingPredicate:
                [NSPredicate predicateWithFormat:@"self ENDSWITH '.html'"]]
                sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b){
                    NSDictionary *atA = [[NSFileManager defaultManager]
                        attributesOfItemAtPath:[reportDir stringByAppendingPathComponent:a]
                        error:nil];
                    NSDictionary *atB = [[NSFileManager defaultManager]
                        attributesOfItemAtPath:[reportDir stringByAppendingPathComponent:b]
                        error:nil];
                    return [atB[NSFileModificationDate] compare:atA[NSFileModificationDate]];
                }];

            if (htmlFiles.count) {
                NSString *p = [reportDir stringByAppendingPathComponent:htmlFiles[0]];
                [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:p]];
                [ws appendLine:[NSString stringWithFormat:@"📄  Відкрито (fallback): %@", p]
                         color:COL_YELLOW];
            } else {
                [ws appendLine:[NSString stringWithFormat:
                    @"⚠  Звіт для scan #%@ не знайдено.\n"
                     "   Звіт генерується тільки після завершення сканування.", scanId]
                         color:COL_YELLOW];
            }
        }
    } forButton:btnOpenReport];

    /* Показати деталі */
    [bbt registerBlock:^{
        if (selectedRow < 0 || selectedRow >= (NSInteger)tableData.count) {
            [ws appendLine:@"⚠  Оберіть сканування у таблиці" color:COL_YELLOW]; return;
        }
        NSString *scanId = tableData[selectedRow][@"id"];
        NSString *detail = [ws runBin:bin
            args:@[@"-u", url.length ? url : @"https://dummy.scanxss.local/",
                   @"--show-scan", scanId]];
        dispatch_async(dispatch_get_main_queue(), ^{
            [ws appendLine:[NSString stringWithFormat:
                @"──── Scan #%@ деталі ────", scanId] color:COL_CYAN];
            [ws processOutput:detail ?: @"(немає виводу)"];
        });
    } forButton:btnShowDetail];

    /* Видалити */
    [bbt registerBlock:^{
        if (selectedRow < 0 || selectedRow >= (NSInteger)tableData.count) {
            [ws appendLine:@"⚠  Оберіть сканування у таблиці" color:COL_YELLOW]; return;
        }
        NSString *scanId = tableData[selectedRow][@"id"];
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText     = [NSString stringWithFormat:@"Видалити scan #%@?", scanId];
        alert.informativeText = @"Цю дію неможливо скасувати.";
        alert.alertStyle      = NSAlertStyleWarning;
        [alert addButtonWithTitle:@"Видалити"];
        [alert addButtonWithTitle:@"Скасувати"];
        if ([alert runModal] == NSAlertFirstButtonReturn) {
            [ws runBin:bin args:@[@"-u",
                url.length ? url : @"https://dummy.scanxss.local/",
                @"--delete-scan", scanId]];
            NSString *newRaw = [ws runBin:bin args:listArgs];
            tableData = [ws parseListScans:newRaw ?: @""];
            [helper updateData:tableData];
            [table reloadData];
            selectedRow = -1;
            detailText.stringValue = @"  \u2190 Оберіть сканування";
            countLabel.stringValue = [NSString stringWithFormat:
                @"%lu сканування", (unsigned long)tableData.count];
            [ws appendLine:[NSString stringWithFormat:
                @"🗑  Scan #%@ видалено", scanId] color:COL_YELLOW];
        }
    } forButton:btnDelete];

    /* Закрити */
    [bbt registerBlock:^{
        [panel close];
    } forButton:btnClose];

    /* Оновити */
    [bbt registerBlock:^{
        NSString *newRaw = [ws runBin:bin args:listArgs];
        tableData = [ws parseListScans:newRaw ?: @""];
        [helper updateData:tableData];
        [table reloadData];
        selectedRow = -1;
        detailText.stringValue = @"  \u2190 Оберіть сканування";
        countLabel.stringValue = [NSString stringWithFormat:
            @"%lu сканування", (unsigned long)tableData.count];
    } forButton:btnRefresh];

    /* Підключаємо target/action */
    for (NSButton *b in @[btnOpenReport, btnShowDetail, btnDelete,
                           btnRefresh,   btnClose]) {
        b.target = bbt;
        b.action = @selector(invoke:);
    }

    [panel makeKeyAndOrderFront:nil];
    if (!scans.count)
        detailText.stringValue = url.length
            ? [NSString stringWithFormat:@"  Немає сканувань для: %@", url]
            : @"  Введіть URL у головному вікні для перегляду сканувань цілі";
}

@end
