/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * ScanXSS macOS GUI — AppDelegate.m
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 */
#import "AppDelegate.h"

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

@implementation AppDelegate {
    NSFont *_mono;
    NSFont *_ui;
    NSFont *_label;
    BOOL    _scanning;
    BOOL    _reportOpened;
    NSView *_progressBlocksView;
}

- (void)applicationDidFinishLaunching:(NSNotification *)n {
    _mono  = [NSFont fontWithName:@"Menlo" size:12] ?:
             [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
    _ui    = [NSFont systemFontOfSize:13];
    _label = [NSFont systemFontOfSize:10 weight:NSFontWeightMedium];
    [self buildWindow];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)a { return YES; }

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
    self.window.title      = @"ScanXSS v1.3.1";
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
        font:[NSFont systemFontOfSize:18 weight:NSFontWeightBold]
        color:COL_WHITE parent:hdr];
    (void)logo;

    // Center: subtitle
    NSTextField *sub = [self mkLabel:NSMakeRect(200,16,340,18)
        text:@"Web Vulnerability Scanner v1.3.1"
        font:[NSFont systemFontOfSize:11] color:COL_GRAY parent:hdr];
    (void)sub;

    // Right: copyright
    NSTextField *cpr = [self mkLabel:NSMakeRect(W-420,16,410,18)
        text:@"© 2026 root_bsd <root_bsd@itprof.net.ua>"
        font:[NSFont systemFontOfSize:10] color:COL_GRAY parent:hdr];
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
        font:[NSFont systemFontOfSize:11] color:COL_GRAY parent:panel];

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
    [self appendLine:@"║   ScanXSS v1.3.1 — Web Vulnerability Scanner    ║" color:COL_CYAN];
    [self appendLine:@"║   © 2026 root_bsd <root_bsd@itprof.net.ua>  GPL-2.0 ║" color:COL_GRAY];
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
            @"ls -t \"%@/.scanxss/report/%@\"/*.html 2>/dev/null | head -1",
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
    NSAttributedString *as=[[NSAttributedString alloc]
        initWithString:[line stringByAppendingString:@"\n"]
        attributes:@{NSForegroundColorAttributeName:color,
                     NSFontAttributeName:_mono,
                     NSBackgroundColorAttributeName:[NSColor blackColor]}];
    [self.outputView.textStorage appendAttributedString:as];
    [self.outputView scrollRangeToVisible:NSMakeRange(self.outputView.textStorage.length,0)];
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
    btn.title=t; btn.font=[NSFont systemFontOfSize:13 weight:NSFontWeightMedium];
    btn.target=self; btn.action=s;
    btn.wantsLayer=YES;
    btn.layer.backgroundColor=bg.CGColor;
    btn.layer.cornerRadius=8;
    btn.contentTintColor=fg;
    [p addSubview:btn]; return btn;
}

@end
