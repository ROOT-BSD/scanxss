/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * ScanXSS macOS GUI — AppDelegate.h
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 */
#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (strong) NSWindow             *window;
@property (strong) NSTextField          *urlField;
@property (strong) NSTextField          *depthField;
@property (strong) NSTextField          *rateField;
@property (strong) NSTextField          *timeoutField;
@property (strong) NSTextField          *cookiesField;
@property (strong) NSPopUpButton        *scopePopup;
@property (strong) NSPopUpButton        *scanModePopup;
@property (strong) NSScrollView         *scrollView;
@property (strong) NSTextView           *outputView;
@property (strong) NSProgressIndicator  *progress;
@property (strong) NSTextField          *statusLabel;
@property (strong) NSButton             *scanButton;
@property (strong) NSButton             *stopButton;
@property (strong) NSButton             *reportButton;

@property (strong) NSButton *chkXSS, *chkSQLi, *chkLFI;
@property (strong) NSButton *chkRCE, *chkSSRF, *chkRedirect, *chkCRLF;

@property (strong) NSTask   *scanTask;
@property (strong) NSString *lastReportPath;

- (IBAction)startScan:(id)sender;
- (IBAction)stopScan:(id)sender;
- (IBAction)openReport:(id)sender;

@end
