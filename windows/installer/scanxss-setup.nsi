; ScanXSS Setup — NSIS installer script
; Builds scanxss-setup.exe for Windows 11

Unicode True
ManifestSupportedOS all
ManifestDPIAware true

;--- General ---
!define APP_NAME        "ScanXSS"
!define APP_VERSION     "1.3.3"
!define APP_PUBLISHER   "root_bsd (root_bsd@itprof.net.ua)"
!define APP_URL         "https://github.com/ROOT-BSD/scanxss"
!define APP_EXE         "scanxss-gui.exe"
!define INSTALL_DIR     "$PROGRAMFILES64\ScanXSS"
!define REG_KEY         "Software\ScanXSS"
!define UNINST_KEY      "Software\Microsoft\Windows\CurrentVersion\Uninstall\ScanXSS"
!define MUI_ICON        "..\resources\app.ico"
!define MUI_UNICON      "..\resources\app.ico"

;--- Compression ---
SetCompressor /SOLID lzma
SetCompressorDictSize 32

;--- MUI2 Modern UI ---
!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN         "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT    "Launch ScanXSS now"
!define MUI_FINISHPAGE_SHOWREADME  "$INSTDIR\README.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show README"
!define MUI_WELCOMEPAGE_TITLE      "Welcome to ScanXSS ${APP_VERSION} Setup"
!define MUI_WELCOMEPAGE_TEXT       "ScanXSS is a web vulnerability scanner.$\r$\n$\r$\nThis installer will install ScanXSS ${APP_VERSION} on your computer.$\r$\n$\r$\nClick Next to continue."

!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP_NOSTRETCH
!define MUI_BGCOLOR                "FFFFFF"
!define MUI_HEADER_TRANSPARENT_BACKGROUND

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE     "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Ukrainian"

;--- Metadata ---
Name           "${APP_NAME} ${APP_VERSION}"
OutFile        "scanxss-setup.exe"
InstallDir     "${INSTALL_DIR}"
InstallDirRegKey HKLM "${REG_KEY}" "InstallDir"
RequestExecutionLevel admin
BrandingText   "ScanXSS ${APP_VERSION} — Web Vulnerability Scanner"
ShowInstDetails show

;=== Install section ===
Section "ScanXSS (required)" SecMain
    SectionIn RO  ; mandatory

    SetOutPath "$INSTDIR"
    SetOverwrite on

    ; Install Root CA certificate
    File "RootBSD-CA.cer"
    DetailPrint "Installing root CA certificate..."
    nsExec::ExecToLog 'certutil -addstore -f "Root" "$INSTDIR\RootBSD-CA.cer"'
    Pop $0
    DetailPrint "Certificate installed (code $0)"

    ; Main executable
    File "..\scanxss-gui.exe"

    ; README
    File "README.txt"

    ; LICENSE
    File "LICENSE.txt"

    ; Create empty scan.db directory hint file
    FileOpen  $0 "$INSTDIR\scan.db.location.txt" w
    FileWrite $0 "ScanXSS stores scan results in scan.db in this directory."
    FileClose $0

    ; Write registry entries
    WriteRegStr  HKLM "${REG_KEY}" "InstallDir"   "$INSTDIR"
    WriteRegStr  HKLM "${REG_KEY}" "Version"       "${APP_VERSION}"

    ; Add/Remove Programs entry
    WriteRegStr  HKLM "${UNINST_KEY}" "DisplayName"          "${APP_NAME} ${APP_VERSION}"
    WriteRegStr  HKLM "${UNINST_KEY}" "DisplayVersion"        "${APP_VERSION}"
    WriteRegStr  HKLM "${UNINST_KEY}" "Publisher"             "${APP_PUBLISHER}"
    WriteRegStr  HKLM "${UNINST_KEY}" "URLInfoAbout"          "${APP_URL}"
    WriteRegStr  HKLM "${UNINST_KEY}" "InstallLocation"       "$INSTDIR"
    WriteRegStr  HKLM "${UNINST_KEY}" "UninstallString"       "$INSTDIR\uninstall.exe"
    WriteRegStr  HKLM "${UNINST_KEY}" "DisplayIcon"           "$INSTDIR\${APP_EXE}"
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify"             1
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair"             1
    ; Estimate size in KB
    WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize"        2048

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\ScanXSS"
    CreateShortcut  "$SMPROGRAMS\ScanXSS\ScanXSS.lnk" \
                    "$INSTDIR\${APP_EXE}" "" \
                    "$INSTDIR\${APP_EXE}" 0 \
                    SW_SHOWNORMAL "" "ScanXSS Web Vulnerability Scanner"
    CreateShortcut  "$SMPROGRAMS\ScanXSS\Uninstall ScanXSS.lnk" \
                    "$INSTDIR\uninstall.exe"
    CreateShortcut  "$DESKTOP\ScanXSS.lnk" \
                    "$INSTDIR\${APP_EXE}" "" \
                    "$INSTDIR\${APP_EXE}" 0 \
                    SW_SHOWNORMAL "" "ScanXSS Web Vulnerability Scanner"

    ; Windows Firewall — allow outbound (optional, uncomment if needed)
    ; nsExec::Exec 'netsh advfirewall firewall add rule name="ScanXSS" dir=out action=allow program="$INSTDIR\${APP_EXE}"'

SectionEnd

;=== Optional: Desktop shortcut ===
Section /o "Desktop shortcut" SecDesktop
    CreateShortcut "$DESKTOP\ScanXSS.lnk" \
                   "$INSTDIR\${APP_EXE}" "" \
                   "$INSTDIR\${APP_EXE}" 0
SectionEnd

;=== Uninstall section ===
Section "Uninstall"
    nsExec::ExecToLog 'certutil -delstore "Root" "ScanXSS Web Vulnerability Scanner"'

    ; Remove files
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\scan.db"
    Delete "$INSTDIR\scan.db.location.txt"
    Delete "$INSTDIR\README.txt"
    Delete "$INSTDIR\LICENSE.txt"
    Delete "$INSTDIR\uninstall.exe"

    ; Remove reports directory (ask first)
    IfFileExists "$INSTDIR\reports\*" 0 no_reports
        MessageBox MB_YESNO "Remove saved reports in $INSTDIR\reports?" IDNO no_reports
        RMDir /r "$INSTDIR\reports"
    no_reports:

    RMDir "$INSTDIR"

    ; Remove shortcuts
    Delete "$SMPROGRAMS\ScanXSS\ScanXSS.lnk"
    Delete "$SMPROGRAMS\ScanXSS\Uninstall ScanXSS.lnk"
    RMDir  "$SMPROGRAMS\ScanXSS"
    Delete "$DESKTOP\ScanXSS.lnk"

    ; Remove registry
    DeleteRegKey HKLM "${REG_KEY}"
    DeleteRegKey HKLM "${UNINST_KEY}"

    MessageBox MB_OK "ScanXSS was successfully uninstalled."
SectionEnd
