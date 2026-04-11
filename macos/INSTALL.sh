#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ScanXSS v1.3.0 — macOS Installer
# Copyright (c) 2025 root_bsd (mglushak@gmail.com) GPL-2.0
# ─────────────────────────────────────────────────────────────
set -e
VER="1.3.0"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════════╗"
echo "║   ScanXSS v$VER — macOS Installer        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

[ "$(uname -s)" != "Darwin" ] && echo "❌  macOS only" && exit 1

# ── 1. Xcode CLT ──────────────────────────────────────────
echo "🔍  Checking compiler..."
if ! command -v clang &>/dev/null; then
    echo "    Installing Xcode Command Line Tools..."
    xcode-select --install
    echo "    Re-run this script after installation."
    exit 1
fi
echo "    ✅  $(clang --version 2>&1 | head -1)"

# ── 2. Homebrew + deps ────────────────────────────────────
echo ""
echo "📦  Checking dependencies..."
if ! command -v brew &>/dev/null; then
    echo "    Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL \
        https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    [ -f /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
    [ -f /usr/local/bin/brew ]    && eval "$(/usr/local/bin/brew shellenv)"
fi
echo "    ✅  $(brew --version | head -1)"
for pkg in openssl curl; do
    brew list --formula | grep -q "^${pkg}$" \
        && echo "    ✅  $pkg" \
        || { echo "    Installing $pkg..."; brew install "$pkg"; }
done

# ── 3. Build CLI scanner ──────────────────────────────────
echo ""
echo "🔨  Building CLI scanner..."
cd "$DIR"
make clean 2>/dev/null || true
make all
echo "    ✅  $(file ./scanxss | grep -o 'Mach-O[^,]*')"

# ── 4. Build GUI ──────────────────────────────────────────
echo ""
echo "🖥  Building GUI..."
SDK=$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)
ARCH=$(uname -m)
GUI_BIN="/tmp/ScanXSS_gui_build"
rm -f "$GUI_BIN"

echo "    Compiling Cocoa GUI for $ARCH..."

# Simple compile — same as: clang -fobjc-arc -O2 -framework Cocoa -framework Foundation
clang \
    -fobjc-arc \
    -O2 \
    -framework Cocoa \
    -framework Foundation \
    -o "$GUI_BIN" \
    "$DIR/gui/src/AppDelegate.m" \
    "$DIR/gui/src/main.m"

CLANG_EXIT=$?
if [ $CLANG_EXIT -ne 0 ] || [ ! -f "$GUI_BIN" ]; then
    echo "❌  GUI compilation failed (exit $CLANG_EXIT)"
    exit 1
fi

GUI_SIZE=$(du -sh "$GUI_BIN" | cut -f1)
CLI_SIZE=$(du -sh "$DIR/scanxss" | cut -f1)
echo "    ✅  GUI binary: $GUI_SIZE (CLI is $CLI_SIZE — must differ)"

# Sanity check: GUI must be different from CLI
if [ "$(wc -c < "$GUI_BIN")" = "$(wc -c < "$DIR/scanxss")" ]; then
    echo "    ⚠   WARNING: GUI same size as CLI — something wrong!"
fi

# ── 5. Build ICNS icon ────────────────────────────────────
echo ""
echo "🎨  Building icon..."
# Use iconutil to build .icns from existing iconset (or use pre-built)
if command -v iconutil &>/dev/null && [ -d "$DIR/gui/resources/AppIcon.iconset" ]; then
    iconutil -c icns "$DIR/gui/resources/AppIcon.iconset"              -o "$DIR/gui/resources/AppIcon.icns" 2>/dev/null         && echo "    ✅  Icon built with iconutil"         || echo "    ⚠   iconutil failed, using pre-built AppIcon.icns"
else
    echo "    ✅  Using pre-built AppIcon.icns"
fi
echo "    ✅  AppIcon.icns"

# ── 6. Assemble ScanXSS.app ───────────────────────────────
echo ""
echo "📦  Assembling ScanXSS.app..."
APP="$DIR/ScanXSS.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources"

# GUI binary (compiled above)
cp "$GUI_BIN" "$APP/Contents/MacOS/ScanXSS-gui"
chmod +x "$APP/Contents/MacOS/ScanXSS-gui"
rm -f "$GUI_BIN"

# CLI scanner
cp "$DIR/scanxss" "$APP/Contents/MacOS/scanxss"
chmod +x "$APP/Contents/MacOS/scanxss"

# Icon
cp "$DIR/gui/resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

# Info.plist
cp "$DIR/gui/Info.plist" "$APP/Contents/Info.plist"

# PkgInfo
printf "APPLSXSS" > "$APP/Contents/PkgInfo"

xattr -rd com.apple.quarantine "$APP" 2>/dev/null || true

echo "    Contents:"
echo "      MacOS/ScanXSS-gui  $(du -sh "$APP/Contents/MacOS/ScanXSS-gui" | cut -f1)  ← GUI"
# Verify GUI != CLI (same size = compile failed)
GUI_SZ=$(stat -f%z "$APP/Contents/MacOS/ScanXSS-gui" 2>/dev/null || echo 0)
CLI_SZ=$(stat -f%z "$APP/Contents/MacOS/scanxss" 2>/dev/null || echo 1)
[ "$GUI_SZ" = "$CLI_SZ" ] && echo "      ⚠   WARNING: GUI=CLI size — Cocoa build may have failed!" || true
echo "      MacOS/scanxss  $(du -sh "$APP/Contents/MacOS/scanxss" | cut -f1)  ← CLI"
echo "      Resources/AppIcon.icns"

# ── 7. Install to /Applications ───────────────────────────
echo ""
echo "📂  Installing to /Applications..."
sudo rm -rf /Applications/ScanXSS.app
sudo cp -r "$APP" /Applications/ScanXSS.app
sudo xattr -rd com.apple.quarantine /Applications/ScanXSS.app 2>/dev/null || true
echo "    ✅  /Applications/ScanXSS.app"

# ── 8. Launch ─────────────────────────────────────────────
echo ""
echo "🚀  Launching..."
# Verify both binaries exist before launch
if [ ! -f "/Applications/ScanXSS.app/Contents/MacOS/ScanXSS-gui" ]; then
    echo "❌  ScanXSS-gui missing — copy failed"
    exit 1
fi
if [ ! -f "/Applications/ScanXSS.app/Contents/MacOS/scanxss" ]; then
    echo "❌  scanxss CLI missing — copy failed"
    exit 1
fi

open /Applications/ScanXSS.app
sleep 2
if pgrep -xq "ScanXSS-gui"; then
    echo "    ✅  Running! (PID: $(pgrep -x ScanXSS-gui))"
else
    echo "    ⚠   Check: bash gui/diagnose.sh"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅  ScanXSS $VER installed!                         ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  App:     /Applications/ScanXSS.app                 ║"
echo "║  DB:      ~/.scanxss/scan.db                        ║"
echo "║  Reports: ~/Desktop/report/<host>/                 ║"
echo "╚══════════════════════════════════════════════════════╝"
