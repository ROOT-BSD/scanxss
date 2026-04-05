# ScanXSS macOS GUI Makefile
# Copyright (c) 2025 root_bsd (mglushak@gmail.com)

APP      = ScanXSS.app
BINARY   = ScanXSS
SRCS     = src/main.m src/AppDelegate.m
FRAMEWORKS = -framework Cocoa -framework Foundation
CFLAGS   = -O2 -Wall -fobjc-arc -Isrc
LDFLAGS  = $(FRAMEWORKS)
CC       = clang

.PHONY: all clean install

all: $(APP)/Contents/MacOS/$(BINARY) icon

$(APP)/Contents/MacOS/$(BINARY): $(SRCS)
	@mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)
	@cp Info.plist $(APP)/Contents/Info.plist
	@echo -n "APPLSXSS" > $(APP)/Contents/PkgInfo
	@echo "✅  $(BINARY) compiled"

icon:
	@if [ -f resources/AppIcon.icns ]; then \
	    cp resources/AppIcon.icns $(APP)/Contents/Resources/AppIcon.icns; \
	    echo "✅  Icon installed from resources/"; \
	elif command -v iconutil &>/dev/null && [ -d resources/AppIcon.iconset ]; then \
	    iconutil -c icns resources/AppIcon.iconset -o $(APP)/Contents/Resources/AppIcon.icns; \
	    echo "✅  Icon built with iconutil"; \
	else \
	    echo "⚠   Icon skipped"; \
	fi

clean:
	rm -rf $(APP)

install: all
	sudo rm -rf /Applications/ScanXSS.app
	sudo cp -r $(APP) /Applications/
	sudo xattr -rd com.apple.quarantine /Applications/$(APP) 2>/dev/null || true
	@echo "✅  Installed to /Applications/$(APP)"
