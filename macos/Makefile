# ScanXSS — Portable Makefile
# GNU Make 3.81+ | Linux / macOS / BSD / Debian 13
#
# SQLite strategy:
#   - vendor/sqlite3.h  is shipped with the project (no libsqlite3-dev needed)
#   - Runtime: links against libsqlite3.so (in libsqlite3-0, always installed)
#   - Fallback: links against libsqlite3.a if .so not found

CC     := $(shell command -v gcc 2>/dev/null || echo cc)
UNAME  := $(shell uname -s)
CFLAGS := -Wall -Wextra -O2 -Iinclude -Ivendor

# Suppress false-positive truncation warnings.
# GCC uses -Wno-stringop-truncation; Clang (macOS) does not support it.
ifeq ($(UNAME),Darwin)
    # Clang on macOS: suppress only warnings it supports
    CFLAGS += -Wno-incompatible-pointer-types
    # Silence unknown warning option warnings themselves
    CFLAGS += -Wno-unknown-warning-option
else
    CFLAGS += -Wno-stringop-truncation -Wno-format-truncation
endif


# ── SQLite: find library (.so or .a), NO -dev package required ──
SQLITE_SO := $(shell \
  for d in /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu \
            /usr/lib64 /usr/lib /usr/local/lib /opt/homebrew/lib \
            /usr/local/opt/sqlite/lib; do \
    test -f "$$d/libsqlite3.so"   && { echo "$$d/libsqlite3.so";   exit; }; \
    test -f "$$d/libsqlite3.so.0" && { echo "$$d/libsqlite3.so.0"; exit; }; \
    test -f "$$d/libsqlite3.a"    && { echo "$$d/libsqlite3.a";    exit; }; \
  done)

ifneq ($(SQLITE_SO),)
    SQLITE_LDFLAGS := $(SQLITE_SO)
else
    # Last resort: hope -lsqlite3 works
    SQLITE_LDFLAGS := -lsqlite3
endif

# ── OpenSSL + curl ───────────────────────────────────────────
ifeq ($(UNAME),Darwin)
    BREW_PREFIX    := $(shell brew --prefix 2>/dev/null || echo /usr/local)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo $(BREW_PREFIX))
    CURL_PREFIX    := $(shell brew --prefix curl    2>/dev/null || echo $(BREW_PREFIX))
    SQLITE_PREFIX  := $(shell brew --prefix sqlite  2>/dev/null || echo $(BREW_PREFIX))
    CFLAGS  += -I$(OPENSSL_PREFIX)/include -I$(CURL_PREFIX)/include \
               -I$(SQLITE_PREFIX)/include
    export PKG_CONFIG_PATH := \
        $(OPENSSL_PREFIX)/lib/pkgconfig:$(CURL_PREFIX)/lib/pkgconfig:\
        $(SQLITE_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
    HAVE_PKG := $(shell pkg-config --exists libcurl openssl 2>/dev/null && echo yes)
    ifeq ($(HAVE_PKG),yes)
        LDFLAGS := $(shell pkg-config --libs libcurl openssl) $(SQLITE_LDFLAGS)
    else
        LDFLAGS := -L$(OPENSSL_PREFIX)/lib -L$(CURL_PREFIX)/lib \
                   -lcurl -lssl -lcrypto $(SQLITE_LDFLAGS)
    endif
else
    # Linux / BSD — curl + openssl via pkg-config, sqlite via direct path
    HAVE_PKG := $(shell pkg-config --exists libcurl openssl 2>/dev/null && echo yes)
    ifeq ($(HAVE_PKG),yes)
        CFLAGS  += $(shell pkg-config --cflags libcurl openssl)
        LDFLAGS := $(shell pkg-config --libs   libcurl openssl) $(SQLITE_LDFLAGS)
    else
        LDFLAGS := -lcurl -lssl -lcrypto $(SQLITE_LDFLAGS)
    endif
endif

# ── Paths ────────────────────────────────────────────────────
TARGET   := scanxss
BD       := build
TEST_BIN := $(BD)/test_integration

OBJ := \
    $(BD)/src_main.o     \
    $(BD)/src_http.o     \
    $(BD)/src_utils.o    \
    $(BD)/src_crawler.o  \
    $(BD)/src_attack.o   \
    $(BD)/src_report.o   \
    $(BD)/src_rate.o     \
    $(BD)/src_progress.o \
    $(BD)/src_session.o  \
    $(BD)/src_config.o   \
    $(BD)/src_email.o    \
    $(BD)/src_db.o       \
    $(BD)/mod_xss.o      \
    $(BD)/mod_sqli.o     \
    $(BD)/mod_misc.o     \
    $(BD)/mod_ssrf.o

LIB_OBJ := $(filter-out $(BD)/src_main.o, $(OBJ))

# ── Default target (must be first) ─────────────────────────
.PHONY: all clean test check-deps help vendor-sqlite
all: check-deps $(TARGET)

# ── Explicit per-file rules (avoids GNU Make 4.3+ pattern ambiguity) ──
$(BD)/src_main.o:     src/main.c     ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -Wno-unused-result -c $< -o $@
$(BD)/src_http.o:     src/http.c     ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_utils.o:    src/utils.c    ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_crawler.o:  src/crawler.c  ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_attack.o:   src/attack.c   ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_report.o:   src/report.c   ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_rate.o:     src/rate.c     ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_progress.o: src/progress.c ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_session.o: src/session.c  ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_config.o:  src/config.c   ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_email.o:   src/email.c    ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/src_db.o:       src/db.c       ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/mod_xss.o:      modules/mod_xss.c   ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/mod_sqli.o:     modules/mod_sqli.c  ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/mod_misc.o:     modules/mod_misc.c  ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@
$(BD)/mod_ssrf.o:     modules/mod_ssrf.c  ; @mkdir -p $(BD) && echo "  CC  $<" && $(CC) $(CFLAGS) -c $< -o $@

$(OBJ): include/scanxss.h vendor/sqlite3.h

# ── Link ─────────────────────────────────────────────────────
$(TARGET): $(OBJ)
	@echo "  LD  $@"
	@$(CC) $(OBJ) -o $@ $(LDFLAGS)
	@echo ""
	@echo "✅  Build OK: ./$(TARGET)"
	@echo "    SQLite:  $(SQLITE_LDFLAGS)"

$(TEST_BIN): tests/test_integration.c $(LIB_OBJ)
	@mkdir -p $(BD)
	@echo "  CC  tests/test_integration.c"
	@$(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@ $(LDFLAGS)

.PHONY: clean test check-deps help vendor-sqlite

test: $(TARGET) $(TEST_BIN)
	@echo "=== CLI tests ==="
	@./$(TARGET) --version
	@./$(TARGET) --list-modules
	@echo ""
	@echo "=== Integration tests ==="
	@$(TEST_BIN)

clean:
	@rm -rf $(BD) $(TARGET)
	@echo "Cleaned"

# ── Dependency check with clear messages ─────────────────────
check-deps:
	@echo "  [deps] Checking dependencies..."
ifeq ($(UNAME),Darwin)
	@if ! $(CC) -I$(OPENSSL_PREFIX)/include -x c -c /dev/null \
	    -o /dev/null 2>/dev/null; then \
	    echo ""; \
	    echo "❌  OpenSSL headers not found."; \
	    echo "    Fix: brew install openssl curl sqlite"; \
	    echo ""; exit 1; fi
	@echo "  [deps] macOS OK: openssl=$(OPENSSL_PREFIX)"
else
	@if ! $(CC) -x c -c /dev/null -o /dev/null 2>/dev/null; then \
	    echo "❌  C compiler not found. Fix: sudo apt install build-essential"; \
	    exit 1; fi
	@if ! pkg-config --exists libcurl 2>/dev/null; then \
	    echo ""; \
	    echo "❌  libcurl development headers not found."; \
	    echo "    Fix: sudo apt install libcurl4-openssl-dev"; \
	    echo ""; exit 1; fi
	@if [ -z "$(SQLITE_SO)" ] && ! pkg-config --exists sqlite3 2>/dev/null; then \
	    echo ""; \
	    echo "❌  SQLite runtime library not found."; \
	    echo "    Fix (Debian/Ubuntu): sudo apt install libsqlite3-0"; \
	    echo "    Fix (Arch):          sudo pacman -S sqlite"; \
	    echo "    Fix (Fedora):        sudo dnf install sqlite"; \
	    echo "    Note: libsqlite3-DEV is NOT required — headers are bundled."; \
	    echo ""; exit 1; fi
	@echo "  [deps] Linux OK: sqlite=$(SQLITE_LDFLAGS)"
endif
	@if [ ! -f vendor/sqlite3.h ]; then \
	    echo ""; \
	    echo "❌  vendor/sqlite3.h missing. Run:"; \
	    echo "    make vendor-sqlite"; \
	    echo ""; exit 1; fi

# ── Install sqlite3.h into vendor/ from the system ───────────
vendor-sqlite:
	@mkdir -p vendor
	@if [ -f /usr/include/sqlite3.h ]; then \
	    cp /usr/include/sqlite3.h vendor/sqlite3.h; \
	    echo "✅  Copied /usr/include/sqlite3.h → vendor/sqlite3.h"; \
	elif [ -f /usr/local/include/sqlite3.h ]; then \
	    cp /usr/local/include/sqlite3.h vendor/sqlite3.h; \
	    echo "✅  Copied /usr/local/include/sqlite3.h → vendor/sqlite3.h"; \
	else \
	    echo "❌  sqlite3.h not found. Install:"; \
	    echo "    Debian/Ubuntu: sudo apt install libsqlite3-dev"; \
	    echo "    macOS:         brew install sqlite"; \
	    echo "    Fedora:        sudo dnf install sqlite-devel"; \
	    exit 1; fi

help:
	@echo "Targets:"
	@echo "  make              — build ./scanxss"
	@echo "  make test         — build + run all tests"
	@echo "  make clean        — remove build/"
	@echo "  make vendor-sqlite — copy sqlite3.h into vendor/ from system"
	@echo ""
	@echo "Required packages (Debian/Ubuntu):"
	@echo "  sudo apt install build-essential libcurl4-openssl-dev libssl-dev"
	@echo "  (libsqlite3-dev NOT required — sqlite3.h bundled in vendor/)"
	@echo ""
	@echo "Required packages (macOS):"
	@echo "  brew install openssl curl sqlite"
