/*
 * test_integration.c — інтеграційний тест ScanXSS
 * Запускає вбудований HTTP-сервер (сокети) і тестує сканер.
 */
#include "scanxss.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>

#define TEST_PORT 19876

/* ── ANSI helpers ── */
#define PASS(msg) printf(COL_GREEN "  [PASS] " COL_RESET msg "\n")
#define FAIL(msg) do { printf(COL_RED "  [FAIL] " COL_RESET msg "\n"); fails++; } while(0)
#define SECTION(s) printf(COL_BOLD "\n── %s ──\n" COL_RESET, s)

static int fails = 0;

/* ═══════════════════════════════════════════════════════
 *  Unit tests (no network needed)
 * ═══════════════════════════════════════════════════════ */
static void test_utils(void) {
    SECTION("utils");

    /* url_encode */
    char *e = url_encode("hello world&foo=bar");
    if (strcmp(e, "hello%20world%26foo%3Dbar") == 0) PASS("url_encode");
    else { FAIL("url_encode"); printf("    got: %s\n", e); }
    free(e);

    /* str_replace */
    char *r = str_replace("hello WORLD", "WORLD", "C");
    if (strcmp(r, "hello C") == 0) PASS("str_replace");
    else { FAIL("str_replace"); printf("    got: %s\n", r); }
    free(r);

    /* str_contains_icase */
    if (str_contains_icase("Warning: mysql_fetch", "mysql_fetch")) PASS("str_contains_icase hit");
    else FAIL("str_contains_icase hit");
    if (!str_contains_icase("clean response", "error")) PASS("str_contains_icase miss");
    else FAIL("str_contains_icase miss");

    /* url_in_scope – domain */
    if (url_in_scope("http://example.com/", "http://example.com/page", "domain"))
        PASS("url_in_scope domain same");
    else FAIL("url_in_scope domain same");
    if (!url_in_scope("http://example.com/", "http://evil.com/page", "domain"))
        PASS("url_in_scope domain diff");
    else FAIL("url_in_scope domain diff");

    /* resolve_url */
    char *u1 = resolve_url("http://example.com/path/page.html", "/other");
    if (strcmp(u1, "http://example.com/other") == 0) PASS("resolve_url abs-path");
    else { FAIL("resolve_url abs-path"); printf("    got: %s\n", u1); }
    free(u1);

    char *u2 = resolve_url("http://example.com/path/", "sub.html");
    if (strcmp(u2, "http://example.com/path/sub.html") == 0) PASS("resolve_url relative");
    else { FAIL("resolve_url relative"); printf("    got: %s\n", u2); }
    free(u2);

    /* html_strip */
    char *stripped = html_strip("<b>Hello</b> <i>World</i>");
    if (strcmp(stripped, "Hello World") == 0) PASS("html_strip");
    else { FAIL("html_strip"); printf("    got: '%s'\n", stripped); }
    free(stripped);
}

static void test_crawler_extract(void) {
    SECTION("crawler extract");

    /* links */
    const char *html =
        "<html><body>"
        "<a href=\"/page1\">P1</a>"
        "<a href=\"http://example.com/page2\">P2</a>"
        "<a href=\"http://evil.com/page3\">P3</a>"
        "<a href=\"#anchor\">Skip</a>"
        "<a href=\"javascript:void(0)\">Skip JS</a>"
        "</body></html>";

    CrawlResult r = {0};
    crawler_extract_links("http://example.com/", html, &r);
    if (r.url_count >= 2) PASS("extract_links count");
    else { FAIL("extract_links count"); printf("    got: %d\n", r.url_count); }

    /* verify /page1 was resolved */
    int found_p1 = 0;
    for (int i = 0; i < r.url_count; i++)
        if (strcmp(r.urls[i], "http://example.com/page1") == 0) found_p1 = 1;
    if (found_p1) PASS("resolve /page1");
    else FAIL("resolve /page1");

    /* evil.com should be excluded (different domain) */
    int found_evil = 0;
    for (int i = 0; i < r.url_count; i++)
        if (strstr(r.urls[i], "evil.com")) found_evil = 1;
    if (!found_evil) PASS("exclude cross-domain");
    else FAIL("exclude cross-domain");

    /* forms */
    const char *form_html =
        "<html><body>"
        "<form method='POST' action='/login'>"
        "  <input type='text' name='username' value=''>"
        "  <input type='password' name='password' value=''>"
        "  <input type='submit' value='Login'>"
        "</form>"
        "<form method='GET' action='/search'>"
        "  <input type='text' name='q' value=''>"
        "</form>"
        "</body></html>";

    CrawlResult r2 = {0};
    crawler_extract_forms("http://example.com/", form_html, &r2);
    if (r2.form_count == 2) PASS("extract_forms count=2");
    else { FAIL("extract_forms count"); printf("    got %d\n", r2.form_count); }

    if (r2.form_count >= 1) {
        if (r2.forms[0].method == METHOD_POST) PASS("form[0] method=POST");
        else FAIL("form[0] method=POST");
        if (strcmp(r2.forms[0].url, "http://example.com/login") == 0 ||
            strstr(r2.forms[0].url, "login")) PASS("form[0] action=/login");
        else { FAIL("form[0] action"); printf("    got: %s\n", r2.forms[0].url); }
        if (r2.forms[0].field_count >= 2) PASS("form[0] field_count>=2");
        else { FAIL("form[0] field_count"); printf("    got: %d\n", r2.forms[0].field_count); }
    }
    if (r2.form_count >= 2) {
        if (r2.forms[1].method == METHOD_GET) PASS("form[1] method=GET");
        else FAIL("form[1] method=GET");
    }
}

static void test_vuln_dedup(void) {
    SECTION("vuln deduplication");

    ScanContext *ctx = calloc(1, sizeof(ScanContext));

    Vuln v1 = {0};
    v1.type = VULN_XSS; v1.severity = 4;
    strncpy(v1.url, "http://x.com/", MAX_URL_LEN-1);
    strncpy(v1.parameter, "q", MAX_PARAM_LEN-1);
    strncpy(v1.payload, "<script>", MAX_PARAM_LEN-1);

    attack_add_vuln(ctx, &v1);
    attack_add_vuln(ctx, &v1);  /* duplicate */

    Vuln v2 = v1;
    v2.type = VULN_SQLI;
    attack_add_vuln(ctx, &v2);  /* different type — should add */

    if (ctx->vuln_count == 2) PASS("dedup: 2 unique vulns");
    else { FAIL("dedup"); printf("    got %d\n", ctx->vuln_count); }

    free(ctx);
}

/* ═══════════════════════════════════════════════════════
 *  Embedded HTTP server (fork)
 * ═══════════════════════════════════════════════════════ */

static void serve_client(int fd) {
    /* read request line */
    char req[4096] = {0};
    int  n = (int)read(fd, req, sizeof(req)-1);
    if (n <= 0) { close(fd); return; }

    /* parse method + path */
    char method[8]={0}, path[256]={0};
    sscanf(req, "%7s %255s", method, path);

    /* parse body for POST */
    char *body_start = strstr(req, "\r\n\r\n");
    char body[1024] = {0};
    if (body_start) strncpy(body, body_start+4, sizeof(body)-1);

    const char *http200 =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n";

    char resp[8192];

    if (strcmp(path, "/") == 0) {
        const char *page =
            "<html><body>"
            "<a href=\"/search\">search</a> "
            "<a href=\"/login\">login</a> "
            "<a href=\"/file?filename=readme.txt\">file</a>"
            "<form method=\"GET\" action=\"/search\">"
            "<input name=\"q\" value=\"\">"
            "<input type=\"submit\"></form>"
            "</body></html>";
        snprintf(resp, sizeof(resp),
            "%sContent-Length: %zu\r\n\r\n%s",
            http200, strlen(page), page);

    } else if (strncmp(path, "/search", 7) == 0) {
        /* extract q= param */
        char q[256] = "";
        char *qp = strstr(path, "q=");
        if (qp) {
            sscanf(qp+2, "%255[^& \t\r\n]", q);
            /* url-decode %XX */
            char dec[256] = {0}; char *d = dec;
            for (char *s = q; *s; s++) {
                if (*s=='%' && s[1] && s[2]) {
                    unsigned int c; sscanf(s+1,"%2x",&c); *d++=(char)c; s+=2;
                } else *d++=*s;
            }
            strncpy(q, dec, sizeof(q)-1);
        }
        /* VULN: XSS – reflect q without escaping */
        char page[2048];
        snprintf(page, sizeof(page),
            "<html><body>"
            "<h2>Results for: %s</h2>"
            "<form method=\"GET\" action=\"/search\">"
            "<input name=\"q\" value=\"%s\">"
            "<input type=\"submit\"></form>"
            "</body></html>", q, q);
        snprintf(resp, sizeof(resp), "%sContent-Length: %zu\r\n\r\n%s",
            http200, strlen(page), page);

    } else if (strncmp(path, "/file", 5) == 0) {
        char fn[256] = "readme.txt";
        char *fp = strstr(path, "filename=");
        if (fp) sscanf(fp+9, "%255[^& \t\r\n]", fn);
        char page[512];
        /* VULN: LFI – simulate /etc/passwd */
        if (strstr(fn,"passwd") || strstr(fn,"..") || strstr(fn,"etc"))
            snprintf(page, sizeof(page),
                "<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\n</pre>");
        else
            snprintf(page, sizeof(page), "<pre>normal file content</pre>");
        snprintf(resp, sizeof(resp), "%sContent-Length: %zu\r\n\r\n%s",
            http200, strlen(page), page);

    } else if (strcmp(path, "/login") == 0 && strcmp(method,"GET")==0) {
        const char *page =
            "<html><body>"
            "<form method=\"POST\" action=\"/login\">"
            "<input name=\"username\"><input name=\"password\" type=\"password\">"
            "<input type=\"submit\"></form></body></html>";
        snprintf(resp, sizeof(resp), "%sContent-Length: %zu\r\n\r\n%s",
            http200, strlen(page), page);

    } else if (strcmp(path, "/login") == 0 && strcmp(method,"POST")==0) {
        char u[256] = "";
        char *up = strstr(body, "username=");
        if (up) sscanf(up+9, "%255[^&\r\n]", u);
        char page[512];
        /* VULN: SQLi – reflect SQL error */
        if (strchr(u,'\'') || strstr(u,"--") || strchr(u,'"'))
            snprintf(page, sizeof(page),
                "<html><body>Warning: mysql_fetch_array() "
                "You have an error in your SQL syntax near '%s'</body></html>", u);
        else
            snprintf(page, sizeof(page),
                "<html><body>Login failed for: %s</body></html>", u);
        snprintf(resp, sizeof(resp), "%sContent-Length: %zu\r\n\r\n%s",
            http200, strlen(page), page);

    } else {
        const char *p404 = "<html><body>404 Not Found</body></html>";
        snprintf(resp, sizeof(resp),
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n"
            "Content-Length: %zu\r\n\r\n%s", strlen(p404), p404);
    }

    write(fd, resp, strlen(resp));
    close(fd);
}

static pid_t start_server(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(TEST_PORT),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return -1;
    }
    listen(srv, 64);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid > 0) { close(srv); usleep(100000); return pid; }

    /* child: serve requests */
    signal(SIGTERM, SIG_DFL);
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        serve_client(fd);
    }
}

static void test_network_scan(void) {
    SECTION("network scan (embedded server)");

    ScanContext *ctx = calloc(1, sizeof(ScanContext));
    ScanConfig  *cfg = &ctx->config;

    snprintf(cfg->target_url, MAX_URL_LEN, "http://127.0.0.1:%d/", TEST_PORT);
    cfg->depth           = 2;
    cfg->timeout         = 5;
    cfg->modules         = VULN_XSS | VULN_SQLI | VULN_LFI;
    cfg->color           = 0;
    cfg->verbose         = 0;
    cfg->max_links       = 50;
    cfg->follow_redirects= true;
    strncpy(cfg->scope, "domain", 31);

    /* Phase 1: crawl */
    int cr = crawler_run(ctx);
    if (cr == 0) PASS("crawler_run returned 0");
    else FAIL("crawler_run returned 0");

    printf("    urls=%d  forms=%d  requests=%d\n",
           ctx->crawl.url_count, ctx->crawl.form_count, ctx->requests_made);

    if (ctx->crawl.url_count >= 1) PASS("crawled >= 1 url");
    else FAIL("crawled >= 1 url");

    if (ctx->crawl.form_count >= 1) PASS("found >= 1 form");
    else FAIL("found >= 1 form");

    /* Phase 2: attack */
    attack_run_all(ctx);
    ctx->end_time = time(NULL);

    printf("    vulns=%d  total_requests=%d\n",
           ctx->vuln_count, ctx->requests_made);

    if (ctx->vuln_count >= 1) PASS("found >= 1 vulnerability");
    else FAIL("found >= 1 vulnerability (XSS/SQLi/LFI expected)");

    /* check specific vuln types */
    int has_xss=0, has_sqli=0, has_lfi=0;
    for (int i = 0; i < ctx->vuln_count; i++) {
        if (ctx->vulns[i].type == VULN_XSS)  has_xss=1;
        if (ctx->vulns[i].type == VULN_SQLI) has_sqli=1;
        if (ctx->vulns[i].type == VULN_LFI)  has_lfi=1;
    }
    if (has_xss)  PASS("XSS detected");
    else          FAIL("XSS not detected");
    if (has_sqli) PASS("SQLi detected");
    else          FAIL("SQLi not detected");
    if (has_lfi)  PASS("LFI detected");
    else          FAIL("LFI not detected");

    /* Phase 3: reports */
    ctx->start_time = time(NULL) - 2;

    int rj = report_json(ctx, "/tmp/scanxss_test.json");
    int rh = report_html(ctx, "/tmp/scanxss_test.html");
    int rt = report_txt (ctx, "/tmp/scanxss_test.txt");

    if (rj == 0) PASS("report_json");  else FAIL("report_json");
    if (rh == 0) PASS("report_html"); else FAIL("report_html");
    if (rt == 0) PASS("report_txt");  else FAIL("report_txt");

    /* verify JSON contains at least one vuln */
    FILE *jf = fopen("/tmp/scanxss_test.json","r");
    if (jf) {
        char jbuf[4096] = {0};
        fread(jbuf, 1, sizeof(jbuf)-1, jf);
        fclose(jf);
        if (strstr(jbuf, "\"type\"")) PASS("JSON has vuln type field");
        else FAIL("JSON missing type field");
    }

    free(ctx);
}

/* ═══════════════════════════════════════════════════════ */
int main(void) {
    printf(COL_BOLD "═══════════════════════════════════════\n"
           "  ScanXSS v1.3.0 Integration Tests\n"
           "═══════════════════════════════════════\n" COL_RESET);

    test_utils();
    test_crawler_extract();
    test_vuln_dedup();

    /* start embedded server */
    pid_t srv_pid = start_server();
    if (srv_pid <= 0) {
        printf(COL_RED "Cannot start test server\n" COL_RESET);
        return 1;
    }

    test_network_scan();

    kill(srv_pid, SIGTERM);
    waitpid(srv_pid, NULL, 0);

    printf(COL_BOLD "\n═══════════════════════════════════════\n" COL_RESET);
    if (fails == 0)
        printf(COL_GREEN "  ALL TESTS PASSED ✅\n" COL_RESET);
    else
        printf(COL_RED   "  %d TEST(S) FAILED ❌\n" COL_RESET, fails);
    printf(COL_BOLD "═══════════════════════════════════════\n" COL_RESET);

    return fails ? 1 : 0;
}
