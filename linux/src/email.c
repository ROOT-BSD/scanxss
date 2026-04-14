/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 *
 * email.c — SMTP email sender with STARTTLS via OpenSSL
 *           No external mail libraries required.
 *           Reads configuration from scanxss.conf.
 */
#include "scanxss.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#ifdef __linux__
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <arpa/inet.h>
#endif
#ifdef __APPLE__
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <arpa/inet.h>
#endif

#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* ── Base64 encode ───────────────────────────────────────── */
static void b64_encode(const char *in, size_t len, char *out, size_t outsz) {
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t oi = 0;
    for (size_t i = 0; i < len && oi+4 < outsz; i += 3) {
        unsigned int v = (unsigned char)in[i] << 16;
        if (i+1 < len) v |= (unsigned char)in[i+1] << 8;
        if (i+2 < len) v |= (unsigned char)in[i+2];
        out[oi++] = t[(v >> 18) & 63];
        out[oi++] = t[(v >> 12) & 63];
        out[oi++] = (i+1 < len) ? t[(v >> 6) & 63] : '=';
        out[oi++] = (i+2 < len) ? t[v & 63]        : '=';
    }
    out[oi] = '\0';
}

/* ── SMTP session state ──────────────────────────────────── */
typedef struct {
    int      fd;
    SSL_CTX *ctx;
    SSL     *ssl;
    bool     tls_active;
} SmtpConn;

/* ── TCP connect ─────────────────────────────────────────── */
static int tcp_connect(const char *host, int port) {
    struct addrinfo hints = {0}, *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "[email] DNS lookup failed for %s\n", host);
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "[email] Cannot connect to %s:%d\n", host, port);
        return -1;
    }
    /* Set 30-second receive/send timeout */
    struct timeval tv = {30, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

/* ── Send/receive helpers ────────────────────────────────── */
static int smtp_send(SmtpConn *c, const char *fmt, ...) {
    char buf[2048];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int rc;
    if (c->tls_active)
        rc = SSL_write(c->ssl, buf, n);
    else
        rc = (int)write(c->fd, buf, (size_t)n);
    return rc > 0 ? 0 : -1;
}

static int smtp_recv(SmtpConn *c, char *buf, size_t sz) {
    memset(buf, 0, sz);
    size_t total = 0;
    /* Read lines until we get a non-continuation line (code + space, not dash) */
    while (total < sz - 1) {
        int n;
        if (c->tls_active)
            n = SSL_read(c->ssl, buf + total, (int)(sz - total - 1));
        else
            n = (int)read(c->fd, buf + total, sz - total - 1);
        if (n <= 0) {
            if (total > 0) break; /* partial read is ok */
            return -1;
        }
        total += (size_t)n;
        buf[total] = '\0';
        /* Check if last complete line is non-continuation: "NNN " not "NNN-" */
        char *last = buf;
        char *p = buf;
        while ((p = strchr(p, '\n')) != NULL) {
            last = p + 1;
            p++;
        }
        /* last points to start of last line in buffer */
        if (strlen(last) >= 4 && isdigit((unsigned char)last[0])
            && isdigit((unsigned char)last[1])
            && isdigit((unsigned char)last[2])
            && last[3] == ' ') {
            break; /* final response line */
        }
        if (strchr(buf, '\n') && last[0] == '\0') break; /* trailing newline */
    }
    return atoi(buf); /* SMTP response code from first line */
}

static int smtp_expect(SmtpConn *c, int expected, const char *cmd_sent) {
    char resp[1024];
    int code = smtp_recv(c, resp, sizeof(resp));
    /* strip trailing \r\n for log */
    char *nl = strpbrk(resp, "\r\n"); if (nl) *nl = '\0';
    if (code != expected) {
        fprintf(stderr, "[email] SMTP error after '%s': %d %s (expected %d)\n",
                cmd_sent, code, resp, expected);
        return -1;
    }
    return 0;
}

/* ── STARTTLS upgrade ────────────────────────────────────── */
static int starttls_upgrade(SmtpConn *c, const char *host) {
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) return -1;

    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL); /* allow self-signed */
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);

    c->ssl = SSL_new(c->ctx);
    if (!c->ssl) { SSL_CTX_free(c->ctx); c->ctx=NULL; return -1; }

    SSL_set_fd(c->ssl, c->fd);
    SSL_set_tlsext_host_name(c->ssl, host); /* SNI */

    if (SSL_connect(c->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(c->ssl); c->ssl=NULL;
        SSL_CTX_free(c->ctx); c->ctx=NULL;
        return -1;
    }
    c->tls_active = true;
    return 0;
}

/* ── Build RFC 2822 message ──────────────────────────────── */
static int write_message(SmtpConn *c,
                         const char *from, const char *to,
                         const char *subject,
                         const char *txt_path,
                         const char *html_path) {
    time_t now = time(NULL);
    char date[64];
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", localtime(&now));

    const char *bound = "----ScanXSSBoundary1337";

    smtp_send(c, "Date: %s\r\n", date);
    smtp_send(c, "From: %s\r\n", from);
    smtp_send(c, "To: %s\r\n", to);
    smtp_send(c, "Subject: %s\r\n", subject);
    smtp_send(c, "MIME-Version: 1.0\r\n");
    smtp_send(c, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n", bound);
    smtp_send(c, "\r\n");

    /* ── Part 1: plain text body from .txt report ── */
    smtp_send(c, "--%s\r\n", bound);
    smtp_send(c, "Content-Type: text/plain; charset=utf-8\r\n");
    smtp_send(c, "Content-Transfer-Encoding: 8bit\r\n\r\n");

    if (txt_path) {
        FILE *tf = fopen(txt_path, "r");
        if (tf) {
            char line[512];
            while (fgets(line, sizeof(line), tf)) {
                /* dot-stuffing: lines starting with '.' must be doubled */
                if (line[0] == '.') smtp_send(c, ".");
                smtp_send(c, "%s", line);
                if (!strchr(line, '\n')) smtp_send(c, "\r\n");
            }
            fclose(tf);
        }
    }
    smtp_send(c, "\r\n");

    /* ── Part 2: HTML report as attachment ── */
    if (html_path) {
        smtp_send(c, "--%s\r\n", bound);
        smtp_send(c, "Content-Type: text/html; charset=utf-8\r\n");
        smtp_send(c, "Content-Disposition: attachment; filename=\"scanxss_report.html\"\r\n");
        smtp_send(c, "Content-Transfer-Encoding: base64\r\n\r\n");

        FILE *hf = fopen(html_path, "rb");
        if (hf) {
            unsigned char buf[48]; /* 48 bytes → 64 base64 chars per line */
            char enc[96];
            size_t nr;
            while ((nr = fread(buf, 1, sizeof(buf), hf)) > 0) {
                b64_encode((char *)buf, nr, enc, sizeof(enc));
                smtp_send(c, "%s\r\n", enc);
            }
            fclose(hf);
        }
        smtp_send(c, "\r\n");
    }

    /* ── Final boundary ── */
    smtp_send(c, "--%s--\r\n", bound);
    smtp_send(c, ".\r\n"); /* end of DATA */
    return 0;
}

/* ── Main send function ──────────────────────────────────── */
int email_send_report(const ScanXSSConfig *cfg,
                      const char *host,
                      int vuln_count,
                      const char *html_path,
                      const char *txt_path) {

    if (!cfg->email_enabled)                              return 0;
    if (cfg->email_only_vulns && vuln_count == 0)         return 0;
    if (!cfg->email_to[0] || !cfg->smtp_host[0] ||
        !cfg->smtp_user[0] || !cfg->smtp_pass[0]) {
        fprintf(stderr, "[email] Incomplete config — skipping email\n");
        return -1;
    }

    /* ── Build subject ── */
    char subject[512];
    char date_str[32]; time_t t=time(NULL);
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", localtime(&t));
    char vuln_str[16]; snprintf(vuln_str, sizeof(vuln_str), "%d", vuln_count);

    const char *s = cfg->email_subject;
    size_t oi = 0;
    while (*s && oi < sizeof(subject)-1) {
        if (*s == '%' && *(s+1)) {
            s++;
            const char *rep = *s=='h' ? host :
                              *s=='v' ? vuln_str :
                              *s=='d' ? date_str : NULL;
            if (rep) { size_t rl=strlen(rep);
                if (oi+rl < sizeof(subject)-1) { memcpy(subject+oi,rep,rl); oi+=rl; } }
            else { subject[oi++]='%'; subject[oi++]=*s; }
        } else subject[oi++]=*s;
        s++;
    }
    subject[oi] = '\0';

    /* ── from address ── */
    const char *from = cfg->email_from[0] ? cfg->email_from : cfg->smtp_user;

    printf(COL_CYAN "[Email] Connecting to %s:%d...\n" COL_RESET,
           cfg->smtp_host, cfg->smtp_port);

    /* ── TCP connect ── */
    SmtpConn c = {0};
    c.fd = tcp_connect(cfg->smtp_host, cfg->smtp_port);
    if (c.fd < 0) return -1;

    char resp[1024];

    /* ── SMTP greeting ── */
    if (smtp_recv(&c, resp, sizeof(resp)) != 220) {
        fprintf(stderr, "[email] Bad greeting: %s\n", resp);
        close(c.fd); return -1;
    }

    /* ── EHLO ── */
    smtp_send(&c, "EHLO scanxss.local\r\n");
    if (smtp_recv(&c, resp, sizeof(resp)) < 0) { close(c.fd); return -1; }

    /* ── STARTTLS (порт 587) — опціональний ── */
    if (cfg->smtp_tls && cfg->smtp_port != 25) {
        smtp_send(&c, "STARTTLS\r\n");
        if (smtp_expect(&c, 220, "STARTTLS") < 0) { close(c.fd); return -1; }

        if (starttls_upgrade(&c, cfg->smtp_host) < 0) {
            fprintf(stderr, "[email] STARTTLS upgrade failed\n");
            close(c.fd); return -1;
        }
        printf(COL_CYAN "[Email] STARTTLS OK (TLS 1.2+)\n" COL_RESET);

        /* Re-send EHLO after STARTTLS */
        smtp_send(&c, "EHLO scanxss.local\r\n");
        if (smtp_recv(&c, resp, sizeof(resp)) < 0) goto fail;
    }

    /* ── AUTH LOGIN (якщо вказані облікові дані) ── */
    if (cfg->smtp_user[0] && cfg->smtp_pass[0]) {
        char b64user[512], b64pass[512];
        b64_encode(cfg->smtp_user, strlen(cfg->smtp_user), b64user, sizeof(b64user));
        b64_encode(cfg->smtp_pass, strlen(cfg->smtp_pass), b64pass, sizeof(b64pass));

        smtp_send(&c, "AUTH LOGIN\r\n");
        if (smtp_expect(&c, 334, "AUTH LOGIN") < 0) goto fail;

        smtp_send(&c, "%s\r\n", b64user);
        if (smtp_expect(&c, 334, "username") < 0) goto fail;

        smtp_send(&c, "%s\r\n", b64pass);
        if (smtp_expect(&c, 235, "password") < 0) goto fail;

        printf(COL_CYAN "[Email] Authenticated as %s\n" COL_RESET, cfg->smtp_user);
    } else {
        printf(COL_CYAN "[Email] Sending without authentication\n" COL_RESET);
    }

    /* ── MAIL FROM ── */
    smtp_send(&c, "MAIL FROM:<%s>\r\n", from);
    if (smtp_expect(&c, 250, "MAIL FROM") < 0) goto fail;

    /* ── RCPT TO (support comma-separated list) ── */
    {
        char rcpt_list[512];
        strncpy(rcpt_list, cfg->email_to, sizeof(rcpt_list)-1);
        char *tok = strtok(rcpt_list, ",");
        while (tok) {
            /* trim spaces */
            while (*tok == ' ') tok++;
            char *e = tok + strlen(tok);
            while (e > tok && *(e-1) == ' ') *--e = '\0';
            smtp_send(&c, "RCPT TO:<%s>\r\n", tok);
            if (smtp_expect(&c, 250, "RCPT TO") < 0) goto fail;
            tok = strtok(NULL, ",");
        }
    }

    /* ── DATA ── */
    smtp_send(&c, "DATA\r\n");
    if (smtp_expect(&c, 354, "DATA") < 0) goto fail;

    write_message(&c, from, cfg->email_to, subject,
                  txt_path, cfg->email_attach_html ? html_path : NULL);

    if (smtp_expect(&c, 250, "message body") < 0) goto fail;

    /* ── QUIT ── */
    smtp_send(&c, "QUIT\r\n");
    smtp_recv(&c, resp, sizeof(resp)); /* 221 */

    if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); }
    if (c.ctx) SSL_CTX_free(c.ctx);
    close(c.fd);

    printf(COL_GREEN "[Email] Report sent to %s ✓\n" COL_RESET, cfg->email_to);
    return 0;

fail:
    if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); }
    if (c.ctx) SSL_CTX_free(c.ctx);
    close(c.fd);
    fprintf(stderr, "[email] Failed to send report\n");
    return -1;
}
