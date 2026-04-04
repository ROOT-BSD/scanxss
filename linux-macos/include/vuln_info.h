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

#ifndef VULN_INFO_H
#define VULN_INFO_H

#include "scanxss.h"

/* ── Single reference link ──────────────────────────────────── */
typedef struct {
    const char *label;   /* "OWASP Top 10", "CWE-79", "CVSS 3.1" ... */
    const char *url;
} VulnRef;

/* ── Full vulnerability description ────────────────────────── */
typedef struct {
    VulnType    type;
    int         min_severity;   /* applies from this severity up */
    const char *short_name;     /* "XSS" */
    const char *full_name;      /* "Cross-Site Scripting" */
    const char *cvss_score;     /* "9.8 Critical" */
    const char *description;    /* Ukrainian description */
    const char *impact;
    const char *remediation;
    VulnRef     refs[6];        /* up to 6 reference links */
} VulnInfo;

/* ══════════════════════════════════════════════════════════════
 * VULNERABILITY DATABASE
 * ══════════════════════════════════════════════════════════════ */
static const VulnInfo VULN_DB[] = {

    /* ── RCE ─────────────────────────────────────────────────── */
    {
        VULN_RCE, 5,
        "RCE",
        "Remote Code Execution",
        "CVSS 9.8 — Critical",
        "Виконання довільного коду на сервері. Найнебезпечніша категорія вразливостей. "
        "Зловмисник отримує повний контроль над сервером: доступ до файлів, БД, "
        "мережевих ресурсів, може встановити backdoor або ransomware.",
        "Повний компроміс сервера, витік усіх даних, потенційне поширення в мережі.",
        "Негайно ізолюйте сервер. Оновіть фреймворк/залежності. "
        "Ніколи не передавайте дані від користувача у eval(), exec(), system(). "
        "Використовуйте allowlist для дозволених операцій.",
        {
            {"OWASP A03:2021 — Injection",
             "https://owasp.org/Top10/A03_2021-Injection/"},
            {"CWE-94: Code Injection",
             "https://cwe.mitre.org/data/definitions/94.html"},
            {"CWE-78: OS Command Injection",
             "https://cwe.mitre.org/data/definitions/78.html"},
            {"OWASP Testing Guide — Command Injection",
             "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection"},
            {"CVSS v3.1 Calculator",
             "https://www.first.org/cvss/calculator/3.1"},
            {NULL, NULL}
        }
    },

    /* ── SQL Injection ───────────────────────────────────────── */
    {
        VULN_SQLI, 4,
        "SQLi",
        "SQL Injection",
        "CVSS 9.8 — Critical",
        "SQL-ін'єкція дозволяє маніпулювати запитами до бази даних. "
        "Зловмисник може читати, змінювати або видаляти будь-які дані в БД, "
        "обходити автентифікацію, а в деяких конфігураціях — виконувати команди ОС.",
        "Витік усіх даних БД (паролі, персональні дані, фінансова інформація), "
        "обхід авторизації, пошкодження даних, повний компроміс сервера (через xp_cmdshell/UDF).",
        "Використовуйте параметризовані запити (prepared statements). "
        "Ніколи не конкатенуйте SQL з даними користувача. "
        "Застосовуйте ORM. Обмежте права облікового запису БД.",
        {
            {"OWASP A03:2021 — Injection",
             "https://owasp.org/Top10/A03_2021-Injection/"},
            {"CWE-89: SQL Injection",
             "https://cwe.mitre.org/data/definitions/89.html"},
            {"OWASP SQL Injection Prevention Cheat Sheet",
             "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
            {"OWASP Testing — SQL Injection",
             "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"},
            {"PortSwigger — SQL Injection",
             "https://portswigger.net/web-security/sql-injection"},
            {NULL, NULL}
        }
    },

    /* ── LFI ─────────────────────────────────────────────────── */
    {
        VULN_LFI, 4,
        "LFI",
        "Local File Inclusion",
        "CVSS 8.6 — High",
        "Вразливість дозволяє читати довільні файли сервера через path traversal. "
        "Зловмисник отримує доступ до /etc/passwd, конфігураційних файлів, "
        "приватних ключів SSH, вихідного коду застосунку та логів.",
        "Витік облікових даних, приватних ключів, вихідного коду. "
        "При певних умовах може призвести до RCE (через log poisoning).",
        "Ніколи не використовуйте дані користувача у шляхах файлів. "
        "Застосовуйте allowlist дозволених файлів. "
        "Обмежте права читання файлів для веб-процесу. "
        "Використовуйте chroot/container ізоляцію.",
        {
            {"OWASP — Path Traversal",
             "https://owasp.org/www-community/attacks/Path_Traversal"},
            {"CWE-22: Path Traversal",
             "https://cwe.mitre.org/data/definitions/22.html"},
            {"CWE-98: File Inclusion",
             "https://cwe.mitre.org/data/definitions/98.html"},
            {"OWASP Testing — LFI",
             "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"},
            {"PortSwigger — File Path Traversal",
             "https://portswigger.net/web-security/file-path-traversal"},
            {NULL, NULL}
        }
    },

    /* ── SSRF ────────────────────────────────────────────────── */
    {
        VULN_SSRF, 4,
        "SSRF",
        "Server-Side Request Forgery",
        "CVSS 8.6 — High",
        "Сервер виконує HTTP-запити на довільні адреси за вказівкою зловмисника. "
        "Це дозволяє сканувати внутрішню мережу, звертатися до метадата-сервісів "
        "хмарних провайдерів (AWS/GCP/Azure), обходити файрволи та отримувати "
        "токени доступу до хмарної інфраструктури.",
        "Доступ до внутрішніх сервісів, хмарних метаданих (IAM-ролі, токени AWS), "
        "сканування внутрішньої мережі, обхід захисту периметра.",
        "Не дозволяйте серверу робити запити за URL від користувача без валідації. "
        "Використовуйте allowlist дозволених доменів. "
        "Відключіть непотрібні схеми (file://, gopher://, dict://). "
        "Ізолюйте сервер від внутрішньої мережі через egress firewall.",
        {
            {"OWASP A10:2021 — SSRF",
             "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"},
            {"CWE-918: SSRF",
             "https://cwe.mitre.org/data/definitions/918.html"},
            {"OWASP SSRF Prevention Cheat Sheet",
             "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
            {"PortSwigger — SSRF",
             "https://portswigger.net/web-security/ssrf"},
            {"HackTricks — SSRF",
             "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery"},
            {NULL, NULL}
        }
    },

    /* ── XSS ─────────────────────────────────────────────────── */
    {
        VULN_XSS, 3,
        "XSS",
        "Cross-Site Scripting",
        "CVSS 7.4 — High",
        "Cross-Site Scripting дозволяє впровадити шкідливий JavaScript у сторінку, "
        "яку бачать інші користувачі. Зловмисник може вкрасти cookies/сесії, "
        "виконувати дії від імені жертви, перенаправляти на фішинг-сторінки, "
        "перехоплювати введення форм (keylogging).",
        "Крадіжка сесій та облікових даних, defacement, поширення шкідливого ПЗ, "
        "виконання привілейованих дій від імені адміністратора.",
        "Екранізуйте весь вивід у HTML (< → &lt;, > → &gt; тощо). "
        "Використовуйте Content Security Policy (CSP). "
        "Встановіть прапори HttpOnly та Secure для cookies. "
        "Застосовуйте бібліотеки для безпечного рендерингу (DOMPurify).",
        {
            {"OWASP A03:2021 — XSS",
             "https://owasp.org/www-community/attacks/xss/"},
            {"CWE-79: XSS",
             "https://cwe.mitre.org/data/definitions/79.html"},
            {"OWASP XSS Prevention Cheat Sheet",
             "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
            {"PortSwigger — XSS",
             "https://portswigger.net/web-security/cross-site-scripting"},
            {"MDN — Content Security Policy",
             "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
            {NULL, NULL}
        }
    },

    /* ── Open Redirect ───────────────────────────────────────── */
    {
        VULN_OPEN_REDIR, 2,
        "Redirect",
        "Open Redirect",
        "CVSS 6.1 — Medium",
        "Сервер перенаправляє користувача на довільний URL без перевірки. "
        "Використовується для фішингу: жертва клікає на легітимне посилання "
        "але потрапляє на шкідливий сайт.",
        "Фішинг, обхід referer-перевірок, OAuth-redirect hijacking.",
        "Валідуйте URL перенаправлення через allowlist. "
        "Не приймайте абсолютні URL у параметрах redirect. "
        "Використовуйте тільки відносні шляхи для редиректів.",
        {
            {"OWASP — Open Redirect",
             "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
            {"CWE-601: Open Redirect",
             "https://cwe.mitre.org/data/definitions/601.html"},
            {"PortSwigger — Open Redirection",
             "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"},
            {NULL, NULL}
        }
    },

    /* ── CRLF ────────────────────────────────────────────────── */
    {
        VULN_CRLF, 2,
        "CRLF",
        "CRLF Injection / HTTP Response Splitting",
        "CVSS 6.1 — Medium",
        "Впровадження символів \\r\\n у HTTP-заголовки дозволяє розщеплювати відповідь, "
        "встановлювати довільні заголовки (Set-Cookie, Location), "
        "виконувати reflected XSS через заголовки.",
        "Cookie injection, cache poisoning, XSS через заголовки відповіді.",
        "Видаляйте або відхиляйте \\r та \\n з усіх даних що потрапляють у заголовки. "
        "Використовуйте безпечні API для встановлення заголовків.",
        {
            {"OWASP — CRLF Injection",
             "https://owasp.org/www-community/vulnerabilities/CRLF_Injection"},
            {"CWE-93: CRLF Injection",
             "https://cwe.mitre.org/data/definitions/93.html"},
            {"PortSwigger — HTTP Response Splitting",
             "https://portswigger.net/kb/issues/00200200_http-response-header-injection"},
            {NULL, NULL}
        }
    },

    /* terminator */
    {VULN_NONE, 0, NULL, NULL, NULL, NULL, NULL, NULL, {{NULL,NULL}}}
};

/* ── Lookup function ─────────────────────────────────────────── */
static inline const VulnInfo *vuln_info_get(VulnType type, int severity) {
    for (int i = 0; VULN_DB[i].short_name; i++)
        if (VULN_DB[i].type == type && severity >= VULN_DB[i].min_severity)
            return &VULN_DB[i];
    return NULL;
}

#endif /* VULN_INFO_H */
