/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
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
 * Source: https://github.com/ROOT-BSD/scanxss
 * SPDX-License-Identifier: GPL-2.0
 */

#include "scanxss.h"
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>

#define BAR_WIDTH 32

/* ── Global scan progress ─────────────────────────────────── */
static struct {
    int     total;
    int     done;
    int     color;
    int     active;          /* 1 = bar is on screen */
    char    phase[32];       /* "Crawling" / "Attacking" */
    struct timeval t_start;
} G;

void progress_init(ProgressBar *p, int total, int color, const char *label) {
    p->total = total > 0 ? total : 1;
    p->done  = 0;
    p->color = color;
    strncpy(p->label, label ? label : "Progress", sizeof(p->label)-1);
}

void progress_update(ProgressBar *p, int done) {
    p->done = done;
    (void)p; /* rendered by global bar */
}

void progress_finish(ProgressBar *p) {
    p->done = p->total;
}

/* ── Global progress bar API ──────────────────────────────── */
void progress_global_init(int total, int color, const char *phase) {
    int already_active = G.active;
    G.total  = total > 0 ? total : 1;
    G.color  = color;
    G.active = isatty(STDOUT_FILENO);
    if (phase) strncpy(G.phase, phase, sizeof(G.phase)-1);
    /* reset timer and done counter only on first call */
    if (!already_active || G.done == 0) {
        G.done = 0;
        gettimeofday(&G.t_start, NULL);
    }
}

void progress_global_tick(int done) {
    if (!G.active) return;
    G.done = done;

    int pct  = (int)((double)done / G.total * 100.0);
    int fill = (int)((double)done / G.total * BAR_WIDTH);

    /* elapsed time */
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec  - G.t_start.tv_sec)
                   + (now.tv_usec - G.t_start.tv_usec) * 1e-6;

    /* ETA */
    char eta[16] = "--";
    if (done > 0 && done < G.total) {
        double remaining = elapsed / done * (G.total - done);
        if (remaining < 3600)
            snprintf(eta, sizeof(eta), "%dm%02ds",
                     (int)remaining/60, (int)remaining%60);
        else
            snprintf(eta, sizeof(eta), ">1h");
    } else if (done >= G.total) {
        snprintf(eta, sizeof(eta), "done");
    }

    /* draw */
    if (G.color)
        fprintf(stdout, "\r" COL_BOLD "  %-10s" COL_RESET
                " " COL_CYAN "[" COL_RESET, G.phase);
    else
        fprintf(stdout, "\r  %-10s [", G.phase);

    for (int i = 0; i < BAR_WIDTH; i++) {
        if (i < fill)
            fputs(G.color ? COL_GREEN "█" COL_RESET : "#", stdout);
        else
            fputs(G.color ? "░" : ".", stdout);
    }

    if (G.color)
        fprintf(stdout, COL_CYAN "]" COL_RESET
                COL_BOLD " %3d%%" COL_RESET
                " %d/%d  ETA:%s  %.0fs   ",
                pct, done, G.total, eta, elapsed);
    else
        fprintf(stdout, "] %3d%% %d/%d ETA:%s %.0fs   ",
                pct, done, G.total, eta, elapsed);

    fflush(stdout);
}

void progress_global_finish(void) {
    if (!G.active) return;
    progress_global_tick(G.total);
    fputc('\n', stdout);
    fflush(stdout);
}
