/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * SPDX-License-Identifier: GPL-2.0
 *
 * progress.c — progress bar з коректним elapsed і ETA.
 *
 * Thread safety:
 *   draw() захищена g_draw_mutex — єдиний рядок виводу
 *   в будь-який момент часу. Усуває подвійний бар при
 *   паралельній роботі worker pool.
 */

#include "scanxss.h"
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <pthread.h>

#define BAR_WIDTH     32
#define EWMA_WINDOW   8

/* ── Mutex — захищає вивід від race між worker-потоками ────── */
static pthread_mutex_t g_draw_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Глобальний стан ───────────────────────────────────────── */
static struct {
    int    total;
    int    done;
    int    color;
    int    active;           /* 1 = tty, малюємо bar */
    char   phase[32];

    struct timeval t_start;  /* час старту ВСЬОГО сканування */
    struct timeval t_phase;  /* час старту поточної фази */
    struct timeval t_last_tick;

    /* EWMA для ETA */
    double ewma_rate;        /* запитів/сек, ковзне середнє */
    int    tick_count;       /* скільки тіків зроблено */

    /* Spinner */
    int    spin_idx;
    struct timeval t_last_spin;

    /* Запам'ятовуємо чи вже є щось на рядку */
    int    line_dirty;
} G;

static const char *SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
static const int   SPIN_FRAMES = 10;
/* Fallback для не-UTF8 терміналів */
static const char  SPINNER_ASCII[] = "|/-\\";
static const int   SPIN_ASCII      = 4;

/* ── Час у секундах від точки відліку ─────────────────────── */
static double tv_diff(const struct timeval *a, const struct timeval *b) {
    return (a->tv_sec  - b->tv_sec)
         + (a->tv_usec - b->tv_usec) * 1e-6;
}

static double now_elapsed(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return tv_diff(&now, &G.t_start);
}

static double phase_elapsed(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return tv_diff(&now, &G.t_phase);
}

/* ── Форматування часу ─────────────────────────────────────── */
static void fmt_time(char *buf, size_t sz, double sec) {
    if (sec < 0 || sec > 86400) {
        snprintf(buf, sz, "--:--");
        return;
    }
    int h = (int)sec / 3600;
    int m = ((int)sec % 3600) / 60;
    int s = (int)sec % 60;
    if (h > 0)
        snprintf(buf, sz, "%d:%02d:%02d", h, m, s);
    else
        snprintf(buf, sz, "%d:%02d", m, s);
}

/* ── Малюємо один рядок бару — thread-safe ─────────────────── */
static void draw(void) {
    if (!G.active) return;

    pthread_mutex_lock(&g_draw_mutex);

    /* Spinner: кадр */
    char spin_char[8] = {0};
    /* Якщо виводиться у кольоровий tty — UTF-8 spinner */
    if (G.color) {
        /* Вибираємо UTF-8 фрейм: SPINNER — рядок де кожен символ = 3 байти */
        int fi = G.spin_idx % SPIN_FRAMES;
        spin_char[0] = SPINNER[fi * 3];
        spin_char[1] = SPINNER[fi * 3 + 1];
        spin_char[2] = SPINNER[fi * 3 + 2];
        spin_char[3] = '\0';
    } else {
        spin_char[0] = SPINNER_ASCII[G.spin_idx % SPIN_ASCII];
        spin_char[1] = '\0';
    }

    int pct  = G.total > 0 ? (int)((double)G.done / G.total * 100.0) : 0;
    if (pct > 100) pct = 100;
    int fill = (int)((double)pct / 100.0 * BAR_WIDTH);

    double elapsed = phase_elapsed();
    double scan_elapsed = now_elapsed();

    /* ETA через EWMA rate */
    char eta_buf[16];
    if (G.done <= 0 || G.ewma_rate <= 0 || G.done >= G.total) {
        snprintf(eta_buf, sizeof(eta_buf), G.done >= G.total ? "00:00" : "--:--");
    } else {
        double remaining_sec = (G.total - G.done) / G.ewma_rate;
        /* Обмежуємо розумними значеннями */
        if (remaining_sec > 86400) remaining_sec = 86400;
        fmt_time(eta_buf, sizeof(eta_buf), remaining_sec);
    }

    /* Elapsed поточної фази */
    char phase_buf[16], scan_buf[16];
    fmt_time(phase_buf, sizeof(phase_buf), elapsed);
    fmt_time(scan_buf,  sizeof(scan_buf),  scan_elapsed);

    /* req/s */
    double rps = elapsed > 0.5 ? G.done / elapsed : 0.0;

    /* Будуємо рядок */
    fprintf(stdout, "\r");

    if (G.color) {
        fprintf(stdout,
            COL_CYAN "%s" COL_RESET
            " " COL_BOLD "%-10s" COL_RESET
            " [",
            spin_char, G.phase);
    } else {
        fprintf(stdout, "\r%s %-10s [", spin_char, G.phase);
    }

    /* Сам бар */
    for (int i = 0; i < BAR_WIDTH; i++) {
        if (i < fill)
            fputs(G.color ? COL_GREEN "█" COL_RESET : "#", stdout);
        else if (i == fill && fill < BAR_WIDTH)
            fputs(G.color ? COL_YELLOW "▌" COL_RESET : ">", stdout);
        else
            fputs(G.color ? "░" : ".", stdout);
    }

    if (G.color) {
        fprintf(stdout,
            "] "
            COL_BOLD "%3d%%" COL_RESET
            " %d/%d"
            "  ETA:" COL_CYAN "%s" COL_RESET
            "  " COL_YELLOW "%s" COL_RESET
            "  %.1freq/s   ",
            pct, G.done, G.total, eta_buf, phase_buf, rps);
    } else {
        fprintf(stdout,
            "] %3d%% %d/%d  ETA:%s  %s  %.1freq/s   ",
            pct, G.done, G.total, eta_buf, phase_buf, rps);
    }

    fflush(stdout);
    G.line_dirty = 1;
    pthread_mutex_unlock(&g_draw_mutex);
}

/* ── Публічний API ─────────────────────────────────────────── */

void progress_init(ProgressBar *p, int total, int color, const char *label) {
    p->total = total > 0 ? total : 1;
    p->done  = 0;
    p->color = color;
    strncpy(p->label, label ? label : "Progress", sizeof(p->label)-1);
}

void progress_update(ProgressBar *p, int done) { p->done = done; }
void progress_finish(ProgressBar *p)           { p->done = p->total; }

/* Скидаємо ВЕСЬ таймер (на початку main()) */
void progress_global_reset(void) {
    gettimeofday(&G.t_start, NULL);
    G.t_phase     = G.t_start;
    G.t_last_tick = G.t_start;
    G.ewma_rate   = 0.0;
    G.tick_count  = 0;
    G.spin_idx    = 0;
    G.done        = 0;
    G.total       = 1;
    G.line_dirty  = 0;
}

void progress_global_init(int total, int color, const char *phase) {
    /* Якщо таймер ще не запущено — запускаємо */
    if (G.t_start.tv_sec == 0)
        gettimeofday(&G.t_start, NULL);

    /* Завжди скидаємо фазовий таймер */
    gettimeofday(&G.t_phase, NULL);
    G.t_last_tick = G.t_phase;

    G.total      = total > 0 ? total : 1;
    G.done       = 0;
    G.color      = color;
    G.active     = isatty(STDOUT_FILENO);
    G.ewma_rate  = 0.0;
    G.tick_count = 0;
    G.spin_idx   = 0;
    G.line_dirty = 0;

    if (phase) snprintf(G.phase, sizeof(G.phase), "%s", phase);

    draw();
}

void progress_global_tick(int done) {
    if (!G.active) return;

    struct timeval now;
    gettimeofday(&now, NULL);

    double dt = tv_diff(&now, &G.t_last_tick);
    G.t_last_tick = now;

    /* Оновлюємо EWMA rate — ігноруємо dt > 30s (таймаут запиту) */
    if (done > G.done && dt > 0.01 && dt < 30.0) {
        double instant_rate = (done - G.done) / dt;
        if (G.ewma_rate <= 0.0)
            G.ewma_rate = instant_rate;
        else {
            /* α = 2/(N+1) для EWMA з вікном N */
            double alpha = 2.0 / (EWMA_WINDOW + 1);
            G.ewma_rate = alpha * instant_rate + (1.0 - alpha) * G.ewma_rate;
        }
    }

    G.done = done;
    G.tick_count++;

    /* Spinner крутиться кожен тік */
    G.spin_idx++;

    draw();
}

/* Викликається з rate_wait() щоб анімувати spinner під час HTTP-запитів */
void progress_global_spin(void) {
    if (!G.active || !G.line_dirty) return;

    struct timeval now;
    gettimeofday(&now, NULL);

    /* Оновлюємо не частіше ніж 10 разів/сек */
    double dt = tv_diff(&now, &G.t_last_spin);
    if (dt < 0.1) return;
    G.t_last_spin = now;

    G.spin_idx++;
    draw();
}

void progress_global_finish(void) {
    if (!G.active) return;

    G.done = G.total;
    G.spin_idx = 0;

    double elapsed = phase_elapsed();
    double scan_elapsed = now_elapsed();
    double rps = elapsed > 0 ? G.done / elapsed : 0.0;

    char phase_buf[16], scan_buf[16];
    fmt_time(phase_buf, sizeof(phase_buf), elapsed);
    fmt_time(scan_buf,  sizeof(scan_buf),  scan_elapsed);

    /* Фінальний рядок — повний бар без spinner */
    fprintf(stdout, "\r");
    if (G.color) {
        fprintf(stdout,
            COL_GREEN "✓" COL_RESET
            " " COL_BOLD "%-10s" COL_RESET
            " [", G.phase);
    } else {
        fprintf(stdout, "\rOK %-10s [", G.phase);
    }
    for (int i = 0; i < BAR_WIDTH; i++)
        fputs(G.color ? COL_GREEN "█" COL_RESET : "#", stdout);

    if (G.color) {
        fprintf(stdout,
            "] " COL_GREEN COL_BOLD "100%%" COL_RESET
            " %d/%d"
            "  " COL_YELLOW "%s" COL_RESET
            "  " COL_CYAN "%.1freq/s" COL_RESET
            "   \n",
            G.done, G.total, phase_buf, rps);
    } else {
        fprintf(stdout, "] 100%% %d/%d  %s  %.1freq/s\n",
                G.done, G.total, phase_buf, rps);
    }

    fflush(stdout);
    G.line_dirty = 0;
}

/* Повертає elapsed від старту ВСЬОГО сканування (для print_summary) */
double progress_scan_elapsed(void) {
    return now_elapsed();
}
