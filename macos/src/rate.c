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
#include <time.h>
#include <unistd.h>

void rate_init(RateLimiter *r, int req_per_sec) {
    r->rate      = (req_per_sec > 0) ? req_per_sec : 0;
    r->req_count = 0;
    clock_gettime(CLOCK_MONOTONIC, &r->last_req);
}

void rate_wait(RateLimiter *r) {
    if (r->rate <= 0) {
        /* Необмежений режим — все одно крутимо spinner */
        progress_global_spin();
        return;
    }

    r->req_count++;

    long gap_ns = 1000000000L / r->rate;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long elapsed_ns = (now.tv_sec  - r->last_req.tv_sec)  * 1000000000L
                    + (now.tv_nsec - r->last_req.tv_nsec);

    if (elapsed_ns < gap_ns) {
        long remaining = gap_ns - elapsed_ns;

        /* Спимо частинами по 100ms — між кожною ітерацією крутимо spinner */
        const long SLICE_NS = 100000000L;   /* 100 мс */
        while (remaining > 0) {
            long slice = remaining < SLICE_NS ? remaining : SLICE_NS;
            struct timespec ts = {
                .tv_sec  = slice / 1000000000L,
                .tv_nsec = slice % 1000000000L
            };
            nanosleep(&ts, NULL);
            remaining -= slice;
            progress_global_spin();
        }
    } else {
        /* Час вже вийшов — просто крутимо spinner без сну */
        progress_global_spin();
    }

    clock_gettime(CLOCK_MONOTONIC, &r->last_req);
}
