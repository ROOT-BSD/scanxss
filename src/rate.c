#include "scanxss.h"
#include <time.h>
#include <unistd.h>

void rate_init(RateLimiter *r, int req_per_sec) {
    r->rate      = (req_per_sec > 0) ? req_per_sec : 0;
    r->req_count = 0;
    clock_gettime(CLOCK_MONOTONIC, &r->last_req);
}

void rate_wait(RateLimiter *r) {
    if (r->rate <= 0) return;          /* unlimited */

    r->req_count++;

    /* minimum gap between requests = 1e9 / rate  nanoseconds */
    long gap_ns = 1000000000L / r->rate;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long elapsed_ns = (now.tv_sec  - r->last_req.tv_sec)  * 1000000000L
                    + (now.tv_nsec - r->last_req.tv_nsec);

    if (elapsed_ns < gap_ns) {
        struct timespec sleep_ts;
        long remaining = gap_ns - elapsed_ns;
        sleep_ts.tv_sec  = remaining / 1000000000L;
        sleep_ts.tv_nsec = remaining % 1000000000L;
        nanosleep(&sleep_ts, NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &r->last_req);
}
