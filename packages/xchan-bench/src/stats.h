/* SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors */
/* SPDX-License-Identifier: Apache-2.0 */
/* stats.h, tiny aggregate-stats helper (min/median/p99/max) shared by
 * whatever consumes per-request measurements. Header-only, no deps. */
#ifndef BENCH_STATS_H
#define BENCH_STATS_H

#include <stdlib.h>

typedef struct {
    double min;
    double median;
    double p99;
    double max;
    double mean;
    int    n;
} bench_stats_t;

static int bench_cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

/* Computes stats over `values[0..n)`. Sorts `values` in place (caller's
 * copy). n must be > 0. Percentile uses nearest-rank on the sorted array:
 * index = ceil(p * n) - 1, clamped to [0, n-1]. */
static inline bench_stats_t bench_compute_stats(double *values, int n) {
    bench_stats_t s;
    s.n = n;
    qsort(values, (size_t)n, sizeof(double), bench_cmp_double);

    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += values[i];

    s.min = values[0];
    s.max = values[n - 1];
    s.mean = sum / n;

    /* median */
    if (n % 2 == 1) {
        s.median = values[n / 2];
    } else {
        s.median = (values[n / 2 - 1] + values[n / 2]) / 2.0;
    }

    /* p99, nearest-rank */
    int idx = (int)(0.99 * n + 0.9999999) - 1; /* ceil(0.99*n) - 1 */
    if (idx < 0) idx = 0;
    if (idx > n - 1) idx = n - 1;
    s.p99 = values[idx];

    return s;
}

#endif /* BENCH_STATS_H */
