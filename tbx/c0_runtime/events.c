#include "tb_runtime.h"

/* PEN(n) with the light-pen event disabled raises Illegal function call
   (witnessed: t1_penf dosout); enabled, the absent device reads 0 */
int tb_pen_on = 0;
double tb_penf(void) {
    if (!tb_pen_on) tb_error(5);
    return 0;
}

/* --- ON TIMER trapping (polled at statement boundaries, like TB) --- */
double tb_mono(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
#endif
}
double tb_mt0 = 0;  /* MTIMER epoch */
double tb_mtread(void) { return (tb_mono() - tb_mt0) * 1e6; }
void *tb_timer_hdl = 0;
double tb_timer_iv = 0, tb_timer_due_at = 0;
int tb_timer_on = 0;
int tb_timer_due(void) {
    if (!tb_timer_on || !tb_timer_hdl || tb_mono() < tb_timer_due_at) return 0;
    tb_timer_due_at = tb_mono() + tb_timer_iv;
    return 1;
}
void *tb_gstack[256];
int tb_gsp = 0;
