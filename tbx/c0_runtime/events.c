/* --- ON TIMER trapping (polled at statement boundaries, like TB) --- */
static double tb_mono(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
#endif
}
static double tb_mt0 = 0;  /* MTIMER epoch */
static double tb_mtread(void) { return (tb_mono() - tb_mt0) * 1e6; }
static void *tb_timer_hdl = 0;
static double tb_timer_iv = 0, tb_timer_due_at = 0;
static int tb_timer_on = 0;
static int tb_timer_due(void) {
    if (!tb_timer_on || !tb_timer_hdl || tb_mono() < tb_timer_due_at) return 0;
    tb_timer_due_at = tb_mono() + tb_timer_iv;
    return 1;
}
static void *tb_gstack[256];
static int tb_gsp = 0;
