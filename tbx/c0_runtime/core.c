#include "tb_runtime.h"

/* --- error trapping (ON ERROR GOTO / ERR / ERL / RESUME) --- */
jmp_buf tb_env;
void *tb_handler = 0;  /* installed handler label, 0 = none */
void *tb_stmt = 0;     /* start of current statement (RESUME) */
void *tb_next = 0;     /* following statement (RESUME NEXT) */
int tb_err = 0, tb_erl = 0;
void tb_error(int n) {
    tb_err = n;
    if (tb_handler) longjmp(tb_env, 1);
    fprintf(stderr, "\nError %d in line %d\n", n, tb_erl);
    exit(n);
}

FILE *tb_out = 0;  /* current PRINT sink; stdout unless PRINT #n */
int tb_ch = 0;     /* current PRINT channel: 0 = console, n = file #n */
int tb_cols[16];   /* print column per channel (TAB/POS) */
int tb_row = 0;    /* console cursor row (CSRLIN), LOCATE-aware */
#define tb_col tb_cols[tb_ch]
void tb_ps(const char *s) {
    if (!tb_out) tb_out = stdout;
    for (; *s; s++) {
        fputc(*s, tb_out);
        if (*s == '\n') {
            tb_col = 0;
            if (tb_ch == 0) tb_row++;
        } else {
            tb_col++;
        }
    }
}
void tb_nl(void) { tb_ps("\n"); }
/* the LPRINT sink: a printer never shows on the screen (t1_lprint dosout);
   TB_LPRINT_TXT=file captures the output, otherwise it is discarded */
FILE *tb_lpt(void) {
    static FILE *f = 0;
    if (!f) {
        const char *p = getenv("TB_LPRINT_TXT");
        if (p) f = fopen(p, "w");
#ifdef _WIN32
        if (!f) f = fopen("NUL", "w");
#else
        if (!f) f = fopen("/dev/null", "w");
#endif
    }
    return f;
}
const char *tb_s(const char *s) { return s ? s : ""; }
/* --- clock offsets (DATE$/TIME$ assignment shifts a process-local clock) --- */
static double tb_clk_off = 0;
static time_t tb_now_wall(void) { return time(NULL) + (time_t)tb_clk_off; }
static struct tm *tb_now_tm(void) { time_t t = tb_now_wall(); return localtime(&t); }
void tb_set_time(const char *s) {
    int h = 0, m = 0, sec = 0;
    sscanf(tb_s(s), "%d:%d:%d", &h, &m, &sec);
    struct tm *lt = tb_now_tm();
    tb_clk_off += (h * 3600 + m * 60 + sec)
        - (lt->tm_hour * 3600 + lt->tm_min * 60 + lt->tm_sec);
}
void tb_set_date(const char *s) {
    int mo = 1, d = 1, y = 1980;
    sscanf(tb_s(s), "%d-%d-%d", &mo, &d, &y);
    struct tm want = *tb_now_tm();
    want.tm_mon = mo - 1; want.tm_mday = d; want.tm_year = y - 1900;
    tb_clk_off += difftime(mktime(&want), tb_now_wall());
}
/* TB number image (witnessed: t1_fp dosout): integral -> no point
   ("24999999488"); else up to 16 significant digits with the leading zero
   of "0.5" stripped and a sign + THREE-digit exponent
   ("1.355252715606894E-020"). TB expands even singles to 16 digits, but
   its conversion carries ~1e-14 relative noise in the tail (t1_fp prints
   ...894 where the stored float32 is exactly ...881); we print the
   correctly-rounded value and test_c0 compares 13 significant digits. */
void tb_fmt(double v, char *out) {
    if (v == floor(v) && fabs(v) < 1e16) { sprintf(out, "%.0f", v); return; }
    char b[48]; sprintf(b, "%.16G", v);
    char *p = b, *o = out;
    if (*p == '-') *o++ = *p++;
    if (p[0] == '0' && p[1] == '.') p++;
    for (; *p && *p != 'E'; p++) *o++ = *p;
    if (*p == 'E') {                      /* E+x / E+xx -> E+0xx */
        long e = strtol(p + 1, NULL, 10);
        sprintf(o, "E%+04ld", e);
        return;
    }
    *o = 0;
}
void tb_pn(double v) {
    char b[64]; tb_fmt(v, b);
    if (v >= 0) tb_ps(" ");
    tb_ps(b); tb_ps(" ");
}
void tb_tab(double n) { while (tb_col < (int)n - 1) tb_ps(" "); }
void tb_spc(double n) { for (int i = 0; i < (int)n; i++) tb_ps(" "); }
/* CINT: round half to even (the x87/IEEE default nearbyint mode). */
double tb_cint(double v) { return nearbyint(v); }
long tb_i(double v) { return (long)tb_cint(v); }
/* IDE Options toggles, honored as compiled (Program.toggles): c0 emits
   these only when the source EXE had the toggle ON, matching TB's
   compile-in-or-not behavior.  Bounds: every subscript range-checks to
   error 9.  Overflow: integer stores range-check to error 6 (with the
   toggle off both TB and the C cast wrap silently). */
long tb_bix(long i, long lo, long n) {
    if (i < lo || i >= lo + n) tb_error(9);       /* subscript out of range */
    return i - lo;
}
short tb_ichk(double v) {
    double r = tb_cint(v);
    if (r < -32768.0 || r > 32767.0) tb_error(6); /* overflow */
    return (short)r;
}
int tb_lchk(double v) {
    double r = tb_cint(v);
    if (r < -2147483648.0 || r > 2147483647.0) tb_error(6);
    return (int)r;
}
double tb_div(double a, double b) { if (b == 0) tb_error(11); return a / b; }
double tb_idiv(double a, double b) { if (tb_i(b) == 0) tb_error(11); return (double)(tb_i(a) / tb_i(b)); }
double tb_mod(double a, double b) { if (tb_i(b) == 0) tb_error(11); return (double)(tb_i(a) % tb_i(b)); }
double tb_and(double a, double b) { return (double)(short)(tb_i(a) & tb_i(b)); }
double tb_or(double a, double b) { return (double)(short)(tb_i(a) | tb_i(b)); }
double tb_xor(double a, double b) { return (double)(short)(tb_i(a) ^ tb_i(b)); }
double tb_not(double a) { return (double)(short)~tb_i(a); }
double tb_sgn(double v) { return v > 0 ? 1 : v < 0 ? -1 : 0; }
double tb_timer(void) {
    struct tm *lt = tb_now_tm();
    return lt->tm_hour * 3600.0 + lt->tm_min * 60.0 + lt->tm_sec;
}
void tb_delay(double secs) {
#ifdef _WIN32
    Sleep((DWORD)(secs * 1000));
#else
    struct timespec ts = { (time_t)secs, (long)((secs - (long)secs) * 1e9) };
    nanosleep(&ts, NULL);
#endif
}
char *tb_alloc(size_t n) {
    char *p = malloc(n + 1);
    if (!p) { fputs("out of memory\n", stderr); exit(1); }
    p[n] = 0; return p;
}
char *tb_dup(const char *s) { char *p = tb_alloc(strlen(s)); strcpy(p, s); return p; }
char *tb_cat(const char *a, const char *b) {
    a = tb_s(a); b = tb_s(b);
    char *p = tb_alloc(strlen(a) + strlen(b));
    strcpy(p, a); strcat(p, b); return p;
}
double tb_len(const char *s) { return (double)strlen(tb_s(s)); }
double tb_asc(const char *s) { return (double)(unsigned char)tb_s(s)[0]; }
double tb_val(const char *s) { return strtod(tb_s(s), NULL); }
char *tb_chr(double c) { char *p = tb_alloc(1); p[0] = (char)tb_i(c); return p; }
char *tb_strS(double v) {
    char b[64]; tb_fmt(v, b);
    char *p = tb_alloc(strlen(b) + 1);
    if (v >= 0) { p[0] = ' '; strcpy(p + 1, b); } else strcpy(p, b);
    return p;
}
char *tb_space(double n) {
    long k = tb_i(n) < 0 ? 0 : tb_i(n);
    char *p = tb_alloc(k); memset(p, ' ', k); return p;
}
char *tb_stringS(double n, double c) {
    long k = tb_i(n) < 0 ? 0 : tb_i(n);
    char *p = tb_alloc(k); memset(p, (char)tb_i(c), k); return p;
}
char *tb_left(const char *s, double n) {
    s = tb_s(s); size_t L = strlen(s), k = tb_i(n) < 0 ? 0 : (size_t)tb_i(n);
    if (k > L) k = L;
    char *p = tb_alloc(k); memcpy(p, s, k); return p;
}
char *tb_right(const char *s, double n) {
    s = tb_s(s); size_t L = strlen(s), k = tb_i(n) < 0 ? 0 : (size_t)tb_i(n);
    if (k > L) k = L;
    return tb_dup(s + (L - k));
}
char *tb_mid(const char *s, double start, double len) {
    s = tb_s(s); size_t L = strlen(s);
    long st = tb_i(start); if (st < 1) st = 1;
    if ((size_t)st > L) return tb_dup("");
    size_t avail = L - (st - 1), k = len < 0 ? avail : (size_t)tb_i(len);
    if (k > avail) k = avail;
    char *p = tb_alloc(k); memcpy(p, s + st - 1, k); return p;
}
double tb_instr(double start, const char *a, const char *b) {
    a = tb_s(a); b = tb_s(b);
    long st = tb_i(start); if (st < 1) st = 1;
    if ((size_t)st > strlen(a)) return 0;
    const char *hit = strstr(a + st - 1, b);
    return hit ? (double)(hit - a + 1) : 0;
}
char *tb_ucase(const char *s) {
    char *p = tb_dup(tb_s(s));
    for (char *q = p; *q; q++) if (*q >= 'a' && *q <= 'z') *q -= 32;
    return p;
}
char *tb_lcase(const char *s) {
    char *p = tb_dup(tb_s(s));
    for (char *q = p; *q; q++) if (*q >= 'A' && *q <= 'Z') *q += 32;
    return p;
}
char *tb_ltrim(const char *s) { s = tb_s(s); while (*s == ' ') s++; return tb_dup(s); }
char *tb_rtrim(const char *s) {
    char *p = tb_dup(tb_s(s));
    for (size_t L = strlen(p); L && p[L - 1] == ' '; L--) p[L - 1] = 0;
    return p;
}
char *tb_hex(double v) { char b[24]; sprintf(b, "%lX", tb_i(v) & 0xFFFF); return tb_dup(b); }
char *tb_oct(double v) { char b[24]; sprintf(b, "%lo", tb_i(v) & 0xFFFF); return tb_dup(b); }
/* TB's INPUT echoes the typed characters and the Enter newline to the
   screen itself. Under a terminal the tty layer already does that; with
   redirected stdin nothing would, so echo the read line then -- keeping
   the visible output identical to a real DOS run (the dosout goldens). */
static void tb_input_line(char *line, size_t n) {
    if (!fgets(line, n, stdin)) { line[0] = 0; }
    line[strcspn(line, "\r\n")] = 0;
#ifdef _WIN32
    if (!_isatty(0)) { tb_ps(line); tb_ps("\n"); return; }
#else
    if (!isatty(0)) { tb_ps(line); tb_ps("\n"); return; }
#endif
    tb_col = 0;
}
double tb_input_num(const char *prompt, int mark) {
    if (prompt) tb_ps(prompt);
    if (mark) tb_ps("? ");
    char line[256];
    tb_input_line(line, sizeof line);
    return strtod(line, NULL);
}
char *tb_input_str(const char *prompt, int mark) {
    if (prompt) tb_ps(prompt);
    if (mark) tb_ps("? ");
    char line[256];
    tb_input_line(line, sizeof line);
    return tb_dup(line);
}
char *tb_dateS(void) {
    struct tm *lt = tb_now_tm(); char b[40];
    sprintf(b, "%02d-%02d-%04d", lt->tm_mon + 1, lt->tm_mday, lt->tm_year + 1900);
    return tb_dup(b);
}
char *tb_timeS(void) {
    struct tm *lt = tb_now_tm(); char b[16];
    sprintf(b, "%02d:%02d:%02d", lt->tm_hour, lt->tm_min, lt->tm_sec);
    return tb_dup(b);
}
void *tb_calloc(long n, size_t w) {
    void *p = calloc(n > 0 ? n : 1, w);
    if (!p) { fputs("out of memory\n", stderr); exit(1); }
    return p;
}
