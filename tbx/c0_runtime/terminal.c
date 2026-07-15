#include "tb_runtime.h"

/* TB's exact generator, reversed from the runtime's INT ED sub 3E handler
   and pinned by the t1_rnd fixture: Borland's 32-bit LCG
   state = state*08088405h + 1, result = (state>>1) * 2^-31. A program
   starts with state FFFFFFFFh, and RANDOMIZE n stores the IEEE-754
   single-precision bit pattern of n as the new state. */
unsigned int tb_rseed = 0xFFFFFFFFu;
double tb_rnd(void) {
    tb_rseed = tb_rseed * 0x08088405u + 1u;
    return (double)(tb_rseed >> 1) / 2147483648.0;
}
double tb_rndf(double x) {
    if (x == 0) return (double)(tb_rseed >> 1) / 2147483648.0;  /* repeat last */
    if (x < 0) tb_randomize(x);                    /* reseed, then draw */
    return tb_rnd();
}
void tb_randomize(double n) {
    float f = (float)n;
    memcpy(&tb_rseed, &f, sizeof tb_rseed);
}
double tb_instat(void) {
    int k = tb_sdl_instat();          /* -1: no SDL window, use the terminal */
    if (k >= 0) return k ? -1 : 0;
#ifdef _WIN32
    if (!_isatty(0)) {
        int c = getchar();
        if (c == EOF) return 0;
        ungetc(c, stdin);
        return -1;
    }
    return _kbhit() ? -1 : 0;
#else
    struct pollfd p = {0, POLLIN, 0};
    return poll(&p, 1, 0) > 0 ? -1 : 0;
#endif
}
/* --- terminal control (ANSI mapping of the CGA text interface) --- */
/* ANSI escapes bypass tb_ps so they don't disturb column tracking; the
   Windows console needs virtual-terminal processing switched on first */
void tb_esc(const char *s) {
#ifdef _WIN32
    static int vt = 0;
    if (!vt) {
        DWORD m; HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        vt = 1;
        if (GetConsoleMode(h, &m))
            SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
    fputs(s, stdout);
}
void tb_locate(double r, double c) {
    char b[32]; sprintf(b, "\033[%d;%dH", (int)r, (int)c);
    tb_esc(b); tb_cols[0] = (int)c - 1; tb_row = (int)r - 1;
}
static const int tb_cga[8] = {0, 4, 2, 6, 1, 5, 3, 7};  /* CGA -> ANSI hue */
int tb_fg = 3;                                    /* graphics foreground */
void tb_color(int has_fg, double fg, int has_bg, double bg) {
    char b[24];
    if (has_fg) {
        int f = (int)fg & 15;
        sprintf(b, "\033[%s3%dm", f > 7 ? "1;" : "22;", tb_cga[f & 7]);
        tb_esc(b); tb_fg = f;
    }
    if (has_bg) { sprintf(b, "\033[4%dm", tb_cga[(int)bg & 7]); tb_esc(b); }
}
static tb_str tb_key1(int c) { tb_str r = tb_new(1); r.p[0] = (char)c; return r; }
tb_str tb_inkey(void) {
    int k = tb_sdl_inkey();           /* -1: no SDL window, use the terminal */
    if (k >= 0) return k ? tb_key1(k) : tb_new(0);
#ifdef _WIN32
    int ch;
    if (!_isatty(0)) {
        ch = getchar();
        if (ch == EOF) return tb_new(0);
    } else {
        if (!_kbhit()) return tb_new(0);
        ch = _getch();
        if (ch == 0 || ch == 0xE0) {
            /* extended key: CHR$(0) + scan code, TB's two-byte form --
               descriptors carry the embedded NUL */
            tb_str r = tb_new(2);
            r.p[0] = 0; r.p[1] = (char)_getch();
            return r;
        }
    }
#else
    int fl = fcntl(0, F_GETFL);
    struct termios old, raw;
    int tty = isatty(0);
    if (tty) {
        tcgetattr(0, &old); raw = old;
        raw.c_lflag &= ~(unsigned)(ICANON | ECHO);
        tcsetattr(0, TCSANOW, &raw);
    }
    fcntl(0, F_SETFL, fl | O_NONBLOCK);
    char ch; long n = read(0, &ch, 1);
    fcntl(0, F_SETFL, fl);
    if (tty) tcsetattr(0, TCSANOW, &old);
    if (n != 1) return tb_new(0);
#endif
    return tb_key1((unsigned char)ch);
}
#ifdef _WIN32
/* DOS wildcard match (* and ?), case-insensitive: the fnmatch surrogate */
static int tb_match(const char *pat, const char *s) {
    for (; *pat; pat++, s++) {
        if (*pat == '*') {
            while (*pat == '*') pat++;
            for (;; s++) { if (tb_match(pat, s)) return 1; if (!*s) return 0; }
        }
        int a = *pat, b = *s;
        if (a >= 'a' && a <= 'z') a -= 32;
        if (b >= 'a' && b <= 'z') b -= 32;
        if (a != b && *pat != '?') return 0;
        if (!*s) return 0;
    }
    return !*s;
}
#define tb_fnmatch(p, n) (!tb_match(p, n))
#else
#define tb_fnmatch(p, n) fnmatch(p, n, FNM_CASEFOLD)
#endif
void tb_files_(tb_str spec) {
    const char *pat = tb_cs(spec);
    if (!*pat || !strcmp(pat, "*.*")) pat = "*";
    DIR *d = opendir(".");
    if (!d) tb_error(76);                                /* path not found */
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        if (tb_fnmatch(pat, e->d_name)) continue;
        tb_ps(e->d_name); tb_nl();
    }
    closedir(d);
}
tb_str tb_bin(double v) {
    char b[20]; int k = 19;
    unsigned x = (unsigned)tb_i(v) & 0xFFFF;
    do { b[--k] = (char)('0' + (x & 1)); x >>= 1; } while (x);
    tb_str r = tb_new((size_t)(19 - k));
    memcpy(r.p, b + k, (size_t)r.n);
    return r;
}
