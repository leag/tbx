#include "tb_runtime.h"

double tb_rnd(void) { return rand() / ((double)RAND_MAX + 1); }
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
char *tb_inkey(void) {
    int k = tb_sdl_inkey();           /* -1: no SDL window, use the terminal */
    if (k >= 0) {
        char b[2] = {(char)k, 0};
        return tb_dup(k ? b : "");
    }
#ifdef _WIN32
    int ch;
    if (!_isatty(0)) {
        ch = getchar();
        if (ch == EOF) return tb_dup("");
    } else {
        if (!_kbhit()) return tb_dup("");
        ch = _getch();
        /* extended key: TB would return CHR$(0)+scan, but the C string model
           truncates at NUL, so swallow the scan byte and report no key */
        if (ch == 0 || ch == 0xE0) { _getch(); return tb_dup(""); }
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
    if (n != 1) return tb_dup("");
#endif
    char b[2] = {(char)ch, 0};
    return tb_dup(b);
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
void tb_files_(const char *spec) {
    const char *pat = tb_s(spec);
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
char *tb_bin(double v) {
    char b[20]; int k = 19; b[k] = 0;
    unsigned x = (unsigned)tb_i(v) & 0xFFFF;
    do { b[--k] = (char)('0' + (x & 1)); x >>= 1; } while (x);
    return tb_dup(b + k);
}
