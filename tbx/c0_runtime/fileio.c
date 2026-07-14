#include "tb_runtime.h"

/* --- sequential file I/O --- */
static FILE *tb_files[16];
FILE *tb_file(int n) {
    if (n < 1 || n > 15 || !tb_files[n]) tb_error(52);  /* bad file number */
    return tb_files[n];
}
void tb_open(const char *mode, int n, const char *name) {
    if (n < 1 || n > 15) tb_error(52);
    if (tb_files[n]) tb_error(55);                       /* file already open */
    FILE *f = fopen(tb_s(name), mode);
    if (!f) tb_error(53);                                /* file not found */
    tb_files[n] = f;
}
/* random access: fixed 128-byte records (the calibrated OPEN reclen),
   FIELD vars snapshot the record buffer on GET and write into it on LSET/RSET */
static char *tb_recbuf[16];
static long tb_reclen[16], tb_fieldoff[16];
typedef struct { int file; char **var; long off, w; } tb_fielddef;
static tb_fielddef tb_fields[128];
static int tb_nfields = 0;
static void tb_drop_fields(int n) {
    int k = 0;
    for (int i = 0; i < tb_nfields; i++)
        if (tb_fields[i].file != n) tb_fields[k++] = tb_fields[i];
    tb_nfields = k;
}
void tb_close(int n) {
    if (n >= 1 && n <= 15 && tb_files[n]) {
        fclose(tb_files[n]); tb_files[n] = 0;
        free(tb_recbuf[n]); tb_recbuf[n] = 0;
        tb_drop_fields(n);
    }
}
void tb_reset(void) { for (int i = 1; i < 16; i++) tb_close(i); }
void tb_open_r(int n, const char *name) {
    if (n < 1 || n > 15) tb_error(52);
    if (tb_files[n]) tb_error(55);
    FILE *f = fopen(tb_s(name), "r+b");
    if (!f) f = fopen(tb_s(name), "w+b");
    if (!f) tb_error(53);
    tb_files[n] = f;
    tb_reclen[n] = 128;
    tb_recbuf[n] = tb_alloc(128);
    memset(tb_recbuf[n], ' ', 128);
}
double tb_eof(double n) {
    FILE *f = ((int)n >= 1 && (int)n <= 15) ? tb_files[(int)n] : 0;
    if (!f) return -1;
    int c = fgetc(f);
    if (c == EOF) return -1;
    ungetc(c, f);
    return 0;
}
double tb_finput_num(int n) {
    FILE *f = tb_file(n); double v = 0;
    if (fscanf(f, " %lf", &v) != 1) tb_error(62);        /* input past end */
    int c = fgetc(f);
    if (c != ',' && c != EOF && c != '\n') ungetc(c, f);
    return v;
}
char *tb_finput_str(int n) {
    FILE *f = tb_file(n); int c;
    while ((c = fgetc(f)) == ' ') ;
    if (c == EOF) tb_error(62);
    char buf[256]; size_t k = 0;
    if (c == '"') {
        while ((c = fgetc(f)) != EOF && c != '"') if (k < 255) buf[k++] = (char)c;
        c = fgetc(f);                                    /* separator after quote */
    } else {
        while (c != EOF && c != ',' && c != '\n') {
            if (c != '\r' && k < 255) buf[k++] = (char)c;
            c = fgetc(f);
        }
    }
    if (c != ',' && c != EOF && c != '\n') ungetc(c, f);
    buf[k] = 0;
    return tb_dup(buf);
}
void tb_field_start(int n) {
    tb_file(n);
    tb_fieldoff[n] = 0;
    tb_drop_fields(n);
}
void tb_field_reg(int n, char **var, long w) {
    if (tb_nfields >= 128 || !tb_recbuf[n] || tb_fieldoff[n] + w > tb_reclen[n])
        tb_error(50);                                    /* field overflow */
    tb_fields[tb_nfields++] = (tb_fielddef){n, var, tb_fieldoff[n], w};
    tb_fieldoff[n] += w;
    *var = tb_space(w);
}
void tb_lsetrset(char **var, const char *src, int right) {
    src = tb_s(src);
    tb_fielddef *fd = 0;
    for (int i = 0; i < tb_nfields; i++)
        if (tb_fields[i].var == var) { fd = &tb_fields[i]; break; }
    long w = fd ? fd->w : (long)strlen(tb_s(*var));
    long L = (long)strlen(src);
    if (L > w) L = w;
    char *out = tb_alloc(w);
    memset(out, ' ', w);
    memcpy(right ? out + (w - L) : out, src, L);
    if (fd) memcpy(tb_recbuf[fd->file] + fd->off, out, w);
    *var = out;
}
void tb_getrec(int n, double rec) {
    FILE *f = tb_file(n);
    if (!tb_recbuf[n]) tb_error(52);
    fseek(f, (long)(tb_i(rec) - 1) * tb_reclen[n], SEEK_SET);
    memset(tb_recbuf[n], 0, (size_t)tb_reclen[n]);
    if (fread(tb_recbuf[n], 1, (size_t)tb_reclen[n], f)) {}
    for (int i = 0; i < tb_nfields; i++)
        if (tb_fields[i].file == n) {
            char *v = tb_alloc(tb_fields[i].w);
            memcpy(v, tb_recbuf[n] + tb_fields[i].off, tb_fields[i].w);
            *tb_fields[i].var = v;
        }
}
void tb_putrec(int n, double rec) {
    FILE *f = tb_file(n);
    if (!tb_recbuf[n]) tb_error(52);
    fseek(f, (long)(tb_i(rec) - 1) * tb_reclen[n], SEEK_SET);
    fwrite(tb_recbuf[n], 1, (size_t)tb_reclen[n], f);
    fflush(f);
}
/* WRITE layout: comma separators, quoted strings, numbers without padding */
void tb_wnum(double v) { char b[64]; tb_fmt(v, b); tb_ps(b); }
void tb_wstr(const char *s) { tb_ps("\""); tb_ps(tb_s(s)); tb_ps("\""); }
/* PRINT USING: the # / . / + numeric-field subset; other format characters
   raise error 5 rather than misformat */
static const char *tb_puf = "";
static size_t tb_pup = 0;
void tb_pu_begin(const char *f) { tb_puf = tb_s(f); tb_pup = 0; }
void tb_pu_val(double v) {
    const char *f = tb_puf;
    size_t L = strlen(f);
    int guard = 0;
    if (!L) tb_error(5);
    for (;; tb_pup++) {                                  /* literals up to the field */
        if (tb_pup >= L) { tb_pup = 0; if (guard++) tb_error(5); }
        char c = f[tb_pup];
        if (c == '#' || (c == '+' && tb_pup + 1 < L && f[tb_pup + 1] == '#')) break;
        if (strchr("^!\\&_$*", c)) tb_error(5);
        char b[2] = {c, 0}; tb_ps(b);
    }
    int plus = f[tb_pup] == '+';
    if (plus) tb_pup++;
    int iw = 0, dw = -1;
    while (tb_pup < L && f[tb_pup] == '#') { iw++; tb_pup++; }
    if (tb_pup < L && f[tb_pup] == '.') {
        tb_pup++; dw = 0;
        while (tb_pup < L && f[tb_pup] == '#') { dw++; tb_pup++; }
    }
    char num[80];
    snprintf(num, 64, "%.*f", dw < 0 ? 0 : dw, v);
    if (dw == 0) strcat(num, ".");
    if (plus && v >= 0) { memmove(num + 1, num, strlen(num) + 1); num[0] = '+'; }
    int width = iw + (dw >= 0 ? 1 + dw : 0) + (plus ? 1 : 0);
    int pad = width - (int)strlen(num);
    if (pad < 0) tb_ps("%");                             /* field overflow, GW-style */
    for (; pad > 0; pad--) tb_ps(" ");
    tb_ps(num);
}
/* MKx$/CVx: raw little-endian bytes in a string. Caveat of the C string
   model: interior zero bytes truncate, so round trips through string ops
   are only exact when the encoded bytes avoid embedded NULs. */
static char *tb_mkbytes(const void *p, size_t n) {
    char *s = tb_alloc(n); memcpy(s, p, n); return s;
}
static void tb_cvbytes(const char *s, void *out, size_t n) {
    s = tb_s(s);
    size_t L = strlen(s);
    if (L > n) L = n;
    memset(out, 0, n); memcpy(out, s, L);
}
char *tb_mki(double v) { short x = (short)tb_i(v); return tb_mkbytes(&x, 2); }
char *tb_mkl(double v) { int x = (int)tb_i(v); return tb_mkbytes(&x, 4); }
char *tb_mks(double v) { float x = (float)v; return tb_mkbytes(&x, 4); }
char *tb_mkd(double v) { return tb_mkbytes(&v, 8); }
double tb_cvi(const char *s) { short x; tb_cvbytes(s, &x, 2); return x; }
double tb_cvl(const char *s) { int x; tb_cvbytes(s, &x, 4); return x; }
double tb_cvs(const char *s) { float x; tb_cvbytes(s, &x, 4); return x; }
double tb_cvd(const char *s) { double x; tb_cvbytes(s, &x, 8); return x; }
/* MKDIR: the POSIX form takes a mode argument, the Windows CRT form does not */
void tb_mkdir(const char *path) {
#ifdef _WIN32
    if (mkdir(path)) {}
#else
    if (mkdir(path, 0777)) {}
#endif
}
