#include "tb_runtime.h"

/* --- sequential file I/O --- */
static FILE *tb_files[16];
FILE *tb_file(int n) {
    if (n < 1 || n > 15 || !tb_files[n]) tb_error(52);  /* bad file number */
    return tb_files[n];
}
void tb_open(const char *mode, int n, tb_str name) {
    if (n < 1 || n > 15) tb_error(52);
    if (tb_files[n]) tb_error(55);                       /* file already open */
    FILE *f = fopen(tb_cs(name), mode);
    if (!f) tb_error(53);                                /* file not found */
    tb_files[n] = f;
}
/* random access: fixed 128-byte records (the calibrated OPEN reclen),
   FIELD vars snapshot the record buffer on GET and write into it on LSET/RSET */
static char *tb_recbuf[16];
static long tb_reclen[16], tb_fieldoff[16];
typedef struct { int file; tb_str *var; long off, w; } tb_fielddef;
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
void tb_open_r(int n, tb_str name, int reclen) {
    if (n < 1 || n > 15) tb_error(52);
    if (tb_files[n]) tb_error(55);
    FILE *f = fopen(tb_cs(name), "r+b");
    if (!f) f = fopen(tb_cs(name), "w+b");
    if (!f) tb_error(53);
    tb_files[n] = f;
    tb_reclen[n] = reclen;
    tb_recbuf[n] = tb_halloc(reclen);                    /* persists across statements */
    memset(tb_recbuf[n], ' ', reclen);
}
double tb_eof(double n) {
    FILE *f = ((int)n >= 1 && (int)n <= 15) ? tb_files[(int)n] : 0;
    if (!f) tb_error(52);       /* EOF on a closed channel: Bad file number
                                   (witnessed: t1_filef dosout) */
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
tb_str tb_finput_str(int n) {
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
    tb_str r = tb_new(k);
    memcpy(r.p, buf, k);
    return r;
}
void tb_field_start(int n) {
    tb_file(n);
    tb_fieldoff[n] = 0;
    tb_drop_fields(n);
}
void tb_field_reg(int n, tb_str *var, long w) {
    if (tb_nfields >= 128 || !tb_recbuf[n] || tb_fieldoff[n] + w > tb_reclen[n])
        tb_error(50);                                    /* field overflow */
    tb_fields[tb_nfields++] = (tb_fielddef){n, var, tb_fieldoff[n], w};
    tb_fieldoff[n] += w;
    char *p = tb_halloc((size_t)w);                      /* owned, like any var */
    memset(p, ' ', (size_t)w);
    free(var->p);
    *var = (tb_str){w, p};
}
void tb_lsetrset(tb_str *var, tb_str src, int right) {
    tb_fielddef *fd = 0;
    for (int i = 0; i < tb_nfields; i++)
        if (tb_fields[i].var == var) { fd = &tb_fields[i]; break; }
    long w = fd ? fd->w : var->n;
    long L = src.n;
    if (L > w) L = w;
    char *out = tb_halloc((size_t)w);
    memset(out, ' ', (size_t)w);
    if (L) memcpy(right ? out + (w - L) : out, src.p, (size_t)L);
    if (fd) memcpy(tb_recbuf[fd->file] + fd->off, out, (size_t)w);
    free(var->p);
    *var = (tb_str){w, out};
}
void tb_getrec(int n, double rec) {
    FILE *f = tb_file(n);
    if (!tb_recbuf[n]) tb_error(52);
    fseek(f, (long)(tb_i(rec) - 1) * tb_reclen[n], SEEK_SET);
    memset(tb_recbuf[n], 0, (size_t)tb_reclen[n]);
    if (fread(tb_recbuf[n], 1, (size_t)tb_reclen[n], f)) {}
    for (int i = 0; i < tb_nfields; i++)
        if (tb_fields[i].file == n) {
            char *v = tb_halloc((size_t)tb_fields[i].w);
            memcpy(v, tb_recbuf[n] + tb_fields[i].off, (size_t)tb_fields[i].w);
            free(tb_fields[i].var->p);
            *tb_fields[i].var = (tb_str){tb_fields[i].w, v};
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
/* WRITE numbers drop the leading sign-space of the number image; on the
   CONSOLE they keep its trailing space ("1 ,2 ", t1_write dosout) while
   WRITE # writes compactly ("1,\"A\"", t1_writefile dosout) */
void tb_wnum(double v) {
    char b[64]; tb_fmt(v, b); tb_ps(b);
    if (tb_ch == 0) tb_ps(" ");
}
void tb_wstr(tb_str s) { tb_ps("\""); tb_pss(s); tb_ps("\""); }
/* PRINT USING: the # / . / + numeric-field subset; other format characters
   raise error 5 rather than misformat */
static tb_str tb_puf = {0, 0};
static size_t tb_pup = 0;
void tb_pu_begin(tb_str f) {
    /* the format outlives the (arena) temporary it may arrive in */
    free(tb_puf.p);
    tb_puf = tb_sstore((tb_str){0, 0}, f);
    tb_pup = 0;
}
void tb_pu_val(double v) {
    const char *f = tb_cs(tb_puf);
    size_t L = (size_t)tb_puf.n;
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
/* MKx$/CVx: raw little-endian bytes in a string -- binary-safe now that
   descriptors carry their length (MKI$(256) holds its embedded NUL). */
static tb_str tb_mkbytes(const void *p, size_t n) {
    tb_str s = tb_new(n); memcpy(s.p, p, n); return s;
}
static void tb_cvbytes(tb_str s, void *out, size_t n) {
    size_t L = (size_t)s.n;
    if (L > n) L = n;
    memset(out, 0, n);
    if (L) memcpy(out, s.p, L);
}
tb_str tb_mki(double v) { short x = (short)tb_i(v); return tb_mkbytes(&x, 2); }
tb_str tb_mkl(double v) { int x = (int)tb_i(v); return tb_mkbytes(&x, 4); }
tb_str tb_mks(double v) { float x = (float)v; return tb_mkbytes(&x, 4); }
tb_str tb_mkd(double v) { return tb_mkbytes(&v, 8); }
double tb_cvi(tb_str s) { short x; tb_cvbytes(s, &x, 2); return x; }
double tb_cvl(tb_str s) { int x; tb_cvbytes(s, &x, 4); return x; }
double tb_cvs(tb_str s) { float x; tb_cvbytes(s, &x, 4); return x; }
double tb_cvd(tb_str s) { double x; tb_cvbytes(s, &x, 8); return x; }
/* MKDIR: the POSIX form takes a mode argument, the Windows CRT form does not */
void tb_mkdir(tb_str path) {
#ifdef _WIN32
    if (mkdir(tb_cs(path))) {}
#else
    if (mkdir(tb_cs(path), 0777)) {}
#endif
}
/* DOS paths spell the separator '\' */
static const char *tb_dospath(tb_str path) {
    static char buf[512];
    size_t n = (size_t)path.n;
    if (n >= sizeof buf) n = sizeof buf - 1;
    for (size_t i = 0; i < n; i++) {
        char c = path.p[i];
        buf[i] = c == '\\' ? '/' : c;
    }
    buf[n] = 0;
    return buf;
}
/* CHDIR to a missing path is TB error 76, Path not found (t1_chdir dosout) */
void tb_chdir(tb_str path) {
#ifdef _WIN32
    if (_chdir(tb_dospath(path))) tb_error(76);
#else
    if (chdir(tb_dospath(path))) tb_error(76);
#endif
}
/* RMDIR of a missing (or non-empty) directory is TB error 75, Path/File
   access error (t1_rmdir dosout) */
void tb_rmdir(tb_str path) {
#ifdef _WIN32
    if (_rmdir(tb_dospath(path))) tb_error(75);
#else
    if (rmdir(tb_dospath(path))) tb_error(75);
#endif
}
/* SEEK on a random-mode channel is TB error 54, Bad file mode (t1_seek
   dosout); on a sequential channel it moves the byte position (1-based) */
void tb_seek(int n, double pos) {
    FILE *f = tb_file(n);
    if (tb_recbuf[n]) tb_error(54);
    fseek(f, (long)tb_i(pos) - 1, SEEK_SET);
}
