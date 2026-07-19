/* tb_runtime.h -- the Turbo Basic runtime behind `tbx --emit-c`.
   Each .c fragment in c0_runtime includes this header and compiles standalone
   (gcc/clang, POSIX or MinGW-w64), so the runtime can also be built as an
   ordinary C library. tbx amalgamates header + fragments -- stripping the
   include lines -- into the single self-contained generated file. */
#ifndef TB_RUNTIME_H
#define TB_RUNTIME_H

/* The runtime interface version. Bump on ANY change to a declaration in
   this header or to a documented surrogate behavior (see README.md in this
   directory): a generated --no-runtime program only links against a
   libtbrt.a built from the same version. */
#define TB_RT_VERSION 6

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <setjmp.h>
#ifdef _WIN32
/* MinGW-w64 gcc or clang (labels-as-values), not MSVC. dirent.h is shipped
   by MinGW; the termios/poll/fnmatch pieces have _WIN32 replacements. */
#include <windows.h>
#include <conio.h>
#include <io.h>
#include <process.h>
#include <direct.h>
#include <dirent.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <dirent.h>
#include <fnmatch.h>
#include <poll.h>
#include <sys/stat.h>
#ifndef FNM_CASEFOLD
#define FNM_CASEFOLD 0
#endif
#endif

/* Devices with no modern counterpart (the screen, the speaker) are rendered
   to files instead of replicated: SCREEN dumps its framebuffer to TB_SCREEN_PPM
   and PLAY dumps its audio to TB_PLAY_WAV, each at exit. This is a surrogate,
   not the original behavior, so it is gated at compile time -- build with
   -DTB_FILE_DEVICES=0 to omit the dumps entirely and leave the devices absent
   (silent PLAY, no screen file), the way real hardware-less execution behaves. */
#ifndef TB_FILE_DEVICES
#define TB_FILE_DEVICES 1
#endif

/* Build with -DTB_SDL=1 (and SDL2) to present the graphics framebuffer in a
   real window instead: sdl.c then provides tb_present/tb_sdl_inkey/
   tb_sdl_instat and graphics.c's no-op stubs compile out. The flag must be
   consistent across all fragments of one build. */
#ifndef TB_SDL
#define TB_SDL 0
#endif

/* --- strings: binary-safe length-carrying descriptors --- */
/* TB strings are length+bytes (a descriptor over the string space), so
   CHR$(0), MKI$ images and INKEY$ extended keys carry NULs. tb_str mirrors
   that: n bytes at p (p may be NULL when n == 0). Every buffer the runtime
   allocates is also NUL-terminated for OS calls (tb_cs), but no runtime
   operation relies on termination. Expression temporaries live in a
   statement-scoped arena (generated code calls tb_sr() at each top-level
   statement, never inside a SUB/DEF FN body, so CALL argument temps
   survive the callee); variable stores go through tb_sstore, which keeps
   an owned heap copy -- programs no longer leak per-statement garbage. */
typedef struct { long n; char *p; } tb_str;
#define TB_S(lit) ((tb_str){ (long)sizeof(lit) - 1, (char *)(lit) })
static inline const char *tb_cs(tb_str s) { return s.p ? s.p : ""; }
void tb_sr(void);                 /* statement boundary: reset the arena */
tb_str tb_sstore(tb_str old, tb_str val);  /* owned-copy variable store */
tb_str tb_borrow(const char *z);  /* wrap a C string (DATA items) */
long tb_cmp(tb_str a, tb_str b);  /* lexicographic, binary-safe */

/* --- core.c: error trapping, console PRINT, clock, numbers, strings --- */
extern jmp_buf tb_env;            /* tb_error longjmps here when trapped */
extern void *tb_handler;          /* installed handler label, 0 = none */
extern void *tb_stmt;             /* start of current statement (RESUME) */
extern void *tb_next;             /* following statement (RESUME NEXT) */
extern int tb_err, tb_erl;
void tb_error(int n);
extern FILE *tb_out;              /* current PRINT sink; stdout unless PRINT #n */
extern int tb_ch;                 /* current PRINT channel: 0 = console */
extern int tb_cols[16];           /* print column per channel (TAB/POS) */
extern int tb_row;                /* console cursor row (CSRLIN) */
void tb_ps(const char *s);        /* NUL-terminated console write (internal) */
void tb_pss(tb_str s);            /* binary-safe console write */
void tb_nl(void);
FILE *tb_lpt(void);
void tb_set_time(tb_str s);
void tb_set_date(tb_str s);
void tb_fmt(double v, char *out);
void tb_pn(double v);
void tb_tab(double n);
void tb_spc(double n);
double tb_cint(double v);
long tb_bix(long i, long lo, long n);
short tb_ichk(double v);
int tb_lchk(double v);
long tb_i(double v);
double tb_div(double a, double b);
double tb_idiv(double a, double b);
double tb_mod(double a, double b);
double tb_and(double a, double b);
double tb_or(double a, double b);
double tb_xor(double a, double b);
double tb_not(double a);
double tb_sgn(double v);
double tb_timer(void);
void tb_delay(double secs);
char *tb_alloc(size_t n);         /* arena temp, NUL-padded */
char *tb_halloc(size_t n);        /* owned heap buffer, NUL-padded */
tb_str tb_new(size_t n);          /* arena temp descriptor */
double tb_len(tb_str s);
double tb_asc(tb_str s);
double tb_val(tb_str s);
tb_str tb_cat(tb_str a, tb_str b);
tb_str tb_chr(double c);
tb_str tb_strS(double v);
tb_str tb_space(double n);
tb_str tb_stringS(double n, double c);
tb_str tb_stringSS(double n, tb_str s);
tb_str tb_inputS(double n);
tb_str tb_inputSF(double n, double fnum);
tb_str tb_commandS(void);
extern int tb_argc; extern char **tb_argv;  /* set by the generated main */
tb_str tb_left(tb_str s, double n);
tb_str tb_right(tb_str s, double n);
tb_str tb_mid(tb_str s, double start, double len);
double tb_instr(double start, tb_str a, tb_str b);
tb_str tb_ucase(tb_str s);
tb_str tb_lcase(tb_str s);
tb_str tb_ltrim(tb_str s);
tb_str tb_rtrim(tb_str s);
tb_str tb_hex(double v);
tb_str tb_oct(double v);
double tb_input_num(tb_str prompt, int mark);  /* prompt.p NULL = none; mark */
tb_str tb_input_str(tb_str prompt, int mark);  /* bit0 "? ", bit1 INPUT; */
void tb_input_begin(tb_str prompt, int mark);  /* multi-target INPUT: read the */
double tb_input_next_num(void);                /* line, then pull CSV fields */
tb_str tb_input_next_str(void);
tb_str tb_dateS(void);
tb_str tb_timeS(void);
void *tb_calloc(long n, size_t w);

/* --- fileio.c: sequential/random-access files, WRITE, PRINT USING --- */
FILE *tb_file(int n);
void tb_open(const char *mode, int n, tb_str name);
void tb_close(int n);
void tb_reset(void);
void tb_open_r(int n, tb_str name, int reclen);
double tb_eof(double n);
double tb_lof(double n);
double tb_finput_num(int n);
tb_str tb_finput_str(int n);
tb_str tb_finput_line(int n);
void tb_field_start(int n);
void tb_field_reg(int n, tb_str *var, long w);
void tb_lsetrset(tb_str *var, tb_str src, int right);
void tb_getrec(int n, double rec);
void tb_putrec(int n, double rec);
void tb_wnum(double v);
void tb_wstr(tb_str s);
void tb_pu_begin(tb_str f);
void tb_pu_val(double v);
void tb_pu_sval(tb_str s);
void tb_pu_flush(void);
void tb_zone(void);
tb_str tb_mki(double v);
tb_str tb_mkl(double v);
tb_str tb_mks(double v);
tb_str tb_mkd(double v);
double tb_cvi(tb_str s);
double tb_cvl(tb_str s);
double tb_cvs(tb_str s);
double tb_cvd(tb_str s);
void tb_mkdir(tb_str path);
void tb_chdir(tb_str path);
void tb_rmdir(tb_str path);
void tb_seek(int n, double pos);

/* --- terminal.c: RND, INSTAT, ANSI terminal control, INKEY$, FILES --- */
extern unsigned int tb_rseed;     /* TB's exact LCG state (see terminal.c) */
double tb_rnd(void);
double tb_rndf(double x);         /* RND(x): 0 = repeat last, <0 = reseed */
void tb_randomize(double n);
double tb_instat(void);
void tb_esc(const char *s);
void tb_locate(double r, double c);
extern int tb_fg;                 /* graphics foreground, COLOR/DRAW-set */
void tb_color(int has_fg, double fg, int has_bg, double bg);
tb_str tb_inkey(void);
void tb_files_(tb_str spec);
tb_str tb_bin(double v);

/* --- graphics.c: framebuffer with CGA/EGA geometry --- */
extern int tb_gw, tb_gh, tb_maxattr;
extern unsigned char *tb_fb;      /* byte-per-pixel framebuffer, 0 = no SCREEN */
extern int tb_pal[16];
void tb_screen(double mode);
double tb_pointf(double x, double y);
void tb_pset(double x, double y, int step, int has_c, double c, int preset);
void tb_linestmt(double x1, double y1, int s1, double x2, double y2, int s2,
                 int has_c, double c, int box, int fill, unsigned style);
void tb_circle(double x, double y, double r, int step, int has_c, double c,
               double sa, double ea, double aspect);
void tb_paint(double x, double y, int has_p, double p, int has_b, double b);
void tb_getgfx(void *buf, long cap, double x1, double y1, double x2, double y2);
void tb_putgfx(void *buf, long cap, double x, double y, int pset_action);
void tb_view(int has_rect, double x1, double y1, double x2, double y2,
             int absolute, int has_c, double c, int has_b, double b);
void tb_window(int has_rect, double x1, double y1, double x2, double y2,
               int absolute);
void tb_draw(tb_str cmd);
double tb_pmap(double v, double n);
/* presentation hook: every drawing op ends with tb_present(). sdl.c
   implements the TB_SDL side; graphics.c holds the no-op stubs. The
   tb_sdl_* pair returns -1 while no window is open, letting the terminal
   keyboard keep INKEY$/INSTAT. */
void tb_present(void);
int tb_sdl_inkey(void);
int tb_sdl_instat(void);

/* --- play.c: MML decoding to the WAV-file surrogate --- */
void tb_play(tb_str mml);

/* --- machine.c: emulated real-mode memory, ports, REG buffer, CHAIN --- */
double tb_peek(double off);
void tb_poke(double off, double v);
void tb_defseg(int has, double seg);
double tb_inp(double port);
void tb_outp(double port, double v);
void tb_wait(double port, double mask, double xr);
void tb_regset(double n, double v);
double tb_regget(double n);
void tb_callint(double n);
void tb_callabs(double off);
void tb_bsave(tb_str f, double off, double len);
void tb_bload(tb_str f, double off);
void tb_chain(tb_str f);

/* --- events.c: ON TIMER polling, MTIMER, the GOSUB label stack --- */
extern int tb_pen_on;
double tb_penf(void);
double tb_mono(void);
extern double tb_mt0;             /* MTIMER epoch */
double tb_mtread(void);
extern void *tb_timer_hdl;
extern double tb_timer_iv, tb_timer_due_at;
extern int tb_timer_on;
int tb_timer_due(void);
extern void *tb_gstack[256];
extern int tb_gsp;

#endif /* TB_RUNTIME_H */
