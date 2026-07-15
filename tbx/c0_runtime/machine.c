#include "tb_runtime.h"

/* --- machine access: an emulated real-mode machine ---
   PEEK/POKE/DEF SEG/BLOAD/BSAVE address a private zero-filled 1 MiB array
   standing in for the 8086 address space: POKEd values PEEK back, and
   BSAVE/BLOAD round-trip through files with the real 7-byte header, but
   nothing else lives there -- BIOS/DOS structures a program expects at a
   magic address read as 0.  I/O ports are 64 K one-byte latches: OUT
   stores, INP reads back the last OUT -- or 255 if none, the floating
   ISA bus (witnessed: t1_inpf dosout) -- and WAIT returns
   immediately since no device will ever flip a latch.  The REG buffer is
   real storage but CALL INTERRUPT is a no-op (there is no DOS/BIOS behind
   it: registers pass through unchanged), and CALL ABSOLUTE aborts -- the
   emulated memory holds data, never runnable machine code.  CHAIN execs
   the named file from the working directory (the chained-to program is
   expected to be a recompiled native executable), TB error 53 if absent. */

/* default DEF SEG is DGROUP; the paragraph value is synthetic (any fixed
   value works -- it only keys the address arithmetic) */
#define TB_DGROUP 0x1000u
static unsigned tb_seg = TB_DGROUP;
static unsigned char *tb_mem = 0;
static unsigned char tb_ports[65536];

static unsigned long tb_addr(double off) {
    if (!tb_mem) tb_mem = (unsigned char *)tb_calloc(1L << 20, 1);
    return ((unsigned long)tb_seg * 16 + ((unsigned long)tb_i(off) & 0xFFFF))
           & 0xFFFFF;
}
/* tb_addr allocates tb_mem, so it must be sequenced before the tb_mem read */
double tb_peek(double off) {
    unsigned long a = tb_addr(off);
    return tb_mem[a];
}
void tb_poke(double off, double v) {
    unsigned long a = tb_addr(off);
    tb_mem[a] = (unsigned char)tb_i(v);
}
void tb_defseg(int has, double seg) {
    tb_seg = has ? (unsigned)tb_i(seg) & 0xFFFF : TB_DGROUP;
}
/* a port no OUT ever latched reads as the floating bus, 0xFF */
static unsigned char *tb_port(double port) {
    static int init = 0;
    if (!init) { memset(tb_ports, 0xFF, sizeof tb_ports); init = 1; }
    return &tb_ports[(unsigned)tb_i(port) & 0xFFFF];
}
double tb_inp(double port) { return *tb_port(port); }
void tb_outp(double port, double v) {
    *tb_port(port) = (unsigned char)tb_i(v);
}
void tb_wait(double port, double mask, double xr) {
    /* WAIT spins until (INP(port) XOR xr) AND mask <> 0; a latch never
       changes by itself, so treat the absent device as ready */
    (void)port; (void)mask; (void)xr;
}

/* REG 0..9: FLAGS AX BX CX DX SI DI BP DS ES */
static short tb_regs[16];
void tb_regset(double n, double v) {
    tb_regs[(unsigned)tb_i(n) & 15] = (short)tb_i(v);
}
double tb_regget(double n) { return tb_regs[(unsigned)tb_i(n) & 15]; }
void tb_callint(double n) { (void)n; }
void tb_callabs(double off) {
    (void)off;
    fprintf(stderr, "\nCALL ABSOLUTE in line %d: no machine code on this host\n",
            tb_erl);
    exit(255);
}

/* BSAVE image header (GW-BASIC family): FD, seg, offset, length words */
void tb_bsave(tb_str f, double off, double len) {
    unsigned long a = tb_addr(off);
    unsigned long n = (unsigned long)tb_i(len) & 0xFFFF;
    FILE *fp = fopen(tb_cs(f), "wb");
    if (!fp) tb_error(75);                              /* path/file access */
    unsigned char hdr[7] = {0xFD, (unsigned char)tb_seg,
                            (unsigned char)(tb_seg >> 8)};
    hdr[3] = (unsigned char)tb_i(off); hdr[4] = (unsigned char)(tb_i(off) >> 8);
    hdr[5] = (unsigned char)n; hdr[6] = (unsigned char)(n >> 8);
    fwrite(hdr, 1, 7, fp);
    if (a + n > (1UL << 20)) n = (1UL << 20) - a;
    fwrite(tb_mem + a, 1, n, fp);
    fclose(fp);
}
void tb_bload(tb_str f, double off) {
    FILE *fp = fopen(tb_cs(f), "rb");
    if (!fp) tb_error(53);                              /* file not found */
    unsigned char hdr[7];
    if (fread(hdr, 1, 7, fp) != 7 || hdr[0] != 0xFD) {
        fclose(fp); tb_error(54);                       /* bad file mode */
    }
    unsigned long a = tb_addr(off);
    unsigned long n = hdr[5] | (unsigned long)hdr[6] << 8;
    if (a + n > (1UL << 20)) n = (1UL << 20) - a;
    if (fread(tb_mem + a, 1, n, fp) != n) { /* short image: keep what read */ }
    fclose(fp);
}

void tb_chain(tb_str f) {
    /* DOS loads the chained program from the current directory, so exec
       "./name"; retry lowercased, the usual spelling of a recompiled file */
    char name[512];
    const char *s = tb_cs(f);
    fflush(NULL);
    for (int pass = 0; pass < 2; pass++) {
        size_t k = 0;
#ifndef _WIN32
        if (!strchr(s, '/')) { name[k++] = '.'; name[k++] = '/'; }
#endif
        for (const char *p = s; *p && k < sizeof name - 1; p++, k++)
            name[k] = pass && *p >= 'A' && *p <= 'Z' ? (char)(*p + 32) : *p;
        name[k] = 0;
#ifdef _WIN32
        _execl(name, name, (char *)0);
#else
        execl(name, name, (char *)0);
#endif
    }
    tb_error(53);                                       /* file not found */
}
