#include "tb_runtime.h"

/* --- PLAY: decode a GW-BASIC-compatible MML string into audio ---
   There is no audio device on a headless host, so PLAY renders its Music
   Macro Language into a mono 16-bit 44.1kHz square-wave buffer and, like
   TB_SCREEN_PPM for the framebuffer, writes it to a WAV file at exit when
   TB_PLAY_WAV is set. Octave numbering follows GW/Turbo BASIC: middle C
   (261.63 Hz) is the C at the start of octave 3. */
#define TB_SR 44100
static int tb_pl_oct = 4, tb_pl_len = 4, tb_pl_tempo = 120, tb_pl_art = 7; /* MN=7/8 */
#if TB_FILE_DEVICES
static short *tb_pcm = 0;
static long tb_pcm_n = 0, tb_pcm_cap = 0;
static void tb_pcm_tone(double freq, double secs, double on_frac) {
    long total = (long)(secs * TB_SR + 0.5), on = (long)(total * on_frac);
    if (tb_pcm_n + total > tb_pcm_cap) {
        while (tb_pcm_cap < tb_pcm_n + total)
            tb_pcm_cap = tb_pcm_cap ? tb_pcm_cap * 2 : TB_SR;
        tb_pcm = realloc(tb_pcm, tb_pcm_cap * sizeof *tb_pcm);
        if (!tb_pcm) { fputs("out of memory\n", stderr); exit(1); }
    }
    for (long i = 0; i < total; i++)
        tb_pcm[tb_pcm_n++] =
            (i < on && freq > 0) ? (sin(2 * 3.14159265358979 * freq * i / TB_SR) >= 0
                                        ? 9000 : -9000) : 0;
}
static void tb_wav_dump(void) {
    const char *path = getenv("TB_PLAY_WAV");
    if (!path || !tb_pcm_n) return;
    FILE *f = fopen(path, "wb");
    if (!f) return;
    unsigned data = (unsigned)(tb_pcm_n * 2), rate = TB_SR, riff = 36 + data, brate = rate * 2;
    unsigned char h[44] = {'R','I','F','F', riff,riff>>8,riff>>16,riff>>24,
        'W','A','V','E','f','m','t',' ', 16,0,0,0, 1,0, 1,0,
        rate,rate>>8,rate>>16,rate>>24, brate,brate>>8,brate>>16,brate>>24,
        2,0, 16,0, 'd','a','t','a', data,data>>8,data>>16,data>>24};
    fwrite(h, 1, 44, f);
    fwrite(tb_pcm, 2, tb_pcm_n, f);
    fclose(f);
}
#else
static void tb_pcm_tone(double freq, double secs, double on_frac) {
    (void)freq; (void)secs; (void)on_frac;  /* no speaker, no dump: PLAY is silent */
}
#endif
static long tb_pl_num(const char **p) {
    long v = 0; int got = 0;
    while (**p >= '0' && **p <= '9') { v = v * 10 + (*(*p)++ - '0'); got = 1; }
    return got ? v : -1;
}
/* full duration of a note whose base length is `l`, honouring trailing dots */
static double tb_pl_dur(long l, const char **p) {
    double base = (4.0 / l) * (60.0 / tb_pl_tempo), d = base, add = base / 2;
    while (**p == '.') { d += add; add /= 2; (*p)++; }
    return d;
}
void tb_play(tb_str mml) {
    static const int semi[7] = {9, 11, 0, 2, 4, 5, 7};  /* A B C D E F G */
#if TB_FILE_DEVICES
    static int reg = 0;
    if (!reg) { reg = 1; atexit(tb_wav_dump); }
#endif
    const char *p = tb_cs(mml);
    while (*p) {
        int c = *p++;
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c == ' ' || c == '\t' || c == ';' || c == ',') continue;
        if (c == 'O') { long n = tb_pl_num(&p); if (n >= 0) tb_pl_oct = n < 0 ? 0 : n > 6 ? 6 : n; }
        else if (c == '>') { if (tb_pl_oct < 6) tb_pl_oct++; }
        else if (c == '<') { if (tb_pl_oct > 0) tb_pl_oct--; }
        else if (c == 'T') { long n = tb_pl_num(&p); if (n >= 1) tb_pl_tempo = n; }
        else if (c == 'L') { long n = tb_pl_num(&p); if (n >= 1) tb_pl_len = n; }
        else if (c == 'M') {
            int m = *p ? *p++ : 0; if (m >= 'a' && m <= 'z') m -= 32;
            if (m == 'N') tb_pl_art = 7; else if (m == 'L') tb_pl_art = 8;
            else if (m == 'S') tb_pl_art = 6;  /* MF/MB have no meaning here */
        }
        else if (c == 'P' || c == 'R') {
            long l = tb_pl_num(&p); tb_pcm_tone(0, tb_pl_dur(l >= 1 ? l : tb_pl_len, &p), 0);
        }
        else if (c == 'N') {
            long n = tb_pl_num(&p);
            double dur = tb_pl_dur(tb_pl_len, &p);
            if (n <= 0) tb_pcm_tone(0, dur, 0);
            else tb_pcm_tone(261.6255653 * pow(2.0, ((n - 1) - 36) / 12.0), dur, tb_pl_art / 8.0);
        }
        else if (c >= 'A' && c <= 'G') {
            int s = semi[c - 'A'];
            if (*p == '#' || *p == '+') { s++; p++; }
            else if (*p == '-') { s--; p++; }
            long l = tb_pl_num(&p);
            double dur = tb_pl_dur(l >= 1 ? l : tb_pl_len, &p);
            tb_pcm_tone(261.6255653 * pow(2.0, (tb_pl_oct * 12 + s - 36) / 12.0),
                        dur, tb_pl_art / 8.0);
        }
        /* X<var>, =<var>; and unknown letters: no substitution to do here */
    }
}
