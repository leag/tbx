/* --- graphics: in-memory framebuffer with CGA/EGA geometry ---
   There is no screen on a headless modern host, so SCREEN n allocates a
   byte-per-pixel framebuffer instead; a first graphics call without SCREEN
   enters mode 1 (320x200) implicitly. Set TB_SCREEN_PPM=file.ppm to dump
   the final image (CGA palette) at exit. */
static int tb_gw = 0, tb_gh = 0, tb_maxattr = 3;
static unsigned char *tb_fb = 0;
static double tb_lastx = 0, tb_lasty = 0;                /* STEP reference */
static int tb_vx1, tb_vy1, tb_vx2, tb_vy2, tb_vabs = 0;  /* viewport */
static int tb_wset = 0, tb_wabs = 0;
static double tb_wx1, tb_wy1, tb_wx2, tb_wy2;            /* WINDOW rect */
static int tb_pal[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
#if TB_FILE_DEVICES
static void tb_ppm_dump(void) {
    const char *path = getenv("TB_SCREEN_PPM");
    if (!path || !tb_fb) return;
    static const unsigned char pal[16][3] = {
        {0,0,0},{0,0,170},{0,170,0},{0,170,170},{170,0,0},{170,0,170},
        {170,85,0},{170,170,170},{85,85,85},{85,85,255},{85,255,85},
        {85,255,255},{255,85,85},{255,85,255},{255,255,85},{255,255,255}};
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fprintf(f, "P6\n%d %d\n255\n", tb_gw, tb_gh);
    for (long i = 0; i < (long)tb_gw * tb_gh; i++)
        fwrite(pal[tb_pal[tb_fb[i] & 15] & 15], 1, 3, f);
    fclose(f);
}
#endif
static void tb_screen(double mode) {
    static const struct { int m, w, h, a; } md[] = {
        {1,320,200,3},{2,640,200,1},{7,320,200,15},{8,640,200,15},
        {9,640,350,15},{10,640,350,3}};
    int m = (int)mode;
    if (m == 0) { free(tb_fb); tb_fb = 0; tb_gw = tb_gh = 0; return; }
    for (unsigned i = 0; i < sizeof md / sizeof *md; i++)
        if (md[i].m == m) {
            tb_gw = md[i].w; tb_gh = md[i].h;
            tb_maxattr = md[i].a; tb_fg = md[i].a;
            free(tb_fb);
            tb_fb = tb_calloc((long)tb_gw * tb_gh, 1);
            tb_vx1 = tb_vy1 = 0; tb_vx2 = tb_gw - 1; tb_vy2 = tb_gh - 1;
            tb_vabs = tb_wset = 0; tb_lastx = tb_lasty = 0;
#if TB_FILE_DEVICES
            static int reg = 0;
            if (!reg) { reg = 1; atexit(tb_ppm_dump); }
#endif
            return;
        }
    tb_error(5);                                         /* illegal function call */
}
static void tb_gfx(void) { if (!tb_fb) tb_screen(1); }
static void tb_map(double x, double y, long *px, long *py) {
    if (tb_wset) {
        x = tb_vx1 + (x - tb_wx1) * (tb_vx2 - tb_vx1) / (tb_wx2 - tb_wx1);
        y = tb_wabs
            ? tb_vy1 + (y - tb_wy1) * (tb_vy2 - tb_vy1) / (tb_wy2 - tb_wy1)
            : tb_vy1 + (tb_wy2 - y) * (tb_vy2 - tb_vy1) / (tb_wy2 - tb_wy1);
    } else if (!tb_vabs) { x += tb_vx1; y += tb_vy1; }
    *px = lround(x); *py = lround(y);
}
static void tb_px(long x, long y, int c) {
    if (!tb_fb || x < tb_vx1 || x > tb_vx2 || y < tb_vy1 || y > tb_vy2) return;
    tb_fb[y * tb_gw + x] = (unsigned char)(c & 15);
}
static double tb_pointf(double x, double y) {
    long px, py;
    tb_gfx(); tb_map(x, y, &px, &py);
    if (px < 0 || px >= tb_gw || py < 0 || py >= tb_gh) return -1;
    return tb_fb[py * tb_gw + px];
}
static void tb_step(double *x, double *y, int step) {
    if (step) { *x += tb_lastx; *y += tb_lasty; }
}
static void tb_pset(double x, double y, int step, int has_c, double c, int preset) {
    long px, py;
    tb_gfx(); tb_step(&x, &y, step);
    tb_map(x, y, &px, &py);
    tb_px(px, py, has_c ? (int)c : preset ? 0 : tb_fg);
    tb_lastx = x; tb_lasty = y;
}
static void tb_line_px(long x1, long y1, long x2, long y2, int c, unsigned style) {
    long dx = labs(x2 - x1), sx = x1 < x2 ? 1 : -1;
    long dy = -labs(y2 - y1), sy = y1 < y2 ? 1 : -1, err = dx + dy;
    unsigned bit = 0x8000;
    for (;;) {
        if (style & bit) tb_px(x1, y1, c);
        bit = bit >> 1 ? bit >> 1 : 0x8000;
        if (x1 == x2 && y1 == y2) break;
        long e2 = 2 * err;
        if (e2 >= dy) { err += dy; x1 += sx; }
        if (e2 <= dx) { err += dx; y1 += sy; }
    }
}
static void tb_linestmt(double x1, double y1, int s1, double x2, double y2, int s2,
                        int has_c, double c, int box, int fill, unsigned style) {
    long px1, py1, px2, py2;
    tb_gfx();
    tb_step(&x1, &y1, s1);
    tb_lastx = x1; tb_lasty = y1;                        /* second STEP chains */
    tb_step(&x2, &y2, s2);
    tb_map(x1, y1, &px1, &py1); tb_map(x2, y2, &px2, &py2);
    int col = has_c ? (int)c : tb_fg;
    if (fill) {
        if (py1 > py2) { long t = py1; py1 = py2; py2 = t; }
        for (long y = py1; y <= py2; y++) tb_line_px(px1, y, px2, y, col, style);
    } else if (box) {
        tb_line_px(px1, py1, px2, py1, col, style);
        tb_line_px(px2, py1, px2, py2, col, style);
        tb_line_px(px2, py2, px1, py2, col, style);
        tb_line_px(px1, py2, px1, py1, col, style);
    } else {
        tb_line_px(px1, py1, px2, py2, col, style);
    }
    tb_lastx = x2; tb_lasty = y2;
}
static void tb_circle(double x, double y, double r, int step, int has_c, double c,
                      double sa, double ea, double aspect) {
    long cx, cy;
    tb_gfx(); tb_step(&x, &y, step);
    tb_map(x, y, &cx, &cy);
    int col = has_c ? (int)c : tb_fg;
    double rx = r, ry = r;
    if (aspect <= 0) aspect = (4.0 / 3.0) * tb_gh / tb_gw;
    if (aspect < 1) ry = r * aspect; else rx = r / aspect;
    int line_s = sa < 0, line_e = ea < 0;
    sa = fabs(sa); ea = fabs(ea);
    if (ea <= sa && !(sa == 0 && ea == 0)) ea += 6.283185307179586;
    if (sa == 0 && ea == 0) ea = 6.283185307179586;
    double dt = 1.0 / (rx > ry ? rx : ry);
    if (dt > 0.05) dt = 0.05;
    for (double t = sa; t <= ea; t += dt)
        tb_px(lround(cx + rx * cos(t)), lround(cy - ry * sin(t)), col);
    if (line_s) tb_line_px(cx, cy, lround(cx + rx * cos(sa)), lround(cy - ry * sin(sa)), col, 0xFFFF);
    if (line_e) tb_line_px(cx, cy, lround(cx + rx * cos(ea)), lround(cy - ry * sin(ea)), col, 0xFFFF);
    tb_lastx = x; tb_lasty = y;
}
static void tb_paint(double x, double y, int has_p, double p, int has_b, double b) {
    long sx, sy;
    tb_gfx(); tb_map(x, y, &sx, &sy);
    int paint = has_p ? (int)p : tb_fg, border = has_b ? (int)b : paint;
    if (sx < 0 || sx >= tb_gw || sy < 0 || sy >= tb_gh) return;
    long cap = (long)tb_gw * tb_gh, n = 0;
    long *stack = tb_calloc(cap, sizeof(long));
    stack[n++] = sy * tb_gw + sx;
    while (n) {
        long i = stack[--n], px = i % tb_gw, py = i / tb_gw;
        if (px < tb_vx1 || px > tb_vx2 || py < tb_vy1 || py > tb_vy2) continue;
        if (tb_fb[i] == border || tb_fb[i] == paint) continue;
        tb_fb[i] = (unsigned char)paint;
        if (n + 4 <= cap) {
            if (px > 0) stack[n++] = i - 1;
            if (px < tb_gw - 1) stack[n++] = i + 1;
            if (py > 0) stack[n++] = i - tb_gw;
            if (py < tb_gh - 1) stack[n++] = i + tb_gw;
        }
    }
    free(stack);
}
/* GET/PUT blit: internal layout [long w][long h][one byte per pixel] laid
   into the array's storage, clipped to its capacity in bytes */
static void tb_getgfx(void *buf, long cap, double x1, double y1, double x2, double y2) {
    long px1, py1, px2, py2;
    tb_gfx(); tb_map(x1, y1, &px1, &py1); tb_map(x2, y2, &px2, &py2);
    if (px1 > px2) { long t = px1; px1 = px2; px2 = t; }
    if (py1 > py2) { long t = py1; py1 = py2; py2 = t; }
    long w = px2 - px1 + 1, h = py2 - py1 + 1;
    unsigned char *p = buf;
    if (cap < (long)(2 * sizeof(long))) tb_error(5);
    memcpy(p, &w, sizeof w); memcpy(p + sizeof w, &h, sizeof h);
    p += 2 * sizeof(long); cap -= 2 * sizeof(long);
    for (long y = 0; y < h; y++)
        for (long x = 0; x < w; x++) {
            if (cap-- <= 0) return;
            long fx = px1 + x, fy = py1 + y;
            *p++ = (fx >= 0 && fx < tb_gw && fy >= 0 && fy < tb_gh)
                       ? tb_fb[fy * tb_gw + fx] : 0;
        }
}
static void tb_putgfx(void *buf, long cap, double x, double y, int pset_action) {
    long px, py, w, h;
    tb_gfx(); tb_map(x, y, &px, &py);
    unsigned char *p = buf;
    if (cap < (long)(2 * sizeof(long))) tb_error(5);
    memcpy(&w, p, sizeof w); memcpy(&h, p + sizeof w, sizeof h);
    p += 2 * sizeof(long); cap -= 2 * sizeof(long);
    for (long dy = 0; dy < h; dy++)
        for (long dx = 0; dx < w; dx++) {
            if (cap-- <= 0) return;
            unsigned char v = *p++;
            long fx = px + dx, fy = py + dy;
            if (fx < 0 || fx >= tb_gw || fy < 0 || fy >= tb_gh) continue;
            unsigned char *dst = &tb_fb[fy * tb_gw + fx];
            /* action: 0=XOR (default), 1=PSET, 2=PRESET (complement), 3=AND, 4=OR */
            *dst = pset_action == 1 ? v
                 : pset_action == 2 ? (unsigned char)(~v & tb_maxattr)
                 : pset_action == 3 ? (unsigned char)(*dst & v)
                 : pset_action == 4 ? (unsigned char)(*dst | v)
                 : (unsigned char)((*dst ^ v) & 15);
        }
}
static void tb_view(int has_rect, double x1, double y1, double x2, double y2,
                    int absolute, int has_c, double c, int has_b, double b) {
    tb_gfx();
    if (!has_rect) {
        tb_vx1 = tb_vy1 = 0; tb_vx2 = tb_gw - 1; tb_vy2 = tb_gh - 1;
        tb_vabs = 0; return;
    }
    tb_vx1 = lround(x1); tb_vy1 = lround(y1);
    tb_vx2 = lround(x2); tb_vy2 = lround(y2);
    tb_vabs = absolute;
    if (has_c)
        for (long yy = tb_vy1; yy <= tb_vy2; yy++)
            for (long xx = tb_vx1; xx <= tb_vx2; xx++)
                if (xx >= 0 && xx < tb_gw && yy >= 0 && yy < tb_gh)
                    tb_fb[yy * tb_gw + xx] = (unsigned char)((int)c & 15);
    if (has_b) {
        int ox1 = tb_vx1, oy1 = tb_vy1, ox2 = tb_vx2, oy2 = tb_vy2;
        tb_vx1 = 0; tb_vy1 = 0; tb_vx2 = tb_gw - 1; tb_vy2 = tb_gh - 1;
        tb_line_px(ox1 - 1, oy1 - 1, ox2 + 1, oy1 - 1, (int)b, 0xFFFF);
        tb_line_px(ox2 + 1, oy1 - 1, ox2 + 1, oy2 + 1, (int)b, 0xFFFF);
        tb_line_px(ox2 + 1, oy2 + 1, ox1 - 1, oy2 + 1, (int)b, 0xFFFF);
        tb_line_px(ox1 - 1, oy2 + 1, ox1 - 1, oy1 - 1, (int)b, 0xFFFF);
        tb_vx1 = ox1; tb_vy1 = oy1; tb_vx2 = ox2; tb_vy2 = oy2;
    }
}
static void tb_window(int has_rect, double x1, double y1, double x2, double y2, int absolute) {
    tb_gfx();
    if (!has_rect) { tb_wset = 0; return; }
    tb_wset = 1; tb_wabs = absolute;
    tb_wx1 = x1; tb_wy1 = y1; tb_wx2 = x2; tb_wy2 = y2;
}
static void tb_draw(const char *cmd) {
    tb_gfx();
    const char *p = tb_s(cmd);
    double scale = 1;
    while (*p) {
        char op = *p >= 'a' && *p <= 'z' ? (char)(*p - 32) : *p;
        p++;
        if (op == ' ' || op == ';') continue;
        int blank = 0, back = 0;
        while (op == 'B' || op == 'N') {
            if (op == 'B') blank = 1; else back = 1;
            op = *p >= 'a' && *p <= 'z' ? (char)(*p - 32) : *p;
            if (!op) return;
            p++;
        }
        int rel = *p == '+' || *p == '-';
        long a = 0; int got = 0, neg = *p == '-';
        if (rel) p++;
        while (*p >= '0' && *p <= '9') { a = a * 10 + (*p++ - '0'); got = 1; }
        if (neg) a = -a;
        double n = (got ? a : 1) * scale;
        double dx = 0, dy = 0;
        switch (op) {
        case 'U': dy = -n; break;
        case 'D': dy = n; break;
        case 'L': dx = -n; break;
        case 'R': dx = n; break;
        case 'E': dx = n; dy = -n; break;
        case 'F': dx = n; dy = n; break;
        case 'G': dx = -n; dy = n; break;
        case 'H': dx = -n; dy = -n; break;
        case 'C': tb_fg = (int)a & 15; continue;
        case 'S': scale = a / 4.0; continue;
        case 'M': {
            /* M[+|-]x,y -- a signed x makes the whole move relative */
            if (*p == ',') p++;
            long b = 0; int neg2 = *p == '-';
            if (*p == '+' || *p == '-') p++;
            while (*p >= '0' && *p <= '9') b = b * 10 + (*p++ - '0');
            if (neg2) b = -b;
            if (rel) { dx = a; dy = b; }
            else { dx = a - tb_lastx; dy = b - tb_lasty; }
            break;
        }
        default: tb_error(5);
        }
        double nx = tb_lastx + dx, ny = tb_lasty + dy;
        if (!blank) {
            long ax, ay, bx, by;
            tb_map(tb_lastx, tb_lasty, &ax, &ay); tb_map(nx, ny, &bx, &by);
            tb_line_px(ax, ay, bx, by, tb_fg, 0xFFFF);
        }
        if (!back) { tb_lastx = nx; tb_lasty = ny; }
    }
}
static double tb_pmap(double v, double n) {
    long px, py;
    tb_gfx();
    switch ((int)n) {
    case 0: tb_map(v, 0, &px, &py); return (double)px;
    case 1: tb_map(0, v, &px, &py); return (double)py;
    case 2:
        if (!tb_wset) return v - (tb_vabs ? 0 : tb_vx1);
        return tb_wx1 + (v - tb_vx1) * (tb_wx2 - tb_wx1) / (tb_vx2 - tb_vx1);
    case 3:
        if (!tb_wset) return v - (tb_vabs ? 0 : tb_vy1);
        return tb_wabs
            ? tb_wy1 + (v - tb_vy1) * (tb_wy2 - tb_wy1) / (tb_vy2 - tb_vy1)
            : tb_wy2 - (v - tb_vy1) * (tb_wy2 - tb_wy1) / (tb_vy2 - tb_vy1);
    }
    tb_error(5);
    return 0;
}
