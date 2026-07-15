#include "tb_runtime.h"

/* --- optional SDL2 video backend (-DTB_SDL=1) ---
   Presents the graphics framebuffer in a real window instead of (in
   addition to nothing but) the PPM-at-exit surrogate: tb_present() is
   called by every drawing op in graphics.c, uploads tb_fb through the
   palette into a streaming texture, and pumps the SDL event loop so the
   window stays responsive (close = exit).  Keys typed into the window
   feed INKEY$/INSTAT through tb_sdl_inkey()/tb_sdl_instat(), so
   keyboard-driven graphics programs work as they did on DOS.

   The window is 4:3 (like the CRT these modes were designed for) and the
   framebuffer is stretched into it, reproducing the non-square pixels of
   640x200 and friends.  When the program ends with a window open, it is
   held until a key or the close button (set TB_SDL_HOLD=0 to skip).

   Compile with `sdl2-config --cflags`, link `sdl2-config --libs`.  Without
   -DTB_SDL this unit is empty and graphics.c supplies no-op stubs, so the
   fragment always participates in the amalgamation and the library. */
#if TB_SDL
#include <SDL.h>

static SDL_Window *tb_win = 0;
static SDL_Renderer *tb_ren = 0;
static SDL_Texture *tb_tex = 0;
static int tb_tex_w = 0, tb_tex_h = 0;
static Uint32 tb_frame_at = 0;
static int tb_dirty = 0, tb_sdl_dead = 0;
static unsigned tb_kq[64], tb_kh = 0, tb_kt = 0;    /* typed-key queue */

/* same CGA palette as the PPM dump in graphics.c */
static const Uint32 tb_argb[16] = {
    0xFF000000, 0xFF0000AA, 0xFF00AA00, 0xFF00AAAA, 0xFFAA0000, 0xFFAA00AA,
    0xFFAA5500, 0xFFAAAAAA, 0xFF555555, 0xFF5555FF, 0xFF55FF55, 0xFF55FFFF,
    0xFFFF5555, 0xFFFF55FF, 0xFFFFFF55, 0xFFFFFFFF};

static void tb_key_push(unsigned c) {
    if (tb_kt - tb_kh < 64) tb_kq[tb_kt++ & 63] = c;
}
static void tb_pump(void) {
    SDL_Event e;
    while (SDL_PollEvent(&e)) {
        if (e.type == SDL_QUIT) exit(0);
        if (e.type == SDL_TEXTINPUT)
            for (const char *p = e.text.text; *p; p++)
                tb_key_push((unsigned char)*p);
        if (e.type == SDL_KEYDOWN) {
            SDL_Keycode k = e.key.keysym.sym;
            if (k == SDLK_RETURN) tb_key_push('\r');
            else if (k == SDLK_BACKSPACE) tb_key_push(8);
            else if (k == SDLK_TAB) tb_key_push(9);
            else if (k == SDLK_ESCAPE) tb_key_push(27);
        }
    }
}
static void tb_hold_at_exit(void) {
    const char *h = getenv("TB_SDL_HOLD");
    if (!tb_win || (h && !strcmp(h, "0"))) return;
    for (SDL_Event e; SDL_WaitEvent(&e);)
        if (e.type == SDL_QUIT || e.type == SDL_KEYDOWN) return;
}
static void tb_render(void) {
    tb_dirty = 0;
    if (!tb_fb || tb_sdl_dead) return;
    if (!tb_win) {
        if (SDL_Init(SDL_INIT_VIDEO) != 0) { tb_sdl_dead = 1; return; }
        tb_win = SDL_CreateWindow("tbx", SDL_WINDOWPOS_CENTERED,
                                  SDL_WINDOWPOS_CENTERED, 960, 720,
                                  SDL_WINDOW_RESIZABLE);
        if (!tb_win) { tb_sdl_dead = 1; return; }
        tb_ren = SDL_CreateRenderer(tb_win, -1, 0);
        if (!tb_ren) tb_ren = SDL_CreateRenderer(tb_win, -1,
                                                 SDL_RENDERER_SOFTWARE);
        if (!tb_ren) { tb_sdl_dead = 1; return; }
        SDL_StartTextInput();
        atexit(tb_hold_at_exit);
    }
    if (!tb_tex || tb_tex_w != tb_gw || tb_tex_h != tb_gh) {
        if (tb_tex) SDL_DestroyTexture(tb_tex);
        tb_tex = SDL_CreateTexture(tb_ren, SDL_PIXELFORMAT_ARGB8888,
                                   SDL_TEXTUREACCESS_STREAMING, tb_gw, tb_gh);
        if (!tb_tex) { tb_sdl_dead = 1; return; }
        tb_tex_w = tb_gw; tb_tex_h = tb_gh;
    }
    void *px; int pitch;
    if (SDL_LockTexture(tb_tex, NULL, &px, &pitch) == 0) {
        for (int y = 0; y < tb_gh; y++) {
            Uint32 *row = (Uint32 *)((char *)px + (size_t)y * pitch);
            for (int x = 0; x < tb_gw; x++)
                row[x] = tb_argb[tb_pal[tb_fb[y * tb_gw + x] & 15] & 15];
        }
        SDL_UnlockTexture(tb_tex);
    }
    SDL_RenderClear(tb_ren);
    /* stretch to the whole (4:3 by default) window: DOS pixels were not
       square, the CRT was */
    SDL_RenderCopy(tb_ren, tb_tex, NULL, NULL);
    SDL_RenderPresent(tb_ren);
}
void tb_present(void) {
    tb_dirty = 1;
    if (!tb_fb || tb_sdl_dead) return;
    tb_pump();
    Uint32 now = SDL_GetTicks();
    if (tb_win && now - tb_frame_at < 16) return;       /* ~60 fps cap */
    tb_frame_at = now;
    tb_render();
}
int tb_sdl_inkey(void) {
    if (!tb_win) return -1;
    tb_pump();
    if (tb_dirty) tb_render();                          /* settle the frame */
    return tb_kh == tb_kt ? 0 : (int)tb_kq[tb_kh++ & 63];
}
int tb_sdl_instat(void) {
    if (!tb_win) return -1;
    tb_pump();
    return tb_kh != tb_kt;
}
#endif /* TB_SDL */
