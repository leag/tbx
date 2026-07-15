# Build the Turbo Basic runtime as an ordinary static library.
#
#   make                 -> libtbrt.a
#   make SDL=1           -> libtbrt.a with the SDL2 video backend compiled in
#                           (programs then also link `sdl2-config --libs`)
#
# A program emitted with `tbx PROG.EXE --emit-c --no-runtime` builds as
#
#   cc prog.c -I<this dir> -L<this dir> -ltbrt -lm
#
# (add -DTB_SDL=1 to the program's compile when the library was made SDL=1).
# gcc or clang required: GOSUB/RETURN in generated code use labels-as-values.
CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -Wall

OBJS = core.o fileio.o terminal.o graphics.o play.o events.o machine.o sdl.o

ifeq ($(SDL),1)
CFLAGS += -DTB_SDL=1 $(shell sdl2-config --cflags)
endif

libtbrt.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c tb_runtime.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) libtbrt.a

.PHONY: clean
