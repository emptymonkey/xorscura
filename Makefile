
CC = /usr/bin/clang
CFLAGS = -std=gnu99 -Wall -Wextra -pedantic -O3

AR = /usr/bin/ar
ARFLAGS = rcs

RANLIB = /usr/bin/ranlib

RM = /bin/rm
RMFLAGS = -f

STRIP = /usr/bin/strip
STRIPFLAGS = --strip-debug --strip-dwo --strip-unneeded --discard-all --discard-locals

##

all: libxorscura.a xorscura example

libxorscura.a: libxorscura.c libxorscura.h
	$(CC) $(CFLAGS) -c libxorscura.c
	$(STRIP) $(STRIPFLAGS) libxorscura.o
	$(AR) $(ARFLAGS) libxorscura.a libxorscura.o
	$(RANLIB) libxorscura.a

xorscura: xorscura.c libxorscura.a
	$(CC) $(CFLAGS) -L. -o xorscura xorscura.c -lxorscura
	$(STRIP) $(STRIPFLAGS) xorscura

example: example.c libxorscura.a
	$(CC) $(CFLAGS) -L. -o example example.c -lxorscura
	$(STRIP) $(STRIPFLAGS) example

clean: 
	$(RM) $(RMFLAGS) libxorscura.o libxorscura.a xorscura example
