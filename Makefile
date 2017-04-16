
CC = /usr/bin/gcc
CFLAGS = -std=gnu99 -Wall -Wextra -pedantic -O3

AR = /usr/bin/ar
ARFLAGS = rcs

RANLIB = /usr/bin/ranlib

RM = /bin/rm
RMFLAGS = -f

STRIP = /usr/bin/strip

##

all: libxorscura.a xorscura example

libxorscura.a: libxorscura.c libxorscura.h
	$(CC) $(CFLAGS) -c libxorscura.c
	$(AR) $(ARFLAGS) libxorscura.a libxorscura.o
	$(RANLIB) libxorscura.a

xorscura: xorscura.c libxorscura.a
	$(CC) $(CFLAGS) -L. -o xorscura xorscura.c -lxorscura

example: example.c libxorscura.a
	$(CC) $(CFLAGS) -L. -o example example.c -lxorscura
	$(STRIP) example

clean: 
	$(RM) $(RMFLAGS) libxorscura.o libxorscura.a xorscura example
