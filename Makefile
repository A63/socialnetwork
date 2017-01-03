LIBS=$(shell pkg-config --libs gnutls)
CFLAGS=-g3 $(shell pkg-config --cflags gnutls)

udptest: udptest.o udpstream.o
	$(CC) $^ -o $@
