LIBS=$(shell pkg-config --libs gnutls)
CFLAGS=-g3 $(shell pkg-config --cflags gnutls)

peertest: peertest.o peer.o udpstream.o
	$(CC) $^ $(LIBS) -o $@

udptest: udptest.o udpstream.o
	$(CC) $^ -o $@
