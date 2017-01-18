LIBS=$(shell pkg-config --libs gnutls)
CFLAGS=-g3 -Wall $(shell pkg-config --cflags gnutls)

socialtest: socialtest.o libsocial.so
	$(CC) $^ -Wl,-R. -o $@

libsocial.so: CFLAGS+=-fPIC
libsocial.so: social.o peer.o update.o udpstream.o
	$(CC) -shared $^ $(LIBS) -o $@

peertest: peertest.o peer.o udpstream.o
	$(CC) $^ $(LIBS) -o $@

udptest: udptest.o udpstream.o
	$(CC) $^ -o $@

clean:
	rm -f *.o *.so socialtest peertest udptest
