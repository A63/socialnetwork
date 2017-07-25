LIBS=$(shell pkg-config --libs gnutls)
CFLAGS=-g3 -Wall $(shell pkg-config --cflags gnutls)
PREFIX=/usr

all: socialtest libsocial.so libsocial.pc

libsocial.so: CFLAGS+=-fPIC
libsocial.so: social.o peer.o update.o udpstream.o
	$(CC) -shared $^ $(LIBS) -o $@

libsocial.pc:
	echo 'prefix=$(PREFIX)' > libsocial.pc
	echo 'libdir=$${prefix}/lib' >> libsocial.pc
	echo 'includedir=$${prefix}/include' >> libsocial.pc
	echo 'Name: libsocial (for now)' >> libsocial.pc
	echo 'Version: 0.x' >> libsocial.pc
	echo 'Description: peer-to-peer social network' >> libsocial.pc
	echo 'Libs: -L$${libdir} -lsocial' >> libsocial.pc
	echo 'Cflags: -I$${includedir}/libsocial' >> libsocial.pc

install: libsocial.so libsocial.pc
	install -D libsocial.so $(PREFIX)/lib/libsocial.so
	install -D libsocial.pc $(PREFIX)/lib/pkgconfig/libsocial.pc
	install -D udpstream.h $(PREFIX)/include/libsocial/udpstream.h
	install -D peer.h $(PREFIX)/include/libsocial/peer.h
	install -D buffer.h $(PREFIX)/include/libsocial/buffer.h
	install -D update.h $(PREFIX)/include/libsocial/update.h
	install -D social.h $(PREFIX)/include/libsocial/social.h

socialtest: socialtest.o libsocial.so
	$(CC) $^ -o $@

peertest: peertest.o peer.o udpstream.o
	$(CC) $^ $(LIBS) -o $@

udptest: udptest.o udpstream.o
	$(CC) $^ -o $@

docs:
	mkdir -p Documentation/api/html
	gtkdoc-scan --module=socialnetwork --output-dir=Documentation/api --source-dir=. --rebuild-sections
	cd Documentation/api && gtkdoc-mkdb --module=socialnetwork --output-format=XML --source-dir=../..
	cd Documentation/api/html && gtkdoc-mkhtml socialnetwork ../socialnetwork-docs.xml

clean:
	rm -f *.o *.so socialtest peertest udptest *.pc
