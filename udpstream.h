/*
    udpstream, a reliable network layer on top of UDP
    Copyright (C) 2017  alicia@ion.nu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef UDPSTREAM_H
#define UDPSTREAM_H
#include <sys/socket.h>

struct udpstream;

// Create a new stream on the given socket that sends and receives to/from the given address
extern struct udpstream* udpstream_new(int sock, struct sockaddr* addr, socklen_t addrlen);

extern void udpstream_readsocket(int sock);

// Check which (if any) streams have packets available to read
extern struct udpstream* udpstream_poll(void);

extern ssize_t udpstream_read(struct udpstream* stream, void* buf, size_t size);

extern ssize_t udpstream_write(struct udpstream* stream, const void* buf, size_t size);

// Get the network address of a stream's peer (useful for UDP-punchthrough)
extern void udpstream_getaddr(struct udpstream* stream, struct sockaddr* addr, socklen_t* addrlen);

extern int udpstream_getsocket(struct udpstream* stream);

extern void udpstream_close(struct udpstream* stream);
#endif
