/*
    peer, a peer-to-peer foundation
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
#include <gnutls/gnutls.h>
#include "udpstream.h"

struct peer
{
  unsigned int peercount;
  struct udpstream* stream;
  gnutls_session_t tls;
  char handshake;
  uint8_t cmdlength;
  char* cmdname;
  int32_t datalength;
  struct sockaddr addr;
  socklen_t addrlen;
  unsigned char id[20]; // SHA-1 sum of public key (binary)
  // TODO: Account stuff?
};
// Macros for printing peer IDs in printf-family of functions
#define PEERFMT "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define PEERARG(x) x[0],x[1],x[2],x[3],x[4],x[5],x[6],x[7],x[8],x[9],x[10],x[11],x[12],x[13],x[14],x[15],x[16],x[17],x[18],x[19]
extern unsigned char peer_id[20];

extern void peer_registercmd(const char* name, void(*callback)(struct peer*,void*,unsigned int));
extern void peer_init(const char* keypath);
extern struct peer* peer_new(struct udpstream* stream, char server);
extern struct peer* peer_get(struct udpstream* stream);
extern struct peer* peer_new_unique(int sock, struct sockaddr* addr, socklen_t addrlen);
extern void peer_bootstrap(int sock, const char* peerlist);
extern void peer_handlesocket(int sock); // Incoming data
extern void peer_sendcmd(struct peer* peer, const char* cmd, void* data, uint32_t len);
