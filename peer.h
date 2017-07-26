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
/**
* SECTION:peer
* @title: Peer
* @short_description: Handles peering and secure communication between peers
*
* Handles peering and secure communication between peers
*/
#ifndef PEER_H
#define PEER_H
#include <stdint.h>
#include <gnutls/gnutls.h>
#include "udpstream.h"
/**
* ID_SIZE:
*
* Number of bytes required to store a (binary) peer ID
*/
#define ID_SIZE 32

/**
* peer:
* @peercount: The number of other peers this peer is connected to
* @stream: The UDP stream connection to this peer
* @tls: The TLS session on top of the UDP stream
* @handshake: Whether the TLS handshake has been completed
* @cmdlength: Length of an incomplete incoming command's name
* @cmdname: Name of incomplete incoming command
* @datalength: Length of an incomplete incoming command's data/parameters
* @addr: Peer's address
* @addrlen: Length of peer's address
* @id: User ID, binary SHA2-256 fingerprint of public key
* @cert: Certificate, containing the full public key
*
* A peer
*/
struct peer
{
  unsigned int peercount;
  struct udpstream* stream;
  gnutls_session_t tls;
  char handshake;
  uint8_t cmdlength;
  char* cmdname;
  int32_t datalength;
  struct sockaddr_storage addr;
  socklen_t addrlen;
  unsigned char id[ID_SIZE];
  gnutls_x509_crt_t cert;
  // TODO: Account stuff?
};

/**
* PEERFMT:
*
* Format string for printing peer IDs using the printf-family of functions, combine with PEERARG()
*/
#define PEERFMT "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
/**
* PEERARG:
* @x: Binary peer ID
*
* Utility macro for printing peer IDs using the printf-family of functions, combine with #PEERFMT
*/
#define PEERARG(x) x[0],x[1],x[2],x[3],x[4],x[5],x[6],x[7],x[8],x[9],x[10],x[11],x[12],x[13],x[14],x[15],x[16],x[17],x[18],x[19],x[20],x[21],x[22],x[23],x[24],x[25],x[26],x[27],x[28],x[29],x[30],x[31]
extern unsigned char peer_id[ID_SIZE];
extern gnutls_privkey_t peer_privkey;

/**
* peer_registercmd:
* @name: Command
* @callback: Function to handle the command.
* Called with a pointer to the sender's #peer structure,
* a pointer to parameter data, and the length of the data
*
* Registers a callback to handle the specified command
*/
extern void peer_registercmd(const char* name, void(*callback)(struct peer*,void*,unsigned int));
extern void peer_init(const char* keypath);
extern struct peer* peer_new(struct udpstream* stream, char server);
extern struct peer* peer_get(struct udpstream* stream);
extern struct peer* peer_new_unique(int sock, struct sockaddr_storage* addr, socklen_t addrlen);
extern void peer_bootstrap(int sock, const char* peerlist);
/**
* peer_handlesocket:
* @sock: UDP socket
*
* Handle incoming network data, calls callbacks registered with peer_registercmd()
*/
extern void peer_handlesocket(int sock);
/**
* peer_sendcmd:
* @peer: Recipient peer
* @cmd: Command name
* @data: Parameter data
* @len: Length of data
*
* Send a command/request to another peer
*/
extern void peer_sendcmd(struct peer* peer, const char* cmd, const void* data, uint32_t len);
extern void peer_disconnect(struct peer* peer, char cleanly);
/**
* peer_findpeer:
* @id: Peer ID
*
* Find and ask a peer to connect to us
*/
extern void peer_findpeer(const unsigned char id[ID_SIZE]);
/**
* peer_findbyid:
* @id: Peer ID
*
* Get the #peer struct of a connected peer by its ID
*/
extern struct peer* peer_findbyid(const unsigned char id[ID_SIZE]);
/**
* peer_exportpeers:
* @path: Filename to write the list to
*
* Generate a list of peer addresses for bootstrapping
*/
extern void peer_exportpeers(const char* path);
#endif
