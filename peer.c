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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include "udpstream.h"
#include "peer.h"
#define GOOD_NUMBER_OF_PEERS 20

struct command
{
  const char* name;
  void(*callback)(struct peer*,void*,unsigned int);
};

static struct peer** peers=0;
static unsigned int peercount=0;
static struct command* commands=0;
static unsigned int commandcount=0;

void peer_registercmd(const char* name, void(*callback)(struct peer*,void*,unsigned int))
{
  ++commandcount;
  commands=realloc(commands, sizeof(struct command)*commandcount);
  commands[commandcount-1].name=strdup(name);
  commands[commandcount-1].callback=callback;
}

static void sendpeers(struct peer* peer, void* x, unsigned int len)
{
  len=0;
  uint16_t addrlen; // 64kb should be enough for addresses for a while, right?
  uint16_t pcount;
  unsigned int i;
  for(i=0; i<peercount; ++i)
  {
    if(!peers[i]->handshake){continue;} // Don't share incomplete/broken peers
    len+=sizeof(addrlen)+peers[i]->addrlen+sizeof(pcount);
  }
  char data[len];
  x=data;
  for(i=0; i<peercount; ++i)
  {
    if(!peers[i]->handshake){continue;} // Don't share incomplete/broken peers
    addrlen=peers[i]->addrlen;
    memcpy(x, &addrlen, sizeof(addrlen));
    x+=sizeof(addrlen);
    memcpy(x, &peers[i]->addr, addrlen);
    x+=addrlen;
    pcount=peers[i]->peercount;
    memcpy(x, &pcount, sizeof(pcount));
    x+=sizeof(pcount);
  }
  peer_sendcmd(peer, "peers", data, len);
}

struct peeritem
{
  uint16_t addrlen;
  struct sockaddr addr;
  uint16_t peercount;
};
static void getpeers(struct peer* peer, void* data, unsigned int len)
{
  // Receiving list of peer's peers
  uint16_t addrlen;
  struct peeritem* peers=0;
  unsigned int pcount=0;
  // Compose a temporary list and then pick the lowest peer-counts until we have GOOD_NUMBER_OF_PEERS peers (or we exhausted the list)
  while(len>sizeof(addrlen))
  {
    memcpy(&addrlen, data, sizeof(addrlen));
    if(len<sizeof(addrlen)+addrlen+sizeof(pcount)){break;}
    if(addrlen<=sizeof(struct sockaddr))
    {
      ++pcount;
      peers=realloc(peers, sizeof(struct peeritem)*pcount);
      peers[pcount-1].addrlen=addrlen;
      memcpy(&peers[pcount-1].addr, data+sizeof(addrlen), addrlen);
      memcpy(&peers[pcount-1].peercount, data+sizeof(addrlen)+addrlen, sizeof(uint16_t));
    }
    data+=sizeof(addrlen)+addrlen+sizeof(uint16_t);
    len-=sizeof(addrlen)+addrlen+sizeof(uint16_t);
  }
  peer->peercount=pcount;
  int sock=udpstream_getsocket(peer->stream);
  while(pcount && peercount<GOOD_NUMBER_OF_PEERS)
  {
// TODO: Ditch current peers with higher peer counts if we have more than necessary
    unsigned int lowest=0;
    unsigned int i;
    for(i=1; i<pcount; ++i)
    {
      if(peers[i].peercount<peers[lowest].peercount){lowest=i;}
    }
    peer_new_unique(sock, &peers[lowest].addr, peers[lowest].addrlen);
    --pcount;
    memmove(&peers[lowest], &peers[lowest+1], sizeof(struct peeritem)*(pcount-lowest));
  }
  free(peers);
printf("We now have %u peers\n", peercount);
}

void peer_init(void)
{
  gnutls_global_init();
  peer_registercmd("getpeers", sendpeers);
  peer_registercmd("peers", getpeers);
}

static int checkcert(gnutls_session_t tls)
{
  // Find which peer the session belongs to
  struct peer* peer=0;
  unsigned int i;
  for(i=0; i<peercount; ++i)
  {
    if(peers[i]->tls==tls){peer=peers[i]; break;}
  }
  if(!peer){return 1;}

  // Get its certificate
  unsigned int count;
  const gnutls_datum_t* certs=gnutls_certificate_get_peers(tls, &count);
  if(!count){return 1;}
  gnutls_x509_crt_t cert;
  gnutls_x509_crt_init(&cert);
  int x=gnutls_x509_crt_import(cert, certs, GNUTLS_X509_FMT_DER);
  // Get the certificate's public key ID
  size_t size=20;
  gnutls_x509_crt_get_key_id(cert, 0, peer->id, &size);
  gnutls_x509_crt_deinit(cert);
// TODO: Make sure the ID is unique? and not ours?
  return 0;
}

static void generatecert(gnutls_certificate_credentials_t cred)
{
// TODO: Configurable key path
  // Load our private key, or generate one if we don't have one yet
  static gnutls_x509_privkey_t key=0;
  if(!key)
  {
    gnutls_x509_privkey_init(&key);
    struct stat st;
    char loadfailed=1;
    if(!stat("priv.pem", &st))
    {
      gnutls_datum_t keydata;
      keydata.size=st.st_size;
      keydata.data=malloc(st.st_size);
      int f=open("priv.pem", O_RDONLY);
      read(f, keydata.data, st.st_size);
      close(f);
      // TODO: Allow encrypted keys, using _import2()
      if(!gnutls_x509_privkey_import2(key, &keydata, GNUTLS_X509_FMT_PEM, 0, GNUTLS_PKCS_PLAIN)){loadfailed=0;}
      free(keydata.data);
    }
    if(loadfailed)
    {
// printf("Generating a new key...\n");
      // TODO: Why do handshakes fail with >3072 bit keys?
      gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, 3072, 0);
// printf("Done\n");
      // TODO: Allow exporting encrypted key, using _export2_pkcs8() I think
      gnutls_datum_t keydata;
      gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_PEM, &keydata);
      int f=open("priv.pem", O_WRONLY|O_TRUNC|O_CREAT, 0600);
      write(f, keydata.data, keydata.size);
      close(f);
      gnutls_free(keydata.data);
    }
  }
  // Generate the certificate
  gnutls_x509_crt_t cert;
  gnutls_datum_t certdata;
  gnutls_x509_crt_init(&cert);
  gnutls_x509_crt_set_key(cert, key);
  gnutls_x509_crt_set_serial(cert, "", 1);
  gnutls_x509_crt_set_activation_time(cert, time(0)-3600); // Allow up to an hour of time drift
  gnutls_x509_crt_set_expiration_time(cert, time(0)+3600);
  gnutls_x509_crt_sign(cert, cert, key);
  gnutls_certificate_set_x509_key(cred, &cert, 1, key);
  gnutls_x509_crt_deinit(cert);
}

struct peer* peer_new(struct udpstream* stream, char server)
{
  struct peer* peer=malloc(sizeof(struct peer));
  peer->peercount=0;
  peer->stream=stream;
  peer->handshake=0;
  peer->cmdlength=0;
  peer->cmdname=0;
  peer->datalength=-1;
  peer->addrlen=sizeof(peer->addr);
  udpstream_getaddr(stream, &peer->addr, &peer->addrlen);
  gnutls_init(&peer->tls, (server?GNUTLS_SERVER:GNUTLS_CLIENT)|GNUTLS_NONBLOCK);
  // Priority
  gnutls_priority_set_direct(peer->tls, "NORMAL", 0);
  // Credentials
  gnutls_certificate_credentials_t cert;
  gnutls_certificate_allocate_credentials(&cert);
  generatecert(cert);
  gnutls_certificate_set_verify_function(cert, checkcert);
  gnutls_credentials_set(peer->tls, GNUTLS_CRD_CERTIFICATE, cert);
  gnutls_certificate_server_set_request(peer->tls, GNUTLS_CERT_REQUIRE);

  gnutls_transport_set_push_function(peer->tls, (gnutls_push_func)udpstream_write);
  gnutls_transport_set_pull_function(peer->tls, (gnutls_pull_func)udpstream_read);

  gnutls_transport_set_ptr(peer->tls, stream);
  peer->handshake=!gnutls_handshake(peer->tls);
  // TODO: handle gnutls_error_is_fatal(x)

  ++peercount;
  peers=realloc(peers, sizeof(struct peer)*peercount);
  peers[peercount-1]=peer;
  return peer;
}

struct peer* peer_get(struct udpstream* stream)
{
  unsigned int i;
  for(i=0; i<peercount; ++i)
  {
    if(peers[i]->stream==stream){return peers[i];}
  }
  return peer_new(stream, 1);
}

struct peer* peer_new_unique(int sock, struct sockaddr* addr, socklen_t addrlen)
{
  unsigned int i;
  // Make sure we're not already connected to this peer
  for(i=0; i<peercount; ++i)
  {
    if(addrlen==peers[i]->addrlen && !memcmp(addr, &peers[i]->addr, addrlen)){return 0;}
  }
  struct udpstream* stream=udpstream_new(sock, addr, addrlen);
  return peer_new(stream, 0);
}

void peer_bootstrap(int sock, const char* peerlist)
{
  const char* entry=peerlist;
  while(entry)
  {
    while(strchr("\r\n ", entry[0])){entry=&entry[1];}
    const char* end=strchr(entry, '\n');
    if(!end){end=&entry[strlen(entry)];}
    char peer[end-entry+1];
    memcpy(peer, entry, end-entry);
    peer[end-entry]=0;
    entry=(end[0]?&end[1]:0);
    char* port;
    if((port=strchr(peer, '\r'))){port[0]=0;}
    if(!(port=strchr(peer, ':'))){continue;} // Bogus entry
    port[0]=0;
    struct addrinfo* ai;
    getaddrinfo(peer, &port[1], 0, &ai);
    peer_new_unique(sock, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
  }
}

void peer_handlesocket(int sock) // Incoming data
{
  udpstream_readsocket(sock); // If it locks up here we're probably missing a bootstrap node
  struct udpstream* stream;
  while((stream=udpstream_poll()))
  {
    struct peer* peer=peer_get(stream);
    if(!peer->handshake)
    {
// TODO: GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET seems to indicate we're connecting to ourselves
      peer->handshake=!gnutls_handshake(peer->tls);
  // TODO: handle gnutls_error_is_fatal(x)?
      if(peer->handshake)
      {
        peer_sendcmd(peer, "getpeers", 0, 0);
      }
      continue;
    }
    // Get command name, data, and then call the callbacks registered for the command
    if(!peer->cmdlength)
    {
      udpstream_read(peer->stream, &peer->cmdlength, sizeof(peer->cmdlength));
    }
    else if(!peer->cmdname)
    {
      peer->cmdname=malloc(peer->cmdlength+1);
      udpstream_read(peer->stream, peer->cmdname, peer->cmdlength);
      peer->cmdname[peer->cmdlength]=0;
    }
    else if(peer->datalength<0)
    {
      udpstream_read(peer->stream, &peer->datalength, sizeof(peer->datalength));
    }else{
printf("Received command '%s' from peer "PEERFMT"\n", peer->cmdname, PEERARG(peer->id));
      // Call the relevant callback, if any
      char data[peer->datalength+1]; // TODO: malloc instead? or somehow conditionally
      udpstream_read(peer->stream, data, peer->datalength);
      data[peer->datalength]=0;
      unsigned int i;
      for(i=0; i<commandcount; ++i)
      {
        if(!strcmp(commands[i].name, peer->cmdname))
        {
          commands[i].callback(peer, data, peer->datalength);
        }
      }
      free(peer->cmdname);
      peer->cmdname=0;
      peer->cmdlength=0;
      peer->datalength=-1;
    }
  }
}

void peer_sendcmd(struct peer* peer, const char* cmd, void* data, uint32_t len)
{
  if(!peer) // Broadcast to all connected peers
  {
    unsigned int i;
    for(i=0; i<peercount; ++i)
    {
      if(!peers[i]->handshake){continue;}
      peer_sendcmd(peers[i], cmd, data, len);
    }
    return;
  }
  uint8_t cmdlen=strlen(cmd);
  udpstream_write(peer->stream, &cmdlen, sizeof(cmdlen));
  udpstream_write(peer->stream, cmd, cmdlen);
  udpstream_write(peer->stream, &len, sizeof(len));
  udpstream_write(peer->stream, data, len);
}