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

unsigned char peer_id[20];
gnutls_privkey_t peer_privkey=0;
static struct peer** peers=0;
static unsigned int peercount=0;
static struct command* commands=0;
static unsigned int commandcount=0;
static gnutls_x509_privkey_t privkey=0;

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

struct findpeer_request
{
  unsigned char id[20];
  struct sockaddr addr;
  uint16_t addrlen;
  time_t timestamp;
};
static void findpeer(struct peer* peer, void* data, unsigned int len)
{
  // <target ID, 20><ttl, 2>[<addrlen, 2><source addr>]
  // Sender can't know their own address, so the first recipient will need to add the address of whoever they got it from
  uint16_t ttl;
  if(len<20+sizeof(ttl)){return;}
  unsigned char id[20];
  memcpy(id, data, 20);
printf("Got findpeer request for '"PEERFMT"'\n", PEERARG(id));
  memcpy(&ttl, data+20, sizeof(ttl));
  if(!ttl){return;}
  --ttl;
  struct sockaddr addr;
  uint16_t addrlen;
  if(len>20+sizeof(ttl)+sizeof(addrlen))
  { // Has address already
    memcpy(&addrlen, data+20+sizeof(ttl), sizeof(addrlen));
    if(len<20+sizeof(ttl)+sizeof(addrlen)+addrlen){return;}
    memcpy(&addr, data+20+sizeof(ttl)+sizeof(addrlen), addrlen);
  }
  else if(len==20+sizeof(ttl))
  { // Get address from sender
    addrlen=peer->addrlen;
    memcpy(&addr, &peer->addr, addrlen);
  }else{return;}
  // Avoid floody loops by keeping track of what we've already handled recently
  static struct findpeer_request* reqs=0;
  static unsigned int reqcount=0;
  time_t now=time(0);
  struct findpeer_request* newentry=0;
  unsigned int i;
  for(i=0; i<reqcount; ++i)
  {
    if(reqs[i].timestamp+30<now) // Old entry (30 seconds)
    {
      newentry=&reqs[i]; // Mark as replacable
    }
    else if(!memcmp(reqs[i].id, id, 20) && reqs[i].addrlen==addrlen && !memcmp(&reqs[i].addr, &addr, addrlen))
    { // Already handled, update the timestamp too in case it keeps coming for a while
      reqs[i].timestamp=now;
      return;
    }
  }
  if(!newentry) // Make room for new entry if there were no old ones to replace
  {
    ++reqcount;
    reqs=realloc(reqs, sizeof(struct findpeer_request)*reqcount);
    newentry=&reqs[reqcount-1];
  }
  memcpy(newentry->id, id, 20);
  memcpy(&newentry->addr, &addr, addrlen);
  newentry->addrlen=addrlen;
  newentry->timestamp=now;
  // Check if it's us
  if(!memcmp(id, peer_id, 20))
  {
    peer_new_unique(udpstream_getsocket(peer->stream), &addr, addrlen);
    return;
  }
  // Propagate (unless it was us, !ttl, or already handled)
  if(ttl)
  {
    len=20+sizeof(ttl)+sizeof(addrlen)+addrlen;
    unsigned char data[len];
    memcpy(data, id, 20);
    memcpy(data+20, &ttl, sizeof(ttl));
    memcpy(data+20+sizeof(ttl), &addrlen, sizeof(addrlen));
    memcpy(data+20+sizeof(ttl)+sizeof(addrlen), &addr, addrlen);
    peer_sendcmd(0, "findpeer", data, len);
  }
}

void peer_init(const char* keypath)
{
  gnutls_global_init();
  // Load our private key, or generate one if we don't have one yet
  if(!privkey)
  {
    gnutls_x509_privkey_init(&privkey);
    struct stat st;
    char loadfailed=1;
    if(!stat(keypath, &st))
    {
      gnutls_datum_t keydata;
      keydata.size=st.st_size;
      keydata.data=malloc(st.st_size);
      int f=open(keypath, O_RDONLY);
      read(f, keydata.data, st.st_size);
      close(f);
      // TODO: Allow encrypted keys, using _import2()
      if(!gnutls_x509_privkey_import2(privkey, &keydata, GNUTLS_X509_FMT_PEM, 0, GNUTLS_PKCS_PLAIN)){loadfailed=0;}
      free(keydata.data);
    }
    if(loadfailed)
    {
// printf("Generating a new key...\n");
      // TODO: Why do handshakes fail with >3072 bit keys?
      gnutls_x509_privkey_generate(privkey, GNUTLS_PK_RSA, 3072, 0);
// printf("Done\n");
      // TODO: Allow exporting encrypted key, using _export2_pkcs8() I think
      gnutls_datum_t keydata;
      gnutls_x509_privkey_export2(privkey, GNUTLS_X509_FMT_PEM, &keydata);
      int f=open(keypath, O_WRONLY|O_TRUNC|O_CREAT, 0600);
      write(f, keydata.data, keydata.size);
      close(f);
      gnutls_free(keydata.data);
    }
    size_t size=20;
    gnutls_x509_privkey_get_key_id(privkey, 0, peer_id, &size);
    gnutls_privkey_init(&peer_privkey);
    gnutls_privkey_import_x509(peer_privkey, privkey, 0);
  }
  // Register core commands
  peer_registercmd("getpeers", sendpeers);
  peer_registercmd("peers", getpeers);
  peer_registercmd("findpeer", findpeer);
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
  gnutls_x509_crt_init(&peer->cert);
  gnutls_x509_crt_import(peer->cert, certs, GNUTLS_X509_FMT_DER);
  // Get the certificate's public key ID
  size_t size=20;
  gnutls_x509_crt_get_key_id(peer->cert, 0, peer->id, &size);
  // Make sure we're not connecting to ourselves. TODO: Make sure we're not connecting to someone else we're already connected to as well? (different addresses, same ID) may cause issues with reconnects and/or multiple sessions
  return !memcmp(peer->id, peer_id, 20);
}

static void generatecert(gnutls_certificate_credentials_t cred)
{
  // Generate the certificate
  gnutls_x509_crt_t cert;
  gnutls_x509_crt_init(&cert);
  gnutls_x509_crt_set_key(cert, privkey);
  gnutls_x509_crt_set_serial(cert, "", 1);
  gnutls_x509_crt_set_activation_time(cert, time(0)-3600); // Allow up to an hour of time drift
  gnutls_x509_crt_set_expiration_time(cert, time(0)+3600);
  gnutls_x509_crt_sign(cert, cert, privkey);
  gnutls_certificate_set_x509_key(cred, &cert, 1, privkey);
  gnutls_x509_crt_deinit(cert);
}

static struct peer* findpending(void)
{
  struct udpstream* stream=udpstream_poll();
  if(stream)
  {
    return peer_get(stream);
  }
  unsigned int i;
  for(i=0; i<peercount; ++i)
  {
    if(gnutls_record_check_pending(peers[i]->tls)){return peers[i];}
  }
  return 0;
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
  memset(peer->id, 0, 20);
  peer->cert=0;
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

#define readordie(x,y,z) {ssize_t r=gnutls_record_recv(x->tls,y,z); if(z && r<1){peer_disconnect(x, 0); continue;}}
void peer_handlesocket(int sock) // Incoming data
{
  udpstream_readsocket(sock); // If it locks up here we're probably missing a bootstrap node
  struct peer* peer;
  while((peer=findpending()))
  {
    if(!peer->handshake)
    {
// TODO: GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET seems to indicate we're connecting to ourselves
      int res=gnutls_handshake(peer->tls);
      if(gnutls_error_is_fatal(res)){peer_disconnect(peer, 0); continue;}
      peer->handshake=!res;
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
      readordie(peer, &peer->cmdlength, sizeof(peer->cmdlength));
      continue;
    }
    else if(!peer->cmdname)
    {
      peer->cmdname=malloc(peer->cmdlength+1);
      readordie(peer, peer->cmdname, peer->cmdlength);
      peer->cmdname[peer->cmdlength]=0;
      continue;
    }
    else if(peer->datalength<0)
    {
      readordie(peer, &peer->datalength, sizeof(peer->datalength));
      if(peer->datalength){continue;} // If it's a 0-length command just keep going
    }
printf("Received command '%s' from peer "PEERFMT"\n", peer->cmdname, PEERARG(peer->id));
    // Call the relevant callback, if any
    char data[peer->datalength+1]; // TODO: malloc instead? or somehow conditionally
    readordie(peer, data, peer->datalength);
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
  gnutls_record_cork(peer->tls);
  gnutls_record_send(peer->tls, &cmdlen, sizeof(cmdlen));
  gnutls_record_send(peer->tls, cmd, cmdlen);
  gnutls_record_send(peer->tls, &len, sizeof(len));
  gnutls_record_send(peer->tls, data, len);
  gnutls_record_uncork(peer->tls, GNUTLS_RECORD_WAIT);
}

void peer_disconnect(struct peer* peer, char cleanly)
{
  if(cleanly){gnutls_bye(peer->tls, GNUTLS_SHUT_WR);}
  gnutls_deinit(peer->tls);
  if(peer->cert){gnutls_x509_crt_deinit(peer->cert);}
  udpstream_close(peer->stream);
  free(peer->cmdname);
  free(peer);
  unsigned int i;
  for(i=0; i<peercount; ++i)
  {
    if(peers[i]==peer)
    {
      --peercount;
      memmove(&peers[i], &peers[i+1], sizeof(void*)*(peercount-i));
    }
  }
}

void peer_findpeer(const unsigned char id[20])
{
  uint16_t ttl=8; // 8 is probably a good level to start at, might need to be higher in the future
  unsigned int len=20+sizeof(ttl);
  unsigned char data[len];
  memcpy(data, id, 20);
  memcpy(data+20, &ttl, sizeof(ttl));
  peer_sendcmd(0, "findpeer", data, len);
}

struct peer* peer_findbyid(const unsigned char id[20])
{
  unsigned int i;
  for(i=0; i<peercount; ++i)
  {
    if(!peers[i]->handshake){continue;}
    if(!memcmp(peers[i]->id, id, 20)){return peers[i];}
  }
  return 0;
}

void peer_exportpeers(const char* path)
{
  int f=open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
  unsigned int i;
  for(i=0; i<peercount; ++i)
  {
    if(!peers[i]->handshake){continue;} // Skip bad peers
    switch(peers[i]->addr.sa_family)
    {
    case AF_INET:
      {
      struct sockaddr_in* addr=(struct sockaddr_in*)&peers[i]->addr;
      unsigned char* ip=(unsigned char*)&addr->sin_addr.s_addr;
      dprintf(f, "%hhu.%hhu.%hhu.%hhu:%hu\n", ip[0], ip[1], ip[2], ip[3], ntohs(addr->sin_port));
      }
    }
  }
  close(f);
}
