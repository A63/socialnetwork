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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include "udpstream.h"

#define TYPE_PAYLOAD 0
#define TYPE_ACK     1
#define TYPE_RESEND  2
#define HEADERSIZE (sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint8_t))
// TODO: Handle stale connections, disconnects, maybe a connect message type?

struct packet
{
  uint16_t seq;
  char* buf;
  unsigned int buflen;
};

struct udpstream
{
  int sock;
  struct sockaddr addr;
  socklen_t addrlen;
  uint16_t inseq;
  uint16_t outseq;
  struct packet* sentpackets;
  unsigned int sentpacketcount;
  struct packet* recvpackets;
  unsigned int recvpacketcount;
  char* buf; // Received but unparsed data
  unsigned int buflen;
// TODO: add void pointer to keep relevant application data? plus a function to free it if the connection is closed or abandoned as stale
};

static struct udpstream** streams=0;
static unsigned int streamcount=0;

struct udpstream* udpstream_new(int sock, struct sockaddr* addr, socklen_t addrlen)
{
  struct udpstream* stream=malloc(sizeof(struct udpstream));
  stream->sock=sock;
  memcpy(&stream->addr, addr, addrlen);
  stream->addrlen=addrlen;
  stream->inseq=0;
  stream->outseq=0;
  stream->sentpackets=0;
  stream->sentpacketcount=0;
  stream->recvpackets=0;
  stream->recvpacketcount=0;
  stream->buf=0;
  stream->buflen=0;
  ++streamcount;
  streams=realloc(streams, sizeof(void*)*streamcount);
  streams[streamcount-1]=stream;
  return stream;
}

static struct udpstream* stream_find(struct sockaddr* addr, socklen_t addrlen)
{
  unsigned int i;
  for(i=0; i<streamcount; ++i)
  {
    if(streams[i]->addrlen==addrlen && !memcmp(&streams[i]->addr, addr, addrlen))
    {
      return streams[i];
    }
  }
  return 0;
}

static ssize_t stream_send(struct udpstream* stream, uint8_t type, uint16_t seq, uint32_t size, const void* buf)
{
// TODO: Include a checksum in the header?
  unsigned char header[HEADERSIZE];
  memcpy(header, &size, sizeof(uint32_t));
  memcpy(header+sizeof(uint32_t), &seq, sizeof(uint16_t));
  memcpy(header+sizeof(uint32_t)+sizeof(uint16_t), &type, sizeof(uint8_t));
  sendto(stream->sock, header, HEADERSIZE, 0, &stream->addr, stream->addrlen);
  return sendto(stream->sock, buf, size, 0, &stream->addr, stream->addrlen);
}

static void udpstream_requestresend(struct udpstream* stream, uint16_t seq)
{
  unsigned int count=(0x10000+seq-stream->inseq)%0x10000;
  uint16_t missed[count];
  unsigned int missedcount=0;
  // When asking to resend, avoid asking for packets we already have in recvpackets
  unsigned int i;
  for(i=0; i<count; ++i)
  {
    uint16_t seq=(i+stream->inseq)%0x10000;
    unsigned int i2;
    for(i2=0; i2<stream->recvpacketcount; ++i2)
    {
      if(stream->recvpackets[i2].seq==seq){break;}
    }
    if(i2==stream->recvpacketcount) // Not found
    {
      missed[missedcount]=seq;
      ++missedcount;
    }
  }
  if(!missedcount){return;}
  stream_send(stream, TYPE_RESEND, 0, missedcount*sizeof(uint16_t), missed);
}

void udpstream_readsocket(int sock)
{
  char buf[1024];
  struct sockaddr addr;
  socklen_t addrlen=sizeof(addr);
  ssize_t len=recvfrom(sock, buf, 1024, 0, &addr, &addrlen);
  struct udpstream* stream=stream_find(&addr, addrlen);
  if(!stream){stream=udpstream_new(sock, &addr, addrlen);}
  stream->buflen+=len;
  stream->buf=realloc(stream->buf, stream->buflen);
  memcpy(stream->buf+(stream->buflen-len), buf, len);
  while(stream->buflen>=HEADERSIZE) // Parse any complete packets received
  {
    // UDP stream header: <payload size, 32 bits><sequence, 16 bits><payload type, 8 bits>
    uint32_t payloadsize;
    uint16_t seq;
    uint8_t type;
    memcpy(&payloadsize, stream->buf, sizeof(uint32_t));
    if(stream->buflen<HEADERSIZE+payloadsize){break;}
    // Complete packet available
    memcpy(&seq, stream->buf+sizeof(uint32_t), sizeof(uint16_t));
    memcpy(&type, stream->buf+sizeof(uint32_t)+sizeof(uint16_t), sizeof(uint8_t));
    if(type==TYPE_ACK) // Handle acknowledgement of sent packet
    {
      // Remove from sent messages, recipient has confirmed receiving it
      if(payloadsize==sizeof(uint16_t))
      {
        memcpy(&seq, stream->buf+sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint8_t), sizeof(uint16_t));
        unsigned int i;
        for(i=0; i<stream->sentpacketcount; ++i)
        {
          if(stream->sentpackets[i].seq==seq)
          {
            free(stream->sentpackets[i].buf);
            --stream->sentpacketcount;
            memmove(&stream->sentpackets[i], &stream->sentpackets[i+1], sizeof(struct packet)*stream->sentpacketcount);
            --i;
          }
        }
      }else{
        fprintf(stderr, "Error: ACK packet has wrong size (%u, should be 2)\n", payloadsize);
      }
      stream->buflen-=(payloadsize+HEADERSIZE);
      memmove(stream->buf, stream->buf+HEADERSIZE+payloadsize, stream->buflen);
      continue;
    }
    if(type==TYPE_RESEND) // TODO: Handle request to resend packets not received by the peer
    {
fprintf(stderr, "TODO: resend packets\n");
      stream->buflen-=(payloadsize+HEADERSIZE);
      memmove(stream->buf, stream->buf+HEADERSIZE+payloadsize, stream->buflen);
      continue;
    }
    // Send ack, regardless of whether it's in the right order
    stream_send(stream, TYPE_ACK, 0, sizeof(uint16_t), &seq);
    // Add to list of parsed packets
    ++stream->recvpacketcount;
    stream->recvpackets=realloc(stream->recvpackets, sizeof(struct packet)*stream->recvpacketcount);
    stream->recvpackets[stream->recvpacketcount-1].seq=seq;
    stream->recvpackets[stream->recvpacketcount-1].buf=malloc(payloadsize);
    stream->recvpackets[stream->recvpacketcount-1].buflen=payloadsize;
    memcpy(stream->recvpackets[stream->recvpacketcount-1].buf, stream->buf+HEADERSIZE, payloadsize);
    stream->buflen-=(payloadsize+HEADERSIZE);
    memmove(stream->buf, stream->buf+HEADERSIZE+payloadsize, stream->buflen);
    udpstream_requestresend(stream, seq); // Ask to resend if we're missing any packets
  }
}

struct udpstream* udpstream_poll(void)
{
  unsigned int i;
  for(i=0; i<streamcount; ++i)
  {
    // Check for the next packet in the order
    unsigned int i2;
    for(i2=0; i2<streams[i]->recvpacketcount; ++i2)
    {
      if(streams[i]->recvpackets[i2].seq==streams[i]->inseq){return streams[i];}
    }
  }
  return 0;
}

ssize_t udpstream_read(struct udpstream* stream, void* buf, size_t size)
{
  // Check if it's any previously out of order packet's turn now
  unsigned int i;
  for(i=0; i<stream->recvpacketcount; ++i)
  {
    if(stream->recvpackets[i].seq==stream->inseq)
    {
      ssize_t len=stream->recvpackets[i].buflen;
      if(len>size) // Handle buffers smaller than the payload
      {
        memcpy(buf, stream->recvpackets[i].buf, size);
        stream->recvpackets[i].buflen-=size;
        memmove(stream->recvpackets[i].buf, stream->recvpackets[i].buf+size, stream->recvpackets[i].buflen);
        return size;
      }else{
        memcpy(buf, stream->recvpackets[i].buf, len);
        free(stream->recvpackets[i].buf);
        --stream->recvpacketcount;
        memmove(&stream->recvpackets[i], &stream->recvpackets[i+1], sizeof(struct packet)*stream->recvpacketcount);
        ++stream->inseq;
        return len;
      }
    }
  }
// TODO: udpstream_readsocket(stream->sock) and retry if no packet is found?
  errno=EWOULDBLOCK;
  return -1;
}

ssize_t udpstream_write(struct udpstream* stream, const void* buf, size_t size)
{
// TODO: abort and return negative if sentpacketcount is too high? EWOULDBLOCK?
  ++stream->sentpacketcount;
  stream->sentpackets=realloc(stream->sentpackets, sizeof(struct packet)*stream->sentpacketcount);
  stream->sentpackets[stream->sentpacketcount-1].seq=stream->outseq;
  stream->sentpackets[stream->sentpacketcount-1].buf=malloc(size);
  stream->sentpackets[stream->sentpacketcount-1].buflen=size;
  memcpy(stream->sentpackets[stream->sentpacketcount-1].buf, buf, size);
  stream_send(stream, TYPE_PAYLOAD, stream->outseq, size, buf);
  ++stream->outseq;
  return size;
}

void udpstream_getaddr(struct udpstream* stream, struct sockaddr* addr, socklen_t* addrlen)
{
  if(*addrlen>stream->addrlen){*addrlen=stream->addrlen;}
  memcpy(addr, &stream->addr, *addrlen);
}

int udpstream_getsocket(struct udpstream* stream){return stream->sock;}
