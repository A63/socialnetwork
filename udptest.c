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
#include <unistd.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "udpstream.h"

// Temporary test program for udpstream
int main(int argc, char** argv)
{
  int sock=socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct udpstream* stream=0;
  if(argc>2)
  {
    struct addrinfo* ai;
    getaddrinfo(argv[1], argv[2], 0, &ai);
    stream=udpstream_new(sock, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
  }
  else if(argc>1)
  {
    struct addrinfo* ai;
    getaddrinfo("127.0.0.1", argv[1], 0, &ai);
    udpstream_listen(sock, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
  }
  struct pollfd pfd[]={{.fd=0, .events=POLLIN, .revents=0}, {.fd=sock, .events=POLLIN, .revents=0}};
  char buf[1024];
  while(1)
  {
    poll(pfd, 2, -1);
    if(pfd[0].revents) // stdin
    {
      pfd[0].revents=0;
      ssize_t len=read(0, buf, 1024);
      if(!stream){printf("No connection yet!\n"); continue;}
      udpstream_write(stream, buf, len);
    }
    if(pfd[1].revents) // UDP
    {
      pfd[1].revents=0;
      udpstream_readsocket(sock);
      struct udpstream* rstream;
      while((rstream=udpstream_poll()))
      {
        stream=rstream;
        ssize_t len=udpstream_read(rstream, buf, 1024);
        if(len<1){continue;}
        write(1, buf, len);
      }
    }
  }
  return 0;
}
