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
#include <sys/poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include "peer.h"

void gotmsg(struct peer* peer, void* data, unsigned int size)
{
  printf("Message from "PEERFMT":\n", PEERARG(peer->id));
  fwrite(data, size, 1, stdout);
}

int main(int argc, char** argv)
{
  int sock=socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(argc>1)
  {
    struct addrinfo* ai;
    getaddrinfo("0.0.0.0", argv[1], 0, &ai);
    bind(sock, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
  }
  peer_init("priv.pem");
  peer_registercmd("msg", gotmsg);
  peer_bootstrap(sock, "127.0.0.1:4000");
  struct pollfd pfd[]={{.fd=0, .events=POLLIN, .revents=0}, {.fd=sock, .events=POLLIN, .revents=0}};
  char buf[1024];
  while(1)
  {
    poll(pfd, 2, -1);
    if(pfd[0].revents) // stdin
    {
      pfd[0].revents=0;
      ssize_t len=read(0, buf, 1024);
      peer_sendcmd(0, "msg", buf, len);
    }
    if(pfd[1].revents) // UDP
    {
      pfd[1].revents=0;
      peer_handlesocket(sock);
    }
  }
  return 0;
}
