/*
    Socialnetwork, a truly peer-to-peer social network (in search of a better name)
    Copyright (C) 2017-2018  alicia@ion.nu

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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include "peer.h"
#include "social.h"
#include "update.h"

// Inject after "Will be shown/visible to ..."
void printprivacy(struct privacy* privacy)
{
  if(!privacy->flags)
  {
    if(!privacy->circlecount){printf("no one"); return;}
    printf("the circles ");
    unsigned int usertotal=0;
    unsigned int i;
    for(i=0; i<privacy->circlecount; ++i)
    {
      if(i){printf(", ");}
      struct friendslist* circle=social_user_getcircle(social_self, privacy->circles[i]);
      printf("'%s'", circle->name?circle->name:"Unnamed circle");
      usertotal+=circle->count;
    }
    printf(", %u users in total", usertotal);
  }
  else if(privacy->flags&PRIVACY_ANYONE)
  {
    printf("anyone");
  }
  else if(privacy->flags&PRIVACY_FRIENDS)
  {
    printf("all friends");
  }
  else{printf("unknown privacy flag set!");}
}

struct user* finduser(const char* search) // Find user by just the beginnig (or whole) of the key ID
{
  unsigned int i;
  for(i=0; i<social_usercount; ++i)
  {
    char id[ID_SIZE*2+1];
    sprintf(id, PEERFMT, PEERARG(social_users[i]->id));
    if(!strncmp(search, id, strlen(search))){return social_users[i];}
  }
  return 0;
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
  social_init("priv.pem", ".");
  peer_bootstrap(sock, "127.0.0.1:4000");

  struct pollfd pfd[]={{.fd=0, .events=POLLIN, .revents=0}, {.fd=sock, .events=POLLIN, .revents=0}};
  char buf[1024];
  struct privacy privacy={.flags=PRIVACY_FRIENDS, .circles=0, .circlecount=0};
  unsigned int i;
  while(1)
  {
    printf("> ");
    fflush(stdout);
    poll(pfd, 2, -1);
    if(pfd[0].revents) // stdin
    {
      pfd[0].revents=0;
      ssize_t len=read(0, buf, 1023);
      while(len>0 && strchr("\r\n", buf[len-1])){--len;}
      buf[len]=0;
      if(!strcmp(buf, "lsfriends")) // TODO: These aren't necessarily friends, just users we are somehow connected to
      {
        for(i=0; i<social_usercount; ++i)
        {
          printf("%p (%s) %s\n", social_users[i], social_user_getfield(social_users[i], "name"), social_users[i]->peer?"(connected)":"");
          unsigned int i2;
          for(i2=0; i2<social_users[i]->updatecount; ++i2)
          {
            if(social_users[i]->updates[i2].type==UPDATE_FIELD && strcmp(social_users[i]->updates[i2].field.name, "name"))
            {
              printf("  %s = %s", social_users[i]->updates[i2].field.name, social_users[i]->updates[i2].field.value);
            }
          }
        }
      }
      else if(!strcmp(buf, "lsupdates") || // List our own updates for starters
              !strncmp(buf, "lsupdates ", 10)) // List someone else's updates
      {
        struct user* user=(buf[9]?finduser(&buf[10]):social_self);
        if(!user){printf("User not found\n"); continue;}
        unsigned int i;
        for(i=0; i<user->updatecount; ++i)
        {
          struct update* update=&user->updates[i];
          time_t timestamp=update->timestamp;
          printf("\nVisible to ");
          printprivacy(&update->privacy);
          switch(update->type)
          {
          case UPDATE_FIELD:
            printf("\nField %s%s = %s", ctime(&timestamp), update->field.name, update->field.value);
            break;
          case UPDATE_POST:
            printf("\nPost %s%s", ctime(&timestamp), update->post.message);
            break;
          case UPDATE_FRIENDS:
            printf("\nFriend %s%s\n", ctime(&timestamp), update->friends.add?"Add":"Remove");
            break;
          case UPDATE_CIRCLE:
            printf("\nCircle %s%u: %s\n", ctime(&timestamp), update->circle.circle, update->circle.name);
            break;
          }
        }
      }
      else if(!strcmp(buf, "loadmore") || // Load more of our own updates
              !strncmp(buf, "loadmore ", 9)) // Load more of someone else's updates
      {
        struct user* user=(buf[8]?finduser(&buf[9]):social_self);
        if(!user){printf("User not found\n"); continue;}
        social_user_loadmore(user);
      }
      else if(!strncmp(buf, "addfriend ", 10))
      {
        if(strlen(&buf[10])<ID_SIZE*2){continue;}
        char byte[3]={0,0,0};
        unsigned char binid[ID_SIZE];
        unsigned int i;
        for(i=0; i<ID_SIZE; ++i)
        {
          memcpy(byte, &buf[10+i*2], 2);
          binid[i]=strtoul(byte, 0, 16);
        }
        // TODO: Prompt for circle
        social_addfriend(binid, 0);
      }
      else if(!strcmp(buf, "update post"))
      {
        printf("Enter post: (finish with ctrl+D)\n");
        buf[0]=0;
        unsigned int len;
        while((len=strlen(buf))<1023)
        {
          ssize_t r=read(0, &buf[len], 1023-len);
          if(r<1){break;}
          buf[len+r]=0;
        }
        social_createpost(buf, &privacy);
      }
      else if(!strncmp(buf, "update field ", 13))
      {
        char name[strlen(&buf[13]+1)];
        strcpy(name, &buf[13]);
        printf("Enter value: "); fflush(stdout);
        unsigned int len=read(0, buf, 1023);
        while(len && (buf[len-1]=='\n'||buf[len-1]=='\r')){--len;}
        buf[len]=0;
        social_updatefield(name, buf, &privacy);
      }
      else if(!strncmp(buf, "exportpeers ", 12))
      {
        peer_exportpeers(&buf[12]);
      }
      else if(!strcmp(buf, "lscircles"))
      {
        for(i=0; i<social_self->circlecount; ++i)
        {
          struct friendslist* circle=&social_self->circles[i];
          printf("%u: %s (%u friends), additions/removals are visible to ", i, circle->name?circle->name:"Unnamed circle", circle->count);
          printprivacy(&circle->privacy);
          printf("\n");
          unsigned int i2;
          for(i2=0; i2<circle->count; ++i2)
          {
            printf("  "PEERFMT"\n", PEERARG(circle->friends[i2]->id));
          }
        }
      }
      else if(!strcmp(buf, "privacy"))
      {
        printf("With this privacy setting updates will be visible to ");
        printprivacy(&privacy);
        printf("\n");
      }
      else if(!strncmp(buf, "privacy flag ", 13))
      {
        if(!strcmp(&buf[13], "anyone"))
        {
          privacy.flags^=PRIVACY_ANYONE;
        }
        else if(!strcmp(&buf[13], "friends"))
        {
          privacy.flags^=PRIVACY_FRIENDS;
        }
        else{printf("Unknown flag '%s'\n", &buf[13]);}
      }
      else if(!strncmp(buf, "privacy circle ", 15))
      {
        uint32_t circle=strtoul(&buf[15], 0, 0);
        char found=0;
        for(i=0; i<privacy.circlecount; ++i)
        {
          if(privacy.circles[i]==circle)
          {
            --privacy.circlecount;
            memmove(&privacy.circles[i], &privacy.circles[i+1], sizeof(uint32_t)*(privacy.circlecount-i));
            found=1;
            printf("Removed\n");
            break;
          }
        }
        if(!found)
        {
          ++privacy.circlecount;
          privacy.circles=realloc(privacy.circles, sizeof(uint32_t)*privacy.circlecount);
          privacy.circles[privacy.circlecount-1]=circle;
          printf("Added\n");
        }
      }
      else if(!strncmp(buf, "setcircle ", 10))
      {
        uint32_t circle=strtoul(&buf[10], 0, 0);
        printf("Enter name: "); fflush(stdout);
        unsigned int len=read(0, buf, 1023);
        buf[len]=0;
        char* end;
        while((end=strchr(buf, '\r'))||(end=strchr(buf, '\n'))){end[0]=0;}
        // Note: we're also setting the privacy setting that will be referenced for future friend additions/removals from this circle, which might not be readily apparent. The generated update that sets the name (and privacy) of the circle is always private.
        social_setcircle(circle, buf, &privacy);
      }
      else if(!strncmp(buf, "bootstrap ", 10))
      {
        peer_bootstrap(sock, &buf[10]);
      }
      else if(!strcmp(buf, "whoami"))
      {
        printf("ID: "PEERFMT"\n", PEERARG(peer_id));
        struct sockaddr_storage sockaddr;
        socklen_t addrlen=sizeof(sockaddr);
        getsockname(sock, (struct sockaddr*)&sockaddr, &addrlen);
        char addr[INET6_ADDRSTRLEN];
        char port[64];
        if(getnameinfo((struct sockaddr*)&sockaddr, addrlen, addr, INET6_ADDRSTRLEN, port, 64, NI_NUMERICHOST|NI_NUMERICSERV|NI_DGRAM)){continue;}
        const char* fmt=((sockaddr.ss_family==AF_INET6)?"Address: [%s]:%s\n":"Address: %s:%s\n");
        printf(fmt, addr, port);
      }
      else if(!strcmp(buf, "help"))
      {
        printf("Available commands:\n"
               "lsfriends (connected users)\n"
               "lsupdates [<ID>]\n"
               "loadmore [<ID>]\n"
               "addfriend <ID>\n"
               "update post\n"
               "update field <name>\n"
               "exportpeers <filename>\n"
               "lscircles\n"
               "privacy\n"
               "privacy flag \n"
               "privacy circle \n"
               "setcircle <circle ID>\n"
               "bootstrap <host>:<port>\n"
               "whoami\n");
      }
      else{printf("Unknown command '%s'\n", buf);}
    }
    if(pfd[1].revents) // UDP
    {
      pfd[1].revents=0;
      // Erase prompt
      printf("\r  \r");
      fflush(stdout);
      peer_handlesocket(sock);
// TODO: Notify of updates as they happen
    }
  }
  return 0;
}
