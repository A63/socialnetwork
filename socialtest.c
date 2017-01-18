/*
    Socialnetwork, a truly peer-to-peer social network (in search of a better name)
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
  social_init("priv.pem");
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
      if(!strcmp(buf, "lsfriends")) // TODO: These aren't necessarily friends
      {
        for(i=0; i<social_usercount; ++i)
        {
          printf("%p %s\n", social_users[i], social_users[i]->peer?"(connected)":"");
          unsigned int i2;
          for(i2=0; i2<social_users[i]->updatecount; ++i2)
          {
            if(social_users[i]->updates[i2].type==UPDATE_FIELD)
            {
              printf("  %s = %s", social_users[i]->updates[i2].field.name, social_users[i]->updates[i2].field.value);
            }
          }
        }
      }
      else if(!strcmp(buf, "lsupdates")) // List our own updates for starters
      {
        unsigned int i;
        for(i=0; i<social_self->updatecount; ++i)
        {
          struct update* update=&social_self->updates[i];
          time_t timestamp=update->timestamp;
          switch(update->type)
          {
          case UPDATE_FIELD:
            printf("\nField %s%s = %s\n", ctime(&timestamp), update->field.name, update->field.value);
            break;
          case UPDATE_POST:
            printf("\nPost %s%s\n", ctime(&timestamp), update->post.message);
            break;
          }
        }
      }
      else if(!strncmp(buf, "addfriend ", 10))
      {
        if(strlen(&buf[10])<40){continue;}
        char byte[3]={0,0,0};
        unsigned char binid[20];
        unsigned int i;
        for(i=0; i<20; ++i)
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
          printf("%u: %s (%u friends)\n", i, circle->name?circle->name:"Unnamed circle", circle->count);
        }
      }
      else if(!strcmp(buf, "privacy"))
      {
        if(!privacy.flags)
        {
          printf("%u circles of friends can see updates with this setting:\n", privacy.circlecount);
          for(i=0; i<privacy.circlecount; ++i)
          {
            if(privacy.circles[i]>=social_self->circlecount){printf("Undefined circle\n"); continue;}
            struct friendslist* circle=&social_self->circles[privacy.circles[i]];
            printf("%s (%u friends)\n", circle->name?circle->name:"Unnamed circle", circle->count);
          }
        }
        else if(privacy.flags&PRIVACY_ANYONE)
        {
          printf("Anyone can see updates with this setting\n");
        }
        else if(privacy.flags&PRIVACY_FRIENDS)
        {
          printf("Friends in any circle can see updates with this setting\n");
        }
        else{printf("Unknown privacy flag set!\n");}
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
