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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <gnutls/abstract.h>
#include "peer.h"
#include "buffer.h"
#include "update.h"
#include "social.h"
struct user** social_users=0;
unsigned int social_usercount=0;
struct user* social_self;
// Abstract away all the messagepassing and present information more or less statically
// TODO: Think about privacy for all data updates
// TODO: We must also sign all data updates to prevent forgeries

static void updateinfo(struct peer* peer, void* data, unsigned int len)
{
  // <id, 20><sigsize, 4><signature><seq, 8><type, 1><timestamp, 8><type-specific data>
  if(len<20){return;}
  struct user* user=social_finduser(data);
  if(!user || !user->pubkey){return;}
  struct update* update=social_update_parse(user, data+20, len-20);
  if(update){social_update_save(user, update);}
}

static void user_save(struct user* user)
{
  if(!user->pubkey){return;}
  // TODO: Absolute path, something like $HOME/.socialnetwork
  mkdir("users", 0700);
  char path[strlen("users/0")+40];
  sprintf(path, "users/"PEERFMT, PEERARG(user->id));
  int f=open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
  gnutls_datum_t key;
  gnutls_pubkey_export2(user->pubkey, GNUTLS_X509_FMT_PEM, &key);
  uint32_t size=key.size;
  write(f, &size, sizeof(size));
  write(f, key.data, size);
  gnutls_free(key.data);
  close(f);
}

static void greetpeer(struct peer* peer, void* data, unsigned int len)
{
  // Figure out if they're one of our friends (TODO: or friends of friends)
  unsigned int i, i2;
  for(i=0; i<social_self->circlecount; ++i)
  for(i2=0; i2<social_self->circles[i].count; ++i2)
  {
    struct user* user=social_self->circles[i].friends[i2];
    if(!memcmp(user->id, peer->id, 20))
    {
      user->peer=peer;
// TODO: Better way of getting someone's public key (I guess this is fine, but we need to be able to get it when they're not online too)
      if(!user->pubkey)
      {
        gnutls_pubkey_init(&user->pubkey);
        gnutls_pubkey_import_x509(user->pubkey, peer->cert, 0);
        user_save(user);
      }
      // Ask for updates
      len=20+sizeof(uint64_t);
      unsigned char arg[len];
      memcpy(arg, user->id, 20);
      memcpy(arg+20, &user->seq, sizeof(user->seq));
      peer_sendcmd(user->peer, "getupdates", arg, len);
    }
  }
}

static void sendupdate(struct peer* peer, const unsigned char id[20], struct update* update)
{
  struct buffer buf;
  buffer_init(buf);
  buffer_write(buf, id, 20);
  buffer_write(buf, &update->signaturesize, sizeof(update->signaturesize));
  buffer_write(buf, update->signature, update->signaturesize);
  social_update_write(&buf, update);
  peer_sendcmd(peer, "updateinfo", buf.buf, buf.size);
  buffer_deinit(buf);
}

static void sendupdates(struct peer* peer, void* data, unsigned int len)
{
  // <ID, 20><seq, 8>
  uint64_t seq;
  if(len<20+sizeof(seq)){return;}
  memcpy(&seq, data+20, sizeof(seq));
  struct user* user;
  // "getupdates" can also be requests for data of friends of friends
  user=social_finduser(data);
  if(!user){return;}
  unsigned int i;
  for(i=0; i<user->updatecount; ++i)
  {
    // TODO: Check privacy rules
    // Also make sure not to send old news (based on seq)
    if(user->updates[i].seq<=seq){continue;}
    sendupdate(peer, user->id, &user->updates[i]);
  }
}

static void user_load(struct user* user)
{
  // TODO: Absolute path, something like $HOME/.socialnetwork
  // Load user data (only pubkey atm), but spare pubkey if it's already set
  if(!user->pubkey)
  {
    char path[strlen("users/0")+40];
    sprintf(path, "users/"PEERFMT, PEERARG(user->id));
    int f=open(path, O_RDONLY);
    if(f>=0)
    {
      uint32_t size;
      read(f, &size, sizeof(size));
      unsigned char keydata[size];
      read(f, keydata, size);
      close(f);
      gnutls_datum_t key={.data=keydata, .size=size};
      gnutls_pubkey_init(&user->pubkey);
      gnutls_pubkey_import(user->pubkey, &key, GNUTLS_X509_FMT_PEM);
    }
  }
  // Load updates
  char path[strlen("updates/0")+40];
  sprintf(path, "updates/"PEERFMT, PEERARG(user->id));
  int f=open(path, O_RDONLY);
  if(f<0){return;}
  uint64_t size;
  while(read(f, &size, sizeof(size))==sizeof(size))
  {
    uint8_t buf[size];
    read(f, buf, size);
    social_update_parse(user, buf, size);
  }
}

static struct user* user_new(const unsigned char id[20])
{
  struct user* user=malloc(sizeof(struct user));
  memcpy(user->id, id, 20);
  user->pubkey=0;
  user->peer=peer_findbyid(id);
  user->name=0;
  user->circles=0;
  user->circlecount=0;
  user->seq=0;
  user->updates=0;
  user->updatecount=0;
  ++social_usercount;
  social_users=realloc(social_users, sizeof(void*)*social_usercount);
  social_users[social_usercount-1]=user;
  user_load(user);
  return user;
}

void social_init(const char* keypath)
{
  // Load key, friends, circles, etc. our own profile
  peer_init(keypath);
  social_self=user_new(peer_id);
  if(!social_self->pubkey)
  {
    // Get our own pubkey
    gnutls_pubkey_init(&social_self->pubkey);
    gnutls_pubkey_import_privkey(social_self->pubkey, peer_privkey, 0, 0);
    // Save our public key and reload our updates
    user_save(social_self);
    user_load(social_self);
  }
  peer_registercmd("updateinfo", updateinfo);
  peer_registercmd("getpeers", greetpeer);
  peer_registercmd("getupdates", sendupdates);
// TODO: Set up socket and bootstrap here too? or accept an already set up socket?
}

void social_findfriends(void) // Call a second or so after init (once we have some bootstrap peers)
{
  // Loop through friends-list and try to find everyone's peers
  unsigned int i;
  for(i=0; i<social_usercount; ++i)
  {
    if(social_users[i]->peer){continue;}
    peer_findpeer(social_users[i]->id);
  }
}

void social_user_addtocircle(struct user* user, uint32_t circle, unsigned char id[20])
{
  if(circle>=user->circlecount)
  {
    user->circles=realloc(user->circles, sizeof(struct friendslist)*(circle+1));
    for(; user->circlecount<=circle; ++user->circlecount)
    {
      user->circles[user->circlecount].name=0;
      user->circles[user->circlecount].friends=0;
      user->circles[user->circlecount].count=0;
    }
  }
  struct user* friend=social_finduser(id);
  if(!friend){friend=user_new(id);}
  struct friendslist* c=&user->circles[circle];
  ++c->count;
  c->friends=realloc(c->friends, sizeof(void*)*c->count);
  c->friends[c->count-1]=friend;
}

void social_addfriend(unsigned char id[20], uint32_t circle)
{
  struct user* friend=social_finduser(id);
  if(!friend){friend=user_new(id);}
  if(!friend->peer)
  {
    peer_findpeer(id);
  }else{
    if(!friend->pubkey)
    {
      gnutls_pubkey_init(&friend->pubkey);
      gnutls_pubkey_import_x509(friend->pubkey, friend->peer->cert, 0);
      user_save(friend);
    }
    unsigned int len=20+sizeof(uint64_t);
    unsigned char arg[len];
    memcpy(arg, friend->id, 20);
    memcpy(arg+20, &friend->seq, sizeof(friend->seq));
    peer_sendcmd(friend->peer, "getupdates", arg, len);
  }
  social_user_addtocircle(social_self, circle, id);
// TODO: Send a friend request/notification at some point?
  struct update* update=social_update_new(social_self);
  ++social_self->seq;
  update->seq=social_self->seq;
  update->type=UPDATE_FRIENDS;
  update->timestamp=time(0);
  update->friends.circle=circle;
  update->friends.add=1;
  memcpy(update->friends.id, id, 20);
  social_update_sign(update);
  social_update_save(social_self, update);
  social_shareupdate(update);
}

void social_createpost(const char* msg)
{
  // TODO: Posts attached to users and/or users' updates
  struct update* post=social_update_new(social_self);
  ++social_self->seq;
  post->seq=social_self->seq;
  post->type=UPDATE_POST;
  post->timestamp=time(0);
  post->post.message=strdup(msg);
  social_update_sign(post);
  social_update_save(social_self, post);
  social_shareupdate(post);
}

void social_updatefield(const char* name, const char* value)
{
  struct update* post=social_update_new(social_self);
  ++social_self->seq;
  post->seq=social_self->seq;
  post->type=UPDATE_FIELD;
  post->timestamp=time(0);
  post->field.name=strdup(name);
  post->field.value=strdup(value);
  social_update_sign(post);
  social_update_save(social_self, post);
  social_shareupdate(post);
}

struct user* social_finduser(unsigned char id[20])
{
  unsigned int i;
  for(i=0; i<social_usercount; ++i)
  {
    if(!memcmp(social_users[i]->id, id, 20)){return social_users[i];}
  }
  return 0;
}

void social_shareupdate(struct update* update)
{
  // Send update to anyone who is currently online and which the update's privacy settings allow
  unsigned int i;
  for(i=0; i<social_self->circlecount; ++i)
  {
    struct friendslist* c=&social_self->circles[i];
    unsigned int i2;
    for(i2=0; i2<c->count; ++i2)
    {
// TODO: Privacy settings for updates
      if(c->friends[i2]->peer)
      {
        sendupdate(c->friends[i2]->peer, social_self->id, update);
      }
    }
  }
}
