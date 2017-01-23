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
char* social_prefix=0;
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
  char path[strlen(social_prefix)+strlen("/users/0")+40];
  sprintf(path, "%s/users", social_prefix);
  mkdir(path, 0700);
  sprintf(path, "%s/users/"PEERFMT, social_prefix, PEERARG(user->id));
  int f=open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
  gnutls_datum_t key;
  gnutls_pubkey_export2(user->pubkey, GNUTLS_X509_FMT_PEM, &key);
  uint32_t size=key.size;
  write(f, &size, sizeof(size));
  write(f, key.data, size);
  gnutls_free(key.data);
  close(f);
}

static void user_load(struct user* user)
{
  // TODO: Absolute path, something like $HOME/.socialnetwork
  // Load user data (only pubkey atm), but spare pubkey if it's already set
  if(!user->pubkey)
  {
    char path[strlen(social_prefix)+strlen("/users/0")+40];
    sprintf(path, "%s/users/"PEERFMT, social_prefix, PEERARG(user->id));
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
  char path[strlen(social_prefix)+strlen("/updates/0")+40];
  sprintf(path, "%s/updates/"PEERFMT, social_prefix, PEERARG(user->id));
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
  struct user* peeruser=social_finduser(peer->id);
  if(!peeruser){peeruser=user_new(peer->id);}
  unsigned int i;
  for(i=0; i<user->updatecount; ++i)
  {
    // Check privacy rules
    if(!social_privacy_check(user, &user->updates[i].privacy, peeruser)){continue;}
    // Also make sure not to send old news (based on seq)
    if(user->updates[i].seq<=seq){continue;}
    sendupdate(peer, user->id, &user->updates[i]);
  }
}

void social_init(const char* keypath, const char* pathprefix)
{
  free(social_prefix);
  social_prefix=strdup(pathprefix);
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
// TODO: Set up socket and bootstrap here too? or accept an already set up socket to bootstrap?
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

struct friendslist* social_user_getcircle(struct user* user, uint32_t circle)
{
  if(circle>=user->circlecount)
  {
    user->circles=realloc(user->circles, sizeof(struct friendslist)*(circle+1));
    for(; user->circlecount<=circle; ++user->circlecount)
    {
      user->circles[user->circlecount].name=0;
      user->circles[user->circlecount].friends=0;
      user->circles[user->circlecount].count=0;
      user->circles[user->circlecount].privacy.flags=0;
      user->circles[user->circlecount].privacy.circles=0;
      user->circles[user->circlecount].privacy.circlecount=0;
    }
  }
  return &user->circles[circle];
}

void social_user_addtocircle(struct user* user, uint32_t circle, const unsigned char id[20])
{
  struct user* friend=social_finduser(id);
  if(!friend){friend=user_new(id);}
  struct friendslist* c=social_user_getcircle(user, circle);
  ++c->count;
  c->friends=realloc(c->friends, sizeof(void*)*c->count);
  c->friends[c->count-1]=friend;
}

void social_user_removefromcircle(struct user* user, uint32_t circle, const unsigned char id[20])
{
  struct user* friend=social_finduser(id);
  if(!friend){friend=user_new(id);}
  struct friendslist* c=social_user_getcircle(user, circle);
  unsigned int i;
  for(i=0; i<c->count; ++i)
  {
    if(c->friends[i]==friend)
    {
      --c->count;
      memmove(&c->friends[i], &c->friends[i+1], sizeof(void*)*(c->count-i));
      // TODO: Garbage-collect users who are no longer friends of anyone we know?
    }
  }
}

void social_addfriend(const unsigned char id[20], uint32_t circle)
{
  struct user* friend=social_finduser(id);
  if(!friend){friend=user_new(id);}
  if(!friend->peer)
  {
    peer_findpeer(id);
    // TODO: Request updates from any mutual friends we're connected to in the meantime
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
  struct update* update=social_update_getfriend(social_self, circle, id);
  ++social_self->seq;
  update->seq=social_self->seq;
  update->timestamp=time(0);
  privcpy(update->privacy, social_self->circles[circle].privacy);
  update->friends.add=1;
  social_update_sign(update);
  social_update_save(social_self, update);
  social_shareupdate(update);
}

void social_removefriend(const unsigned char id[20], uint32_t circle)
{
  social_user_removefromcircle(social_self, circle, id);
  struct update* update=social_update_getfriend(social_self, circle, id);
  ++social_self->seq;
  update->seq=social_self->seq;
  update->type=UPDATE_FRIENDS;
  update->timestamp=time(0);
  privcpy(update->privacy, social_self->circles[circle].privacy);
  update->friends.add=0;
  social_update_sign(update);
  social_update_save(social_self, update);
  social_shareupdate(update);
}

void social_createpost(const char* msg, struct privacy* privacy)
{
  // TODO: Posts attached to users and/or users' updates
  struct update* post=social_update_new(social_self);
  ++social_self->seq;
  post->seq=social_self->seq;
  post->type=UPDATE_POST;
  post->timestamp=time(0);
  privcpy(post->privacy, *privacy);
  post->post.message=strdup(msg);
  social_update_sign(post);
  social_update_save(social_self, post);
  social_shareupdate(post);
}

void social_updatefield(const char* name, const char* value, struct privacy* privacy)
{
  struct update* post=social_update_getfield(social_self, name);
  ++social_self->seq;
  post->seq=social_self->seq;
  post->timestamp=time(0);
  privcpy(post->privacy, *privacy);
  post->field.value=strdup(value);
  social_update_sign(post);
  social_update_save(social_self, post);
  social_shareupdate(post);
}

struct user* social_finduser(const unsigned char id[20])
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
      // Check privacy setting
      if(!social_privacy_check(social_self, &update->privacy, c->friends[i2])){continue;}
      if(c->friends[i2]->peer)
      {
        sendupdate(c->friends[i2]->peer, social_self->id, update);
      }
    }
  }
}

char social_privacy_check(struct user* origin, struct privacy* privacy, struct user* user)
{
  if(privacy->flags&PRIVACY_ANYONE){return 1;}
  unsigned int i, i2;
  if(privacy->flags&PRIVACY_FRIENDS)
  {
    for(i=0; i<origin->circlecount; ++i)
    {
      for(i2=0; i2<origin->circles[i].count; ++i2)
      {
        if(origin->circles[i].friends[i2]==user){return 1;}
      }
    }
  }
  for(i=0; i<privacy->circlecount; ++i)
  {
    if(privacy->circles[i]>=origin->circlecount){continue;}
    struct friendslist* circle=&origin->circles[privacy->circles[i]];
    for(i2=0; i2<circle->count; ++i2)
    {
      if(circle->friends[i2]==user){return 1;}
    }
  }
  return 0;
}

void social_setcircle(uint32_t circle, const char* name, struct privacy* privacy)
{
  struct friendslist* c=social_user_getcircle(social_self, circle);
  free(c->name);
  c->name=strdup(name);
  privcpy(c->privacy, *privacy);
  // Private circle update
  struct update* update=social_update_getcircle(social_self, circle);
  free((void*)update->circle.name);
  ++social_self->seq;
  update->seq=social_self->seq;
  update->timestamp=time(0);
  // TODO: Is there any situation where we would want this update to be public?
  update->circle.circle=circle;
  update->circle.name=strdup(name);
  privcpy(update->circle.privacy, *privacy);
  social_update_sign(update);
  social_update_save(social_self, update);
}
