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
#include "social.h"
#include "update.h"

static void mkdirp(char* path)
{
  char* next=path;
  char* slash;
  while((slash=strchr(next, '/')))
  {
    next=&slash[1];
    slash[0]=0;
    mkdir(path, 0700);
    slash[0]='/';
  }
}

void social_update_write(struct buffer* buf, struct update* update)
{
  // Write update to buffer, minus the signature (in part to generate the signature)
  buffer_write(*buf, &update->seq, sizeof(update->seq));
  buffer_write(*buf, &update->type, sizeof(update->type));
  buffer_write(*buf, &update->timestamp, sizeof(update->timestamp));
  buffer_write(*buf, &update->privacy.flags, sizeof(update->privacy.flags));
  buffer_write(*buf, &update->privacy.circlecount, sizeof(update->privacy.circlecount));
  buffer_write(*buf, update->privacy.circles, update->privacy.circlecount);
  uint32_t privplaceholder=0;
  buffer_write(*buf, &privplaceholder, sizeof(privplaceholder));
  switch(update->type)
  {
  case UPDATE_FIELD:
    buffer_writestr(*buf, update->field.name);
    buffer_writestr(*buf, update->field.value);
    break;
  case UPDATE_POST:
    buffer_writestr(*buf, update->post.message);
    break;
  case UPDATE_MEDIA:
// TODO: Handle large media, can't keep it all in RAM. Maybe only send name and size here and handle requests for the actual data separately?
    buffer_writestr(*buf, update->media.name);
    buffer_write(*buf, &update->media.size, sizeof(update->media.size));
// TODO: Include signature of file?
    break;
  case UPDATE_FRIENDS:
    buffer_write(*buf, &update->friends.circle, sizeof(update->friends.circle));
    buffer_write(*buf, &update->friends.add, sizeof(update->friends.add));
    buffer_write(*buf, update->friends.id, 20);
    break;
  case UPDATE_CIRCLE:
    buffer_write(*buf, &update->circle.circle, sizeof(update->circle.circle));
    buffer_writestr(*buf, update->circle.name);
    break;
  }
}

struct update* social_update_new(struct user* user)
{
  ++user->updatecount;
  user->updates=realloc(user->updates, sizeof(struct update)*user->updatecount);
  user->updates[user->updatecount-1].privacy.flags=0;
  user->updates[user->updatecount-1].privacy.circles=0;
  user->updates[user->updatecount-1].privacy.circlecount=0;
  return &user->updates[user->updatecount-1];
}

void social_update_sign(struct update* update)
{
  struct buffer buf;
  buffer_init(buf);
  social_update_write(&buf, update);
  gnutls_datum_t data={.data=buf.buf, .size=buf.size};
  gnutls_datum_t signature;
  gnutls_privkey_sign_data(peer_privkey, GNUTLS_DIG_SHA1, 0, &data, &signature);
  buffer_deinit(buf);
  update->signaturesize=signature.size;
  void* sigbuf=malloc(signature.size);
  memcpy(sigbuf, signature.data, signature.size);
  gnutls_free(signature.data);
  update->signature=sigbuf;
}

void social_update_save(struct user* user, struct update* update)
{
  // TODO: Absolute path, something like $HOME/.socialnetwork
  char path[strlen("updates/0")+40];
  sprintf(path, "updates/"PEERFMT, PEERARG(user->id));
  mkdirp(path);
  int f=open(path, O_WRONLY|O_CREAT|O_APPEND, 0600);
  struct buffer buf;
  buffer_init(buf);
  social_update_write(&buf, update);
  uint64_t size=sizeof(update->signaturesize)+update->signaturesize+buf.size;
  write(f, &size, sizeof(size));
  write(f, &update->signaturesize, sizeof(update->signaturesize));
  write(f, update->signature, update->signaturesize);
  write(f, buf.buf, buf.size);
  buffer_deinit(buf);
  close(f);
// TODO: Is it bad to close and reopen a file in rapid succession? if it is maybe we should implement some kind of cache for cases where we're saving many updates fast, like receiving someone else's updates for the first time
}

struct update* social_update_getfield(struct user* user, const char* name)
{
  unsigned int i;
  for(i=0; i<user->updatecount; ++i)
  {
    if(user->updates[i].type!=UPDATE_FIELD){continue;}
    if(!strcmp(user->updates[i].field.name, name)){return &user->updates[i];}
  }
  struct update* ret=social_update_new(user);
  ret->seq=0;
  ret->signature=0;
  ret->field.name=strdup(name);
  ret->field.value=0;
  return ret;
}

struct update* social_update_getfriend(struct user* user, uint32_t circle, const unsigned char id[20])
{
  unsigned int i;
  for(i=0; i<user->updatecount; ++i)
  {
    if(user->updates[i].type!=UPDATE_FRIENDS){continue;}
    if(user->updates[i].friends.circle!=circle){continue;}
    if(!memcmp(user->updates[i].friends.id, id, 20)){return &user->updates[i];}
  }
  struct update* ret=social_update_new(user);
  ret->seq=0;
  ret->signature=0;
  ret->friends.circle=circle;
  memcpy(ret->friends.id, id, 20);
  return ret;
}

#define advance(data, size, length) data+=length; size-=length
#define readbin(data, datalen, buf, buflen) \
  if(datalen<buflen){return 0;} \
  memcpy(buf, data, buflen); \
  advance(data, datalen, buflen)
struct update* social_update_parse(struct user* user, void* data, unsigned int len) // Both for receiving updates and loading them from file
{
  // <sigsize, 4><signature><seq, 8><type, 1><timestamp, 8><type-specific data>
  uint32_t signaturesize;
  uint64_t seq;
  uint8_t type;
  uint64_t timestamp;
  readbin(data, len, &signaturesize, sizeof(signaturesize));
  unsigned char signature[signaturesize];
  readbin(data, len, signature, signaturesize);
  if(!user->pubkey){return 0;} // Don't have their public key to verify yet
  // 1. Verify signature
  gnutls_datum_t verifydata={.data=data, .size=len};
  gnutls_datum_t verifysig={.data=signature, .size=signaturesize};
  if(gnutls_pubkey_verify_data2(user->pubkey, GNUTLS_SIGN_RSA_SHA1, 0, &verifydata, &verifysig)<0){return 0;} // Forgery
  readbin(data, len, &seq, sizeof(seq));
  readbin(data, len, &type, sizeof(type));
  readbin(data, len, &timestamp, sizeof(timestamp));
  // Privacy settings
  struct privacy privacy;
  readbin(data, len, &privacy.flags, sizeof(privacy.flags));
  readbin(data, len, &privacy.circlecount, sizeof(privacy.circlecount));
  uint32_t privcircles[privacy.circlecount];
  privacy.circles=privcircles;
  readbin(data, len, privacy.circles, privacy.circlecount);
  // Placeholder, potentially supporting lists of individuals in addition to circles
  uint32_t privplaceholder;
  readbin(data, len, &privplaceholder, sizeof(privplaceholder));
  // 2. Check sequence number uniqueness
  // NOTE: If instead of checking uniqueness we just checked if seq was higher than the user's previous seq: When relaying updates to a friend's friend a malicious peer could skip some entries, but pass along a more recent one, to effectively censor the earlier entries even when the author themself sends them at a later time. Hopefully it'll be enough that we probably get updates from multiple sources, so if one skips stuff we'll still get filled in by someone else
  unsigned int i;
  for(i=0; i<user->updatecount; ++i)
  {
    if(user->updates[i].seq==seq){return 0;} // Old update
  }
// TODO: To avoid an accidental form of the above when a friend's friend is in different circles and doesn't get the same updates, only update seq when we get the update directly from user or when seq==user->seq+1
  if(user->seq<seq){user->seq=seq;} // Update user's sequence
  // 3. Add to list of updates, replacing any old entry for the same data when applicable (e.g. updating profile fields, but not posts)
  struct update* update;
  switch(type)
  {
  case UPDATE_FIELD:
    {
    uint32_t namelen;
    readbin(data, len, &namelen, sizeof(namelen));
    uint32_t valuelen;
    if(len<namelen+sizeof(valuelen)){return 0;}
    char name[namelen+1];
    readbin(data, len, name, namelen);
    name[namelen]=0;
    readbin(data, len, &valuelen, sizeof(valuelen));
    if(len<valuelen){return 0;}
    char* value=malloc(valuelen+1);
    readbin(data, len, value, valuelen);
    value[valuelen]=0;
    // Erase/replace any old field with the same name if the sequence number is higher
    update=social_update_getfield(user, name);
    if(update->seq>seq){free(value); return 0;} // Old version
    free((void*)update->signature);
    free((void*)update->field.value);
    update->field.value=value;
    }
    break;
  case UPDATE_POST:
    {
    uint32_t msglen;
    readbin(data, len, &msglen, sizeof(msglen));
    if(len<msglen){return 0;}
    char* msg=malloc(msglen+1);
    readbin(data, len, msg, msglen);
    msg[msglen]=0;
    update=social_update_new(user);
    update->post.message=msg;
    }
    break;
  case UPDATE_MEDIA:
    return 0; // TODO: Implement
    break;
  case UPDATE_FRIENDS:
    {
    uint32_t circle;
    unsigned char id[20];
    char add;
    readbin(data, len, &circle, sizeof(circle));
    readbin(data, len, &add, sizeof(add));
    readbin(data, len, id, 20);
    if(add)
    {
      social_user_addtocircle(user, circle, id);
    } // TODO: Removal
    update=social_update_getfriend(user, circle, id);
    if(update->seq>seq){return 0;} // Old version
    update->friends.add=add;
    }
    break;
  default: return 0;
  }
  void* sigbuf=malloc(signaturesize);
  memcpy(sigbuf, signature, signaturesize);
  update->signaturesize=signaturesize;
  update->signature=sigbuf;
  update->seq=seq;
  update->type=type;
  update->timestamp=timestamp;
  privcpy(update->privacy, privacy);
  return update;
}
