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
#ifndef SOCIAL_H
#define SOCIAL_H
#include <stdint.h>
#define PRIVACY_ANYONE  1
#define PRIVACY_FRIENDS 2
struct privacy
{
  uint8_t flags;
  uint32_t* circles; // Circle indexes
  uint32_t circlecount;
// TODO: Allow individual users as well?
};
#define privcpy(dst,src) \
  free((dst).circles); \
  (dst).flags=(src).flags; \
  (dst).circlecount=(src).circlecount; \
  (dst).circles=malloc(sizeof(uint32_t)*(dst).circlecount); \
  memcpy((dst).circles, (src).circles, sizeof(uint32_t)*(dst).circlecount)

struct friendslist
{
  char* name; // What to call this circle of friends
  struct privacy privacy; // Privacy setting to use for additions and removals from this circle
  struct user** friends;
  unsigned int count;
};

struct user
{
  unsigned char id[20];
  gnutls_pubkey_t pubkey;
  struct peer* peer;
  const char* name;
  struct friendslist* circles;
  unsigned int circlecount;
  uint64_t seq; // Sequence of updates we have from this user. 64 bits should be enough for a lifetime of updates (18446744073709551616 updates, enough to update 584 times per millisecond for a million years)
  struct update* updates;
  unsigned int updatecount;
};

extern struct user** social_users;
extern unsigned int social_usercount;
extern struct user* social_self; // Most things we need to keep track of for ourself are the same things we need to keep track of for others
extern void social_init(const char* keypath);
extern void social_user_addtocircle(struct user* user, uint32_t circle, const unsigned char id[20]);
extern void social_addfriend(const unsigned char id[20], uint32_t circle);
extern void social_createpost(const char* msg, struct privacy* privacy);
extern void social_updatefield(const char* name, const char* value, struct privacy* privacy);
extern struct user* social_finduser(const unsigned char id[20]);
extern void social_shareupdate(struct update* update);
extern char social_privacy_check(struct user* origin, struct privacy* privacy, struct user* user);
#endif