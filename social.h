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
/**
* SECTION:social
* @title: Social
* @short_description: High-level social functions
*
* High-level social functions
*/
#ifndef SOCIAL_H
#define SOCIAL_H
#include <stdint.h>
#include "peer.h"
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

/**
* user:
* @id: Peer ID
* @pubkey: Public key
* @peer: Peer structure, or NULL if they are not connected
* @circles: Friend circles
* @circlecount: Number of friend circles
* @seq: Sequence number of the last received (and confirmed) update
* @updates: Updates
* @updatecount: Number of updates
* @rotation: Current number of rotating update files loaded
* @rotationcount: Total number of rotating update files for this user
*
* User structure, keeps track of updates, public keys, peer if connected, etc.
*/
struct user
{
  unsigned char id[ID_SIZE];
  gnutls_pubkey_t pubkey;
  struct peer* peer;
  struct friendslist* circles;
  unsigned int circlecount;
  uint64_t seq; // Sequence of updates we have from this user. 64 bits should be enough for a lifetime of updates (18446744073709551616 updates, enough to update 584 times per millisecond for a million years)
  struct update* updates;
  unsigned int updatecount;
  unsigned int rotation;
  unsigned int rotationcount;
};

extern struct user** social_users;
extern unsigned int social_usercount;
extern struct user* social_self; // Most things we need to keep track of for ourself are the same things we need to keep track of for others
extern char* social_prefix;
/**
* social_init:
* @keypath: Path to the private key file used as one's identity
* @pathprefix: Prefix in which to store various data (updates, public keys)
*
* Initialize libsocial with an account/key
*/
extern void social_init(const char* keypath, const char* pathprefix);
extern struct friendslist* social_user_getcircle(struct user* user, uint32_t circle);
extern void social_user_addtocircle(struct user* user, uint32_t circle, const unsigned char id[ID_SIZE]);
extern void social_user_removefromcircle(struct user* user, uint32_t circle, const unsigned char id[ID_SIZE]);
/**
* social_user_loadmore:
* @user: User to load more updates for
*
* Load more updates for a user from the filesystem
* Returns: The number of additional updates loaded (will be 0 when there is nothing more to load)
*/
extern unsigned int social_user_loadmore(struct user* user);
/**
* social_user_getfield:
* @user: The user whose field you wish to access
* @name: Name of the field
*
* Get the value of a #user's field update by name
* Returns: The field's value, or NULL if none was found. Must not be modified or freed
*/
extern const char* social_user_getfield(struct user* user, const char* name);
extern void social_addfriend(const unsigned char id[ID_SIZE], uint32_t circle);
extern void social_removefriend(const unsigned char id[ID_SIZE], uint32_t circle);
/**
* social_createpost:
* @msg: Message to post
* @privacy: Privacy setting for the update
*
* Creates a post update
*/
extern void social_createpost(const char* msg, struct privacy* privacy);
/**
* social_updatefield:
* @name: Name of the field
* @value: The field's (new) value
* @privacy: Privacy setting for the field
*
* Sets the given field's value
*/
extern void social_updatefield(const char* name, const char* value, struct privacy* privacy);
extern struct user* social_finduser(const unsigned char id[ID_SIZE]);
extern void social_shareupdate(struct update* update);
extern char social_privacy_check(struct user* origin, struct privacy* privacy, struct user* user);
/**
* social_setcircle:
* @circle: Circle ID
* @name: New name for the circle
* @privacy: Circle privacy, determines who can see friends in this circle
*
* Set properties for a given circle ID
*/
extern void social_setcircle(uint32_t circle, const char* name, struct privacy* privacy);
#endif
