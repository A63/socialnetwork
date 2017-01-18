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
#include "social.h"
#include "buffer.h"

enum updatetype
{
  UPDATE_FIELD=0, // Name, profile description etc.
  UPDATE_POST,
  UPDATE_MEDIA, // Pictures, other files?
  UPDATE_FRIENDS, // Friend addition/removal
  UPDATE_CIRCLE, // Private circle names
// TODO: UPDATE_DELETEPOST? post/media comments? (or maybe commenting on any kind of update?)
};
struct update
{
  const char* signature;
  uint32_t signaturesize;
  uint64_t seq; // Sequence of this update
  uint8_t type;
  uint64_t timestamp;
  struct privacy privacy;
  union
  {
    struct // I guess we let it be possible to have any kind of field
    {
      const char* name;
      const char* value;
      // Don't include media but allow referencing other shared media
    } field;
    struct
    {
      // TODO: some equivalent of posting on someone/something's wall?
      const char* message;
    } post;
    struct
    {
      const char* name;
      uint64_t size; // Allow large files, TODO: but maybe have a per-client limit of how large things you'll host. Also large files need to be split up somehow, can't send 1 gigabyte UDP packets
    } media;
    struct
    {
      uint32_t circle;
      unsigned char id[20];
      char add; // 1=add, 0=remove
    } friends;
    struct
    {
      uint32_t circle;
      const char* name;
      struct privacy privacy;
    } circle;
  };
};
extern void social_update_write(struct buffer* buf, struct update* update);
extern struct update* social_update_new(struct user* user);
extern void social_update_sign(struct update* update);
extern void social_update_save(struct user* user, struct update* update);
extern struct update* social_update_getfield(struct user* user, const char* name);
extern struct update* social_update_getfriend(struct user* user, uint32_t circle, const unsigned char id[20]);
extern struct update* social_update_getcircle(struct user* user, uint32_t circle);
extern struct update* social_update_parse(struct user* user, void* data, unsigned int len); // Both for receiving updates and loading them from file
