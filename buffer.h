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
#ifndef BUFFER_H
#define BUFFER_H
#define buffer_init(bufobj) \
  (bufobj).buf=0; \
  (bufobj).size=0; \
  (bufobj).memsize=0
#define buffer_write(bufobj, data, datasize) \
  if((bufobj).memsize-(bufobj).size<datasize) \
  { \
    (bufobj).memsize=(bufobj).size+datasize+128; \
    (bufobj).buf=realloc((bufobj).buf, (bufobj).memsize); \
  } \
  memcpy((bufobj).buf+(bufobj).size, data, datasize); \
  (bufobj).size+=datasize
#define buffer_writestr(bufobj, str) \
  { \
    uint32_t len=strlen(str); \
    buffer_write((bufobj), &len, sizeof(len)); \
    buffer_write((bufobj), str, len); \
  }
#define buffer_deinit(bufobj) free((bufobj).buf)
struct buffer
{
  void* buf;
  unsigned int size;
  unsigned int memsize;
};
#endif
