/*
 * Copyright (C) 2008-2013 NEC Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <stdint.h>
#include "trema.h"
#include "ofdp.h"
#include "oxm.h"


static uint32_t udp_src_field( const bool attr, const enum oxm_ofb_match_fields oxm_type );
static uint16_t udp_src_length( const match *match );
static uint16_t pack_udp_src( oxm_match_header *hdr, const match *match );


static struct oxm oxm_udp_src = {
  OFPXMT_OFB_UDP_SRC,
  ( uint16_t ) sizeof( oxm_match_header ) + sizeof( uint16_t ),
  udp_src_field,
  udp_src_length,
  pack_udp_src
};


void 
init_oxm_udp_src( void ) {
  register_oxm( &oxm_udp_src );
}


static uint32_t
udp_src_field( const bool attr, const enum oxm_ofb_match_fields oxm_type ) {
  uint32_t field = 0;

  if ( attr && oxm_type == oxm_udp_src.type ) {
    field = OXM_OF_UDP_SRC;
  }
  return field;
}


static uint16_t
udp_src_length( const match *match ) {
  uint16_t length = 0;
  
  if ( match->udp_src.valid ) {
    length = oxm_udp_src.length;
  }
  return length;
}


static uint16_t
pack_udp_src( oxm_match_header *hdr, const match *match ) {
  if ( match->udp_src.valid ) {
    *hdr = OXM_OF_UDP_SRC;
    uint16_t *value = ( uint16_t * ) ( ( char * ) hdr + sizeof( oxm_match_header ) );
    *value = match->udp_src.value;
    return oxm_udp_src.length;
  }
  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
