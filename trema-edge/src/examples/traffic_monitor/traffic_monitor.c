/*
 * Traffic counter.
 *
 * Author: Kazushi SUGYO
 *
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


#include <inttypes.h>
#include "trema.h"
#include "fdb.h"
#include "counter.h"


typedef struct {
  hash_table *counter;
  hash_table *fdb;
} traffic;


static uint8_t mac_mask[ OFP_ETH_ALEN ] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


static void
send_flow_mod( uint64_t datapath_id, uint8_t *macsa, uint8_t *macda, uint32_t out_port ) {
  uint64_t cookie_mask = UINT64_MAX;
  uint8_t table_id = 0;
  uint16_t idle_timeout = 0;
  uint16_t hard_timeout = 10;
  uint16_t priority = OFP_HIGH_PRIORITY;
  uint32_t buffer_id = OFP_NO_BUFFER;
  uint32_t out_port_for_delete_command = 0;
  uint32_t out_group_for_delete_command = 0;
  uint16_t flags = OFPFF_SEND_FLOW_REM;
  openflow_actions *actions = create_actions();
  append_action_output( actions, out_port, OFPCML_NO_BUFFER );
  openflow_instructions *insts = create_instructions();
  append_instructions_apply_actions( insts, actions );
  oxm_matches *match = create_oxm_matches();
  append_oxm_match_eth_src( match, macsa, mac_mask );
  append_oxm_match_eth_dst( match, macda, mac_mask );
  buffer *flow_mod = create_flow_mod( get_transaction_id(), get_cookie(), cookie_mask,
                                      table_id, OFPFC_ADD, idle_timeout, hard_timeout,
				      priority, buffer_id,
                                      out_port_for_delete_command,
                                      out_group_for_delete_command,
				      flags, match, insts );
  send_openflow_message( datapath_id, flow_mod );
  free_buffer( flow_mod );
  delete_oxm_matches( match );
  delete_instructions( insts );
  delete_actions( actions );
}


static void
send_packet_out( uint64_t datapath_id, packet_in *message, uint32_t in_port, uint32_t out_port ) {
  uint32_t buffer_id = message->buffer_id;
  if ( datapath_id != message->datapath_id ) {
    buffer_id = OFP_NO_BUFFER;
    in_port = OFPP_CONTROLLER;
  }
  openflow_actions *actions = create_actions();
  append_action_output( actions, out_port, OFPCML_NO_BUFFER );
  const buffer *data = NULL;
  if ( buffer_id == OFP_NO_BUFFER ) {
    data = message->data;
  }
  buffer *packet_out = create_packet_out( get_transaction_id(), buffer_id, in_port, actions, data );

  send_openflow_message( datapath_id, packet_out );
  free_buffer( packet_out );
  delete_actions( actions );
}


static void
do_flooding( uint64_t datapath_id, packet_in *message, uint32_t in_port ) {
  send_packet_out( datapath_id, message, in_port, OFPP_ALL );
}


static void
handle_packet_in( uint64_t datapath_id, packet_in message ) {
  UNUSED( datapath_id );
  uint32_t in_port = get_in_port_from_oxm_matches( message.match );
  if ( in_port == 0 ) {
    return;
  }
  packet_info packet_info = get_packet_info( message.data );
  traffic *db = message.user_data;

  uint8_t *macsa = packet_info.eth_macsa;
  uint8_t *macda = packet_info.eth_macda;

  learn_fdb( db->fdb, macsa, in_port );
  add_counter( db->counter, macsa, 1, message.data->length );
  uint32_t out_port = lookup_fdb( db->fdb, macda );
  if ( out_port != ENTRY_NOT_FOUND_IN_FDB ) {
     send_packet_out( datapath_id, &message, in_port, out_port );
     send_flow_mod( datapath_id, macsa, macda, out_port );
  }
  else {
     do_flooding( datapath_id, &message, in_port );
  }
}


static void
handle_flow_removed( uint64_t datapath_id, flow_removed message ) {
  UNUSED( datapath_id );
  uint8_t *eth_src = NULL;
  for ( list_element *list = message.match->list; list != NULL; list = list->next ) {
    oxm_match_header *oxm = list->data;
    if ( *oxm == OXM_OF_ETH_SRC ) {
      eth_src = ( uint8_t * ) ( ( char * ) oxm + sizeof( oxm_match_header ) );
      break;
    }
  }
  if ( eth_src == NULL ) {
    return;
  }
  traffic *db = message.user_data;
  add_counter( db->counter, eth_src, message.packet_count, message.byte_count );
}


static void
show_each_counter( uint8_t *mac, counter *counter, void *user_data ) {
  UNUSED( user_data );
  printf( "%02x:%02x:%02x:%02x:%02x:%02x %" PRIu64 " packets (%" PRIu64 " bytes)\n",
          mac[ 0 ], mac[ 1 ], mac[ 2 ], mac[ 3 ], mac[ 4 ], mac[ 5 ],
          counter->packet_count, counter->byte_count );
}


static void
show_counter( void *user_data ) {
  traffic *db = user_data;
  time_t now = time( NULL );
  printf( "%s", ctime( &now ) );
  foreach_counter( db->counter, show_each_counter, NULL );
}


static void
handle_switch_ready( uint64_t datapath_id, void *user_data ) {
  UNUSED( user_data );

  openflow_actions *actions = create_actions();
  append_action_output( actions, OFPP_CONTROLLER, OFPCML_NO_BUFFER );

  openflow_instructions *insts = create_instructions();
  append_instructions_apply_actions( insts, actions );

  buffer *flow_mod = create_flow_mod(
    get_transaction_id(),
    get_cookie(),
    0,
    0,
    OFPFC_ADD,
    0,
    0,
    OFP_LOW_PRIORITY,
    OFP_NO_BUFFER,
    0,
    0,
    OFPFF_SEND_FLOW_REM,
    NULL,
    insts
  );
  send_openflow_message( datapath_id, flow_mod );
  free_buffer( flow_mod );

  delete_instructions( insts );

  delete_actions( actions );
}


int
main( int argc, char *argv[] ) {
  init_trema( &argc, &argv );

  traffic db;
  db.counter = create_counter();
  db.fdb = create_fdb();

  add_periodic_event_callback( 10, show_counter, &db );

  set_packet_in_handler( handle_packet_in, &db );
  set_flow_removed_handler( handle_flow_removed, &db );
  set_switch_ready_handler( handle_switch_ready, NULL );

  start_trema();

  delete_fdb( db.fdb );
  delete_counter( db.counter );

  return 0;
}


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
