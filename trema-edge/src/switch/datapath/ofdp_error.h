/*
 * Copyright (C) 2012-2013 NEC Corporation
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


#ifndef OFDP_ERROR_H
#define OFDP_ERROR_H


#include <stdint.h>


typedef enum {
  OFDPE_SUCCESS,
  OFDPE_FAILED,

  ERROR_NO_MEMORY,
  ERROR_LOCK,
  ERROR_UNLOCK,
  ERROR_APPEND_TO_LIST,
  ERROR_INIT_MUTEX,
  ERROR_FINALIZE_MUTEX,
  ERROR_INIT_LIST,
  ERROR_NOT_SUPPORTED,
  ERROR_INVALID_PARAMETER,
  ERROR_NOT_FOUND,
  ERROR_NOT_INITIALIZED,
  ERROR_ALREADY_INITIALIZED,
  ERROR_DROP_PACKET,

  ERROR_OFDPE_HELLO_FAILED_INCOMPATIBLE = 1000,
  ERROR_OFDPE_HELLO_FAILED_EPERM,

  ERROR_OFDPE_BAD_REQUEST_BAD_VERSION,
  ERROR_OFDPE_BAD_REQUEST_BAD_TYPE,
  ERROR_OFDPE_BAD_REQUEST_BAD_MULTIPART,
  ERROR_OFDPE_BAD_REQUEST_BAD_EXPERIMENTER,
  ERROR_OFDPE_BAD_REQUEST_BAD_EXP_TYPE,
  ERROR_OFDPE_BAD_REQUEST_EPERM,
  ERROR_OFDPE_BAD_REQUEST_BAD_LEN,
  ERROR_OFDPE_BAD_REQUEST_BUFFER_EMPTY,
  ERROR_OFDPE_BAD_REQUEST_BUFFER_UNKNOWN,
  ERROR_OFDPE_BAD_REQUEST_BAD_TABLE_ID,
  ERROR_OFDPE_BAD_REQUEST_IS_SLAVE,
  ERROR_OFDPE_BAD_REQUEST_BAD_PORT,
  ERROR_OFDPE_BAD_REQUEST_BAD_PACKET,
  ERROR_OFDPE_BAD_REQUEST_MULTIPART_BUFFER_OVERFLOW,

  ERROR_OFDPE_BAD_ACTION_BAD_TYPE,
  ERROR_OFDPE_BAD_ACTION_BAD_LEN,
  ERROR_OFDPE_BAD_ACTION_BAD_EXPERIMENTER,
  ERROR_OFDPE_BAD_ACTION_BAD_EXP_TYPE,
  ERROR_OFDPE_BAD_ACTION_BAD_OUT_PORT,
  ERROR_OFDPE_BAD_ACTION_BAD_ARGUMENT,
  ERROR_OFDPE_BAD_ACTION_EPERM,
  ERROR_OFDPE_BAD_ACTION_TOO_MANY,
  ERROR_OFDPE_BAD_ACTION_BAD_QUEUE,
  ERROR_OFDPE_BAD_ACTION_BAD_OUT_GROUP,
  ERROR_OFDPE_BAD_ACTION_MATCH_INCONSISTENT,
  ERROR_OFDPE_BAD_ACTION_UNSUPPORTED_ORDER,
  ERROR_OFDPE_BAD_ACTION_BAD_TAG,
  ERROR_OFDPE_BAD_ACTION_BAD_SET_TYPE,
  ERROR_OFDPE_BAD_ACTION_BAD_SET_LEN,
  ERROR_OFDPE_BAD_ACTION_BAD_SET_ARGUMENT,

  ERROR_OFDPE_BAD_INSTRUCTION_UNKNOWN_INST,
  ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_INST,
  ERROR_OFDPE_BAD_INSTRUCTION_BAD_TABLE_ID,
  ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_METADATA,
  ERROR_OFDPE_BAD_INSTRUCTION_UNSUP_METADATA_MASK,
  ERROR_OFDPE_BAD_INSTRUCTION_BAD_EXPERIMENTER,
  ERROR_OFDPE_BAD_INSTRUCTION_BAD_EXP_TYPE,
  ERROR_OFDPE_BAD_INSTRUCTION_BAD_LEN,
  ERROR_OFDPE_BAD_INSTRUCTION_EPERM,

  ERROR_OFDPE_BAD_MATCH_BAD_TYPE,
  ERROR_OFDPE_BAD_MATCH_BAD_LEN,
  ERROR_OFDPE_BAD_MATCH_BAD_TAG,
  ERROR_OFDPE_BAD_MATCH_BAD_DL_ADDR_MASK,
  ERROR_OFDPE_BAD_MATCH_BAD_NW_ADDR_MASK,
  ERROR_OFDPE_BAD_MATCH_BAD_WILDCARDS,
  ERROR_OFDPE_BAD_MATCH_BAD_FIELD,
  ERROR_OFDPE_BAD_MATCH_BAD_VALUE,
  ERROR_OFDPE_BAD_MATCH_BAD_MASK,
  ERROR_OFDPE_BAD_MATCH_BAD_PREREQ,
  ERROR_OFDPE_BAD_MATCH_DUP_FIELD,
  ERROR_OFDPE_BAD_MATCH_EPERM,

  ERROR_OFDPE_FLOW_MOD_FAILED_UNKNOWN,
  ERROR_OFDPE_FLOW_MOD_FAILED_TABLE_FULL,
  ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TABLE_ID,
  ERROR_OFDPE_FLOW_MOD_FAILED_OVERLAP,
  ERROR_OFDPE_FLOW_MOD_FAILED_EPERM,
  ERROR_OFDPE_FLOW_MOD_FAILED_BAD_TIMEOUT,
  ERROR_OFDPE_FLOW_MOD_FAILED_BAD_COMMAND,
  ERROR_OFDPE_FLOW_MOD_FAILED_BAD_FLAGS,

  ERROR_OFDPE_GROUP_MOD_FAILED_GROUP_EXISTS,
  ERROR_OFDPE_GROUP_MOD_FAILED_INVALID_GROUP,
  ERROR_OFDPE_GROUP_MOD_FAILED_WEIGHT_UNSUPPORTED,
  ERROR_OFDPE_GROUP_MOD_FAILED_OUT_OF_GROUPS,
  ERROR_OFDPE_GROUP_MOD_FAILED_OUT_OF_BUCKETS,
  ERROR_OFDPE_GROUP_MOD_FAILED_CHAINING_UNSUPPORTED,
  ERROR_OFDPE_GROUP_MOD_FAILED_WATCH_UNSUPPORTED,
  ERROR_OFDPE_GROUP_MOD_FAILED_LOOP,
  ERROR_OFDPE_GROUP_MOD_FAILED_UNKNOWN_GROUP,
  ERROR_OFDPE_GROUP_MOD_FAILED_CHAINED_GROUP,
  ERROR_OFDPE_GROUP_MOD_FAILED_BAD_TYPE,
  ERROR_OFDPE_GROUP_MOD_FAILED_BAD_COMMAND,
  ERROR_OFDPE_GROUP_MOD_FAILED_BAD_BUCKET,
  ERROR_OFDPE_GROUP_MOD_FAILED_BAD_WATCH,
  ERROR_OFDPE_GROUP_MOD_FAILED_EPERM,

  ERROR_OFDPE_PORT_MOD_FAILED_BAD_PORT,
  ERROR_OFDPE_PORT_MOD_FAILED_BAD_HW_ADDR,
  ERROR_OFDPE_PORT_MOD_FAILED_BAD_CONFIG,
  ERROR_OFDPE_PORT_MOD_FAILED_BAD_ADVERTISE,
  ERROR_OFDPE_PORT_MOD_FAILED_EPERM,

  ERROR_OFDPE_TABLE_MOD_FAILED_BAD_TABLE,
  ERROR_OFDPE_TABLE_MOD_FAILED_BAD_CONFIG,
  ERROR_OFDPE_TABLE_MOD_FAILED_EPERM,

  ERROR_OFDPE_QUEUE_OP_FAILED_BAD_PORT,
  ERROR_OFDPE_QUEUE_OP_FAILED_BAD_QUEUE,
  ERROR_OFDPE_QUEUE_OP_FAILED_EPERM,

  ERROR_OFDPE_SWITCH_CONFIG_FAILED_BAD_FLAGS,
  ERROR_OFDPE_SWITCH_CONFIG_FAILED_BAD_LEN,
  ERROR_OFDPE_SWITCH_CONFIG_FAILED_EPERM,

  ERROR_OFDPE_ROLE_REQUEST_FAILED_STALE,
  ERROR_OFDPE_ROLE_REQUEST_FAILED_UNSUP,
  ERROR_OFDPE_ROLE_REQUEST_FAILED_BAD_ROLE,

  ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN,
  ERROR_OFDPE_METER_MOD_FAILED_METER_EXISTS,
  ERROR_OFDPE_METER_MOD_FAILED_INVALID_METER,
  ERROR_OFDPE_METER_MOD_FAILED_UNKNOWN_METER,
  ERROR_OFDPE_METER_MOD_FAILED_BAD_COMMAND,
  ERROR_OFDPE_METER_MOD_FAILED_BAD_FLAGS,
  ERROR_OFDPE_METER_MOD_FAILED_BAD_RATE,
  ERROR_OFDPE_METER_MOD_FAILED_BAD_BURST,
  ERROR_OFDPE_METER_MOD_FAILED_BAD_BAND,
  ERROR_OFDPE_METER_MOD_FAILED_BAD_BAND_VALUE,
  ERROR_OFDPE_METER_MOD_FAILED_OUT_OF_METERS,
  ERROR_OFDPE_METER_MOD_FAILED_OUT_OF_BANDS,

  ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_TABLE,
  ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_METADATA,
  ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_TYPE,
  ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_LEN,
  ERROR_OFDPE_TABLE_FEATURES_FAILED_BAD_ARGUMENT,
  ERROR_OFDPE_TABLE_FEATURES_FAILED_EPERM,
} OFDPE;


#endif // OFDP_ERROR_H


/*
 * Local variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
*/
