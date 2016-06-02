#
# Simple learning switch application in Ruby
#
# Author: Yasuhito Takamiya <yasuhito@gmail.com>
#
# Copyright (C) 2008-2013 NEC Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# require 'pio'
require 'trema/exact-match'
require_relative 'fdb'

#
# A OpenFlow controller class that emulates a layer-2 switch.
#
class LearningSwitch < Controller
  add_timer_event :age_fdb, 5, :periodic

  def start
    @fdb = FDB.new
  end

  def switch_ready(datapath_id)
    action = SendOutPort.new(port_number: OFPP_CONTROLLER, max_len: OFPCML_NO_BUFFER)
    ins = ApplyAction.new(actions: [action])
    send_flow_mod_add(datapath_id,
                      priority: OFP_LOW_PRIORITY,
                      buffer_id: OFP_NO_BUFFER,
                      flags: OFPFF_SEND_FLOW_REM,
                      instructions: [ins]
    )
  end

  # Handles all incoming packets.
  def packet_in(datapath_id, message)
    # Print out packet information.
    print_packets datapath_id, message
    # Add a new entry in the forwarding table / database.
    @fdb.learn message.eth_src, message.in_port
    # Obtain the port number associated to the destination.
    port_no = @fdb.port_no_of(message.eth_dst)
    if port_no
      flow_mod datapath_id, message, port_no
      packet_out datapath_id, message, port_no
    else
      flood datapath_id, message
    end
  end

  def age_fdb
    @fdb.age
  end

  ##############################################################################

  private

  ##############################################################################

  def flow_mod(datapath_id, message, port_no)
    action = SendOutPort.new(port_number: port_no)
    ins = Instructions::ApplyAction.new(actions: [action])
    send_flow_mod_add(
      datapath_id,
      match: ExactMatch.from(message),
      instructions: [ins]
    )
  end

  def packet_out(datapath_id, message, port_no)
    action = Actions::SendOutPort.new(port_number: port_no)
    send_packet_out(
      datapath_id,
      packet_in: message,
      actions: [action]
    )
  end

  def flood(datapath_id, message)
    packet_out datapath_id, message, OFPP_ALL
  end

  # Responsible for printing out detailed packet information.
  def print_packets(datapath_id, event)
    # Filters packets showing only those sent among hosts defined in the configuration.
    if event.ipv4_src == "192.168.0.1" || event.ipv4_src == "192.168.0.2" || event.ipv4_src == "192.168.0.3"
      puts 'received a packet_in!'
      info "datapath_id: #{ datapath_id.to_hex }"
      info "transaction_id: #{ event.transaction_id.to_hex }"
      info "buffer_id: #{ event.buffer_id.to_hex }"
      info "total_len: #{ event.total_len }"
      info "reason: #{ event.reason.to_hex }"
      info "table_id: #{ event.table_id }"
      info "cookie: #{ event.cookie.to_hex }"
      info "in_port: #{ event.match.in_port }"
      info "data: #{ event.data.map! { | byte | '0x%02x' % byte } }"
      info 'packet_info:'
      info "  eth_src: #{ event.eth_src }"
      info "  eth_dst: #{ event.eth_src }"
      info "  eth_type: #{ event.eth_type.to_hex }"

      if event.eth_type == 0x800 || event.eth_type == 0x86dd
        info "  ip_dscp: #{ event.ip_dscp }"
        info "  ip_ecn: #{ event.ip_ecn }"
        info "  ip_proto: #{ event.ip_proto }"
      end

      if event.vtag?
        info "  vlan_vid: #{ event.vlan_vid.to_hex }"
        info "  vlan_prio: #{ event.vlan_prio.to_hex }"
        info "  vlan_tpid: #{ event.vlan_tpid.to_hex }"
        info "  vlan_tci: #{ event.vlan_tci.to_hex }"
      end

      if event.ipv4?
        info "  ipv4_src: #{ event.ipv4_src }"
        info "  ipv4_dst: #{ event.ipv4_dst }"
      end

      if event.ipv6?
        info "  ipv6_src: #{ event.ipv6_src }"
        info "  ipv6_dst: #{ event.ipv6_dst }"
        info "  ipv6_flabel: #{ event.ipv6_flabel.to_hex }"
        info "  ipv6_exthdr: #{ event.ipv6_exthdr.to_hex }"
      end

      if event.arp?
        info "  arp_op: #{ event.arp_op }"
        info "  arp_sha: #{ event.arp_sha }"
        info "  arp_spa: #{ event.arp_spa }"
        info "  arp_tpa: #{ event.arp_tpa }"
      end

      if event.icmpv4?
        info "  icmpv4_type: #{ event.icmpv4_type.to_hex }"
        info "  icmpv4_code: #{ event.icmpv4_code.to_hex }"
      end

      if event.icmpv6?
        info "  icmpv6_type: #{ event.icmpv6_type.to_hex }"
        info "  icmpv6_code: #{ event.icmpv6_code.to_hex }"
      end

      if event.udp?
        info "  udp_src: #{ event.udp_src.to_hex }"
        info "  udp dst: #{ event.udp_dst.to_hex }"
      end

      if event.sctp?
        info "  sctp_src: #{ event.sctp_src.to_hex }"
        info "  sctp_dst: #{ event.sctp_dst.to_hex }"
      end

      if event.pbb?
        info "  pbb_isid: #{ event.pbb_isid.to_hex }"
      end

      if event.mpls?
        info "  mpls_label: #{ event.mpls_label.to_hex }"
        info "  mpls_tc: #{ event.mpls_tc.to_hex }"
        info "  mpls_bos: #{ event.mpls_bos.to_hex }"
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8
### indent-tabs-mode: nil
### End
