# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'''
Notice, the lifecycle of virtual and physical entry is quite different:
1. virtual entry comes from PacketIn event, and decays in clean routine.
2. physical entry comes from PacketIn event, but decays in FlowRemoved event.
'''
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, udp, tcp
from ryu.lib.packet import ether_types, in_proto

class HardController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HardController, self).__init__(*args, **kwargs)
        # mac_map indicates the 'out_port' of a session.
        self.mac_map = dict()
        # virtual table to manage flow tables 
        self.vtables = dict()
        # global default idle time or init hard time 
        self.init_t0 = 3

    def _init_controller(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, 9527, match, actions)

    # each session is constructed with (layer, five_tuple)
    # layer = 3, proto = ether_type.(ETH_TYPE_ARP)
    #    arp = (proto, eth_src, None, eth_dst, None)
    # layer = 4, proto = in_proto.IPPROTO_ICMP
    #   icmp = (proto, ip_src, None, ip_dst, None)
    # layer = 4, proto = in_proto.(IPPROTO_UDP or IPPROTO_TCP)
    #   tcp/udp = (proto, ip_src, port_src, ip_dst, port_dst)

    def _init_session(self, datapath, session, outport, ht, it):
        parser = datapath.ofproto_parser
        net_layer, net_proto = session[0], session[1]
        src1, src2, dst1, dst2 = session[2:]

        if net_layer == 3:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                    #eth_src=src1,
                                    eth_dst=dst1)
        elif net_proto == in_proto.IPPROTO_TCP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=src1,
                                    ipv4_dst=dst1,
                                    ip_proto=net_proto,
                                    tcp_src=src2,
                                    tcp_dst=dst2)
        elif net_proto == in_proto.IPPROTO_UDP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=src1,
                                    ipv4_dst=dst1,
                                    ip_proto=net_proto,
                                    udp_src=src2,
                                    udp_dst=dst2)
        else: # it should be ICMP
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=src1,
                                    ipv4_dst=dst1,
                                    ip_proto=net_proto)    
        # cookie is the hash value of conn (five tuple)
        cookie = hash(session[1:]) % (2**32-1)
        actions = [parser.OFPActionOutput(outport)]
        self._add_flow(datapath, net_layer, cookie, match, actions, ht, it)

    # init virtual table and segments with different ratio 
    # alpha means the ratio of temporal segments
    # beta means the ratio of persistent segments
    def _init_vtable(self, dpid, capacity, alpha=1):
        pt_size = int(alpha * capacity)

        print('initializing dpid: ', dpid)
        seg_t = self._init_segment(pt_size, dpid)

        # each vtable has a temporal segment (seg_t for short)
        # and a persistent segment (seg_p for short)
        self.vtables[dpid] = {
            'phy_size': capacity,
            'seg_t': seg_t
        }

################################################################
# the following routines are for segment management
################################################################
    def _init_segment(self, pt_size, dpid):
        segment = {
            'pt_size': pt_size,
            'pt_idx': 0,        # current pt size
            'records': {},      # traffic features
            'dpid': dpid,       # dpid for log
        }
        return segment
    
    def _inc_seg_ref(self, seg, flag):
        dpid = seg['dpid']
        idx = '%s_idx' %flag
        seg[idx] += 1
        print('[+] dpid {0}, seg {1}, size: {2}'.format(dpid, flag, seg[idx])) 

    def _dec_seg_ref(self, seg, flag):
        dpid = seg['dpid']
        idx = '%s_idx' %flag
        if seg[idx] > 0:
            seg[idx] -= 1
        print('[-] dpid {0}, seg {1}, size: {2}'.format(dpid, flag, seg[idx])) 

    def _is_seg_free(self, seg, flag):
        idx = '%s_idx' %flag
        size = '%s_size' %flag
        return seg[idx] < seg[size]

    def _is_rec_alive(self, seg, conn):
        conn_rec = seg['records'][conn]
        return conn_rec['alive']

    def _is_rec_ticks(self, seg, conn):
        conn_rec = seg['records'][conn]
        return conn_rec['ticks'] < self.max_ticks

    def _set_rec_init(self, seg, conn):
        seg['records'][conn] = {
            'alive': True,
        }

    def _set_rec_state(self, seg, conn, state):
        conn_rec = seg['records'][conn]
        conn_rec['alive'] = state

    
    # check the stable state, in practice we have no way to infer
    # the state because the controller is always running, so when 
    # the pps is half full, we record the state.
    def _manage_segment(self, datapath, conn):
        dpid = datapath.id
        vtable = self.vtables[dpid]
        seg_t = vtable['seg_t']
        rec_t = seg_t['records']

        # for any new connections
        if conn not in rec_t:
            if not self._is_seg_free(seg_t, 'pt'): 
                return False
            self._inc_seg_ref(seg_t, 'pt')
            self._set_rec_init(seg_t, conn)
            self._set_rec_state(seg_t, conn, True)
            return True
        elif self._is_rec_alive(seg_t, conn):
            return False 
        else:
            # do entry replacement 
            if not self._is_seg_free(seg_t, 'pt'):
                # ignore the request and do nothing
                return False
            else:
                self._inc_seg_ref(seg_t, 'pt')
                self._set_rec_state(seg_t, conn, True)
                return True

    def _extract_meta(self, msg_data):
        pkt = packet.Packet(msg_data)
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_src, eth_dst = eth.src, eth.dst
        ether_type = eth.ethertype
        session = None

        if ether_type == ether_types.ETH_TYPE_ARP:
            session = (3, ether_type, eth_src, None, eth_dst, None)
        elif ether_type == ether_types.ETH_TYPE_IP:
            # only handle TCP or UDP packet
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            ip_src, ip_dst = ipv4_pkt.src, ipv4_pkt.dst
            proto = ipv4_pkt.proto
            if proto == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                port_src = tcp_pkt.src_port
                port_dst = tcp_pkt.dst_port
            elif proto == in_proto.IPPROTO_UDP:
                udp_pkt = pkt.get_protocol(udp.udp)
                port_src = udp_pkt.src_port
                port_dst = udp_pkt.dst_port
            elif proto == in_proto.IPPROTO_ICMP:
                port_src = port_dst = 0
            else:
                return None
            session = (4, proto, ip_src, port_src, ip_dst, port_dst)
        else:
            return None
        return (eth_src, eth_dst), session

    def _query_timeout(self):
        hard_timeout = self.init_t0 
        idle_timeout = 0
        return hard_timeout, idle_timeout

    def _add_flow(self, datapath, priority, cookie, match, \
            actions, hard_time=0, idle_time=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority, 
                                    cookie=cookie, 
                                    match=match, 
                                    hard_timeout=hard_time,
                                    idle_timeout=idle_time,  
                                    instructions=inst, 
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority, 
                                    cookie=cookie, 
                                    match=match, 
                                    hard_timeout=hard_time,
                                    idle_timeout=idle_time, 
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst)
        datapath.send_msg(mod)    

    def _del_flow(self, datapath, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id=ofproto.OFPTT_ALL,
                                cookie=cookie,
                                cookie_mask=0xFFFFFFFFFFFFFFFF,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)


    def _packet_handler(self, msg, session, inport, outport):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        net_layer = session[0]
        if outport != ofproto.OFPP_FLOOD:
            if net_layer == 3:
                ht, it = 0, 0
            else:
                conn = hash(session[1:]) % (2**32 - 1)
                if not self._manage_segment(datapath, conn):
                    return
                ht, it = self._query_timeout()
            self._init_session(datapath, session, outport, ht, it)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        actions = [parser.OFPActionOutput(outport)]
        out = parser.OFPPacketOut(datapath=datapath, 
                                  buffer_id=msg.buffer_id,
                                  in_port=inport, 
                                  actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        inport = msg.match['in_port']
        dpid = datapath.id

        # not target packets
        pkt_meta = self._extract_meta(msg.data)
        if not pkt_meta: 
            return
        (eth_src, eth_dst), session = pkt_meta
    
        self.mac_map.setdefault(dpid, {})
        self.mac_map[dpid][eth_src] = inport
        if eth_dst in self.mac_map[dpid]:
            outport = self.mac_map[dpid][eth_dst]
        else:
            outport = ofproto.OFPP_FLOOD
        self._packet_handler(msg, session, inport, outport)
        
    #handle initial routes and switch-controller session
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self._init_controller(datapath)
        self._init_vtable(datapath.id, 200)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        vtable = self.vtables[dpid]
        seg_t = vtable['seg_t']
        rec_t = seg_t['records']
        conn = msg.cookie

        if msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
            if conn not in rec_t: # unexpected
                print('[HARD: {0}] unexpect conn: {1}'.format(dpid, conn))
                return
            self._dec_seg_ref(seg_t, 'pt')
            self._set_rec_state(seg_t, conn, False)

