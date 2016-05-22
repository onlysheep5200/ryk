#-*- coding:utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4,ipv6,icmp,icmpv6,tcp,udp,arp
from ryu.lib.ovs.bridge import OVSBridge,CONF


'''
    PORT_MAPPING = {
        dpid : {
            port_name : port_num
        }
    }

    SWITCH_MAPPING = {
        switch_address : datapath
    }

    TRANSPORT_RULES = {
        protocol_type : {
            (from_datapath_id,from_port_name,to_address) :
            {
            0 :
                //多个出口，供选路时使用
                {
                    local_datapath_id : dpid,
                    local_output_port_name : portname
                    target_datapath_id : dpid,
                    target_output_port_name : portname
                }
            }
        },
        normal : {

        }
    }

    ADDRESS_ARRANGEMENT = {
        ip_address : {
            dpid : dpid,
            port_name : portname
        }
    }
'''

SWITCH_MAPPING = {

}

PORT_MAPPING = {

}

PROTOCOL_TYPE_MAPPING = {
    8888 : "HTTP",
    9999 : "COAP"
}

TRANSPORT_RULES = {
    "HTTP Video Flow" : {
        (1,"s1-eth1","10.0.0.1","10.0.0.2"):{
            0:{
                "local_datapath_id" : 1,
                "local_output_port_name" : "s1-eth2",
            },

        },
        (2,"s2-eth2","10.0.0.1","10.0.0.2"):{
            0:{
                "local_datapath_id" : 2,
                "local_output_port_name" : "s2-eth1",
            },

        },
        (1,"s1-eth1","10.0.0.1","10.0.0.2"):{
            0:{
                "local_datapath_id" : 1,
                "local_output_port_name" : "s1-eth3",
            },

        },
        (1,"s3-eth3","10.0.0.1","10.0.0.2"):{
            0:{
                "local_datapath_id" : 3,
                "local_output_port_name" : "s3-eth1",
            },

        },
        (2,"s2-eth1","10.0.0.2","10.0.0.3"):{
            0:{
                "local_datapath_id" : 2,
                "local_output_port_name" : "s2-eth2",
            },

        },
        (1,"s1-eth2","10.0.0.2","10.0.0.3"):{
            0:{
                "local_datapath_id" : 1,
                "local_output_port_name" : "s1-eth3",
            },

        },
        (3,"s3-eth3","10.0.0.2","10.0.0.3"):{
            0:{
                "local_datapath_id" : 3,
                "local_output_port_name" : "s3-eth1",
            },

        },
    }

}

ADDRESS_ARRANGEMENT = {
    "10.0.0.1":{
        "dpid":1,
        "port_name":"s1-eth1"
    },
    "10.0.0.2" : {
        "dpid" : 2,
        "port_name" : "s2-eth1"
    },
    "10.0.0.3":{
        "dpid":3,
        "port_name" : "s3-eth1"
    }
}

BORDER_PORT = {
    1:{
        2:'s1-eth2',
        3:'s1-eth3'
    },
    2 : {
        1:'s2-eth2',
        3:'s2-eth3'
    },
    3 : {
        1:'s3-eth3',
        2:'s3-eth2'
    }
}

ETH_TYPE = 0x800
IP_PKT_TYPE = ipv4.ipv4

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.init_switch_info(datapath)
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
        self.add_flow(datapath, 0, match, actions)

    def init_switch_info(self,datapath):
        addr = "tcp:%s:6644"%datapath.address[0]
        if True :
            SWITCH_MAPPING[addr] = datapath
            bridge =  OVSBridge(CONF,datapath.id,addr)
            bridge.init()
            port_name_list = bridge.get_port_name_list()
            PORT_MAPPING.setdefault(datapath.id,{})
            for name in port_name_list :
                port_id = bridge.get_ofport(name)
                PORT_MAPPING[datapath.id][name] = port_id



    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        icmp6_pkt = pkt.get_protocols(icmpv6.icmpv6)
        icmp_pkt = pkt.get_protocols(icmp.icmp)
        arp_pkt = pkt.get_protocols(arp.arp)
        ip_pkt = pkt.get_protocols(IP_PKT_TYPE)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if icmp6_pkt :
            self._operate_with_icmpv6(icmp6_pkt[0],datapath,msg)
        elif icmp_pkt :
            self._operate_with_icmpv6(icmp_pkt[0],datapath,msg)
        elif arp_pkt :
            self._arp_route(datapath,arp_pkt[0],msg)
        elif ip_pkt :
            tsl_pkt = self._get_tsl_pkg(pkt)
            if tsl_pkt :
                self._operate_with_transport_layer(ip_pkt[0],tsl_pkt,datapath,msg)
            else :
                print "未知的传输层协议"



    def _operate_with_icmpv6(self,pkt,datapath,msg):
        output_port = None
        output_dp = None
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #邻居发现协议
        if isinstance(pkt,icmpv6.icmpv6) and  isinstance(pkt.data,icmpv6.nd_neighbor) :

            target = ADDRESS_ARRANGEMENT.get(pkt.data.dst)
            if not target :
                output_port = ofproto.OFPP_FLOOD
                output_dp = datapath
            else :
                #output_dp = SWITCH_MAPPING[target['dp_address']]
                output_dp = self.datapaths[target['dpid']]
                output_port = PORT_MAPPING[output_dp.id][target['port_name']]
        else :
            output_dp = datapath
            output_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(output_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=msg.data)
        output_dp.send_msg(out)


    def _operate_with_transport_layer(self,ip_pkt,tsl_pkt,datapath,msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        from_port_name = None
        #from_datapath_address = datapath.address[0]
        from_datapath_id = datapath.id
        protocol_type = self._get_protocol_type(tsl_pkt)
        if not protocol_type or protocol_type == 'normal' :
            out = self._default_routing_policy(datapath,ip_pkt,msg)
            datapath.send_msg(out)
            return
        to_adress = ip_pkt.dst
        src_address = ip_pkt.src
        ports = PORT_MAPPING.get(datapath.id)
        if ports :
            for p in ports :
                if ports[p] == msg.match['in_port'] :
                    from_port_name = p
                    break
        #if from_port_name and from_datapath_address and protocol_type :
        if from_port_name and from_datapath_id and protocol_type :
            #selections = TRANSPORT_RULES[protocol_type][(from_port_name,from_datapath_address)]
            selections = TRANSPORT_RULES[protocol_type][(from_datapath_id,from_port_name,src_address,to_adress)]
            output_selection = self._select_route(selections)
            #local_datapath_address = output_selection['local_datapath_address']
            local_datapath_id = output_selection['local_datapath_id']
            local_output_port_name = output_selection['local_output_port_name']
            #target_datapath_address = output_selection['target_datapath_address']
            target_datapath_id = output_selection['target_datapath_id']
            target_output_port_name = output_selection['target_output_port_name']

            #local_datapath = SWITCH_MAPPING[local_datapath_address]
            local_datapath = self.datapaths[local_datapath_id]
            local_outport = PORT_MAPPING[local_datapath.id][local_output_port_name]

            local_actions = [parser.OFPActionOutput(local_outport)]
            local_match = self._get_ofmatch_for_tsl(parser,ip_pkt,tsl_pkt,msg.match['in_port'])
            self.add_flow(local_datapath,1,local_match,local_actions)
            out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=local_actions,data = msg.data)
            #if target_datapath_address and local_datapath_address != target_datapath_address :
            if target_datapath_id and local_datapath_id != target_datapath_id :
                target_match = self._get_ofmatch_for_tsl(parser,ip_pkt,tsl_pkt,None)
                #target_datapath = SWITCH_MAPPING[target_datapath_address]
                target_datapath = self.datapaths[target_datapath_id]
                target_outport = PORT_MAPPING[target_datapath.id][target_output_port_name]
                target_actions = [parser.OFPActionOutput(target_outport)]
                self.add_flow(target_datapath,1,target_match,target_actions)
            local_datapath.send_msg(out)
            print protocol_type+" flow from "+from_port_name+" will be sent via port "+local_output_port_name


    def _get_tsl_pkg(self,pkt):
        tcp_pkt = pkt.get_protocols(tcp.tcp)
        if tcp_pkt :
            return tcp_pkt[0]
        else :
            udp_pkt = pkt.get_protocols(udp.udp)
            if udp_pkt :
                return udp_pkt[0]
        return None

    def _get_protocol_type(self,pkt):
        #PROTOCOL_TYPE_MAPPING.setdefault(pkt.src_port,'normal')
        return PROTOCOL_TYPE_MAPPING.get(pkt.src_port)

    def _select_route(self,selections):
        '''
        选路函数
        :param selections:可选路径集合
        :return:选中的路径
        '''
        #TODO：具体选路逻辑
        return selections[0] if selections else None

    def _get_ofmatch_for_tsl(self,parser,ip_pkt,tsl_pkt,in_port = None):
        ip_proto = 6
        if isinstance(tsl_pkt,tcp.tcp) :
            ip_proto = 6
        elif isinstance(tsl_pkt,udp.udp) :
            ip_proto = 17
        src = tsl_pkt.src_port
        dst = tsl_pkt.dst_port
        ip_src = ip_pkt.src
        ip_dst = ip_pkt.dst
        match = parser.OFPMatch(eth_type=ETH_TYPE,ip_proto=ip_proto)
        if isinstance(IP_PKT_TYPE,ipv6.ipv6) :
            match.ipv6_src = ip_src
            match.ipv6_dst = ip_dst
        else :
            match.ipv4_src= ip_src
            match.ipv4_dst = ip_dst
        if in_port :
            match.in_port = in_port
        if ip_proto == 6 :
            match.tcp_src = src
            match.tcp_dst = dst
        else :
            match['udp_src'] = src
            match['udp_dst'] = dst
        return match

    def _default_routing_policy(self,datapath,ip_pkt,msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dst_ip = ip_pkt.dst
        target_dpid = ADDRESS_ARRANGEMENT[dst_ip]['dpid']
        border_port_name = BORDER_PORT[datapath.id][target_dpid]
        actions = [parser.OFPActionOutput(PORT_MAPPING[datapath.id][border_port_name])]
        return parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)

    def _arp_route(self,datapath,pkt,msg):
        parser = datapath.ofproto_parser
        dst_ip = pkt.dst_ip
        target = ADDRESS_ARRANGEMENT[dst_ip]
        if target :
            dst_dpid = target['dpid']
            dst_port_name = target['port_name']
            if dst_ip == datapath.id :
                actions = [parser.OFPActionOutput(PORT_MAPPING[datapath.id][dst_port_name])]
            else :
                border_port_name = BORDER_PORT[datapath.id][dst_dpid]
                actions = [parser.OFPActionOutput(PORT_MAPPING[datapath.id][border_port_name])]
            out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)
            datapath.send_msg(out)








