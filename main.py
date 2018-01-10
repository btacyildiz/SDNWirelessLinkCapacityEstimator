# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

# coding: utf-8


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

# for sending periodic probe packets
import threading
import time

PROBE_PACKET_ID_START = 37400
PROBE_PACKET_ID_END = 37440 

NUMBER_OF_PROBE_PACKETS = 40
PROBE_PACKET_SIZE = 60


class LinkCapacityEstimator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LinkCapacityEstimator, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}
        self.is_sent_already = False
        self.datapath_1 = None
        self.measure_start_time = 0
        

        # start mesauring sequence
        threading.Thread(target=self.auto_send_probe_packet).start()

    
    def auto_send_probe_packet(self):
        while True:
            time.sleep(10)
            self.logger.info("Initializing measuring sequence")
            self.measure_start_time = time.time()
            if self.datapath_1 is not None:
                eth_type_will_send = PROBE_PACKET_ID_START
                while(eth_type_will_send <= PROBE_PACKET_ID_END):
                    self._send_probe_packet(self.datapath_1, self.datapath_1.ofproto.OFPP_FLOOD, eth_type_will_send)
                    #self.logger.info("Packet Sent datapathid: " + str(self.datapath_1.id) + "\n")
                    eth_type_will_send += 1
            else:
                self.logger.info("Datapath is not initialized!")



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)
        
        
        match1 = parser.OFPMatch(eth_type=PROBE_PACKET_ID_START)
        match2 = parser.OFPMatch(eth_type=PROBE_PACKET_ID_END)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match1, actions)
        self.add_flow(datapath, 0, match2, actions)


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # print packet info
        pkt = packet.Packet(data=msg.data)
        
        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # assing the local datapath variable
        if dpid == 1:
            self.datapath_1 = datapath

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        
        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        if eth_pkt.ethertype == PROBE_PACKET_ID_START:
            self.logger.info("packet-in data %s" % (pkt,))
        if eth_pkt.ethertype == PROBE_PACKET_ID_END:
            self.logger.info("packet-in data %s" % (pkt,))
            self.logger.info("Start Time : " + str(self.measure_start_time))
            self.logger.info("End Time : " + str(time.time()))
            link_capacity = ((NUMBER_OF_PROBE_PACKETS - 1)  * PROBE_PACKET_SIZE ) / (time.time() - self.measure_start_time)
            self.logger.info("Link Capacity: " + str(link_capacity))

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)

        datapath.send_msg(out)

    
    def _send_probe_packet(self, datapath, port, eth_type):

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=eth_type,
                                           dst="00:00:00:00:00:01",
                                           src="00:00:00:00:00:02"))
        self._send_packet(datapath, port, pkt)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)