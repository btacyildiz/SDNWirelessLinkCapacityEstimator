def _send_probe_packet(self, datapath, port):

    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=UNIQUE_PROBE_PACKET_ID,
                                        dst="123",
                                        src="123"))
    pkt.data = "Test Berkay 1234"
    pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                code=icmp.ICMP_ECHO_REPLY_CODE,
                                csum=0,
                                data="Test Berkay"))
    self._send_packet(datapath, port, pkt)

def _send_packet(self, datapath, port, pkt):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    pkt.serialize()
    self.logger.info("packet-out %s" % (pkt,))
    data = pkt.data
    actions = [parser.OFPActionOutput(port=port)]
    out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions,
                                data=data)
    datapath.send_msg(out)
