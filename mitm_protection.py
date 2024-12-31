from pox.core import core
from pox.lib.packet import ethernet
from pox.lib.addresses import EthAddr
from pox.openflow import libopenflow_01 as of

log = core.getLogger()

# Địa chỉ MAC của hmi và plc1
MAC_HMI = "00:1D:9C:C8:BC:20"
MAC_PLC1 = "00:1D:9C:C7:B0:10"

class MitmProtection(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        # Kiểm tra luồng giữa hmi và plc1
        if (packet.src == EthAddr(MAC_HMI) and packet.dst == EthAddr(MAC_PLC1)) or \
           (packet.src == EthAddr(MAC_PLC1) and packet.dst == EthAddr(MAC_HMI)):
            log.info(f"Allowing communication between {packet.src} and {packet.dst}")
            self.allow_traffic(event, event.ofp.in_port)
        else:
            log.info(f"Blocking communication from {packet.src} to {packet.dst}")

    def allow_traffic(self, event, in_port):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed, in_port)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info(f"Switch {event.connection.dpid} has connected")
        MitmProtection(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
