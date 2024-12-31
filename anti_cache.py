from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# Danh sách ánh xạ IP-to-MAC hợp lệ
VALID_IP_TO_MAC = {
    "192.168.1.10": "00:1D:9C:C7:B0:10",  # plc1
    "192.168.1.20": "00:1D:9C:C8:BC:20",  # hmi
}

class AntiARPCachePoisoning (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info(f"Protecting switch: {connection.dpid}")

    def _handle_PacketIn(self, event):
        """
        Xử lý gói tin khi không có flow phù hợp trên switch.
        """
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Phân tích gói ARP
        arp = packet.find("arp")
        if arp:
            self._handle_arp(event, arp)

    def _handle_arp(self, event, arp):
        """
        Phát hiện và xử lý các gói ARP Poisoning.
        """
        log.info(f"Received ARP packet: {arp.hwsrc} -> {arp.protosrc}")

        # Kiểm tra ánh xạ IP-to-MAC
        valid_mac = VALID_IP_TO_MAC.get(str(arp.protosrc))
        if valid_mac and valid_mac != str(arp.hwsrc):
            # Phát hiện tấn công ARP Poisoning
            log.warning(f"ARP Poisoning detected: {arp.hwsrc} is spoofing {arp.protosrc}")
            
            # Thêm flow để chặn gói tin này
            self.block_attacker(event, arp)
        else:
            log.info("Valid ARP packet received")

    def block_attacker(self, event, arp):
        """
        Cài đặt flow rule để chặn gói tin từ attacker.
        """
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed, event.port)
        msg.idle_timeout = 10  # Flow timeout
        msg.hard_timeout = 30  # Flow timeout lâu hơn
        msg.actions = []  # Drop packet
        self.connection.send(msg)
        log.info(f"Blocked packets from {arp.hwsrc}")

def launch():
    """
    Khởi chạy POX controller.
    """
    def start_switch(event):
        log.info(f"Switch {event.connection.dpid} has connected")
        AntiARPCachePoisoning(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("Anti ARP Cache Poisoning Controller is running")
