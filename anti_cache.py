from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# Danh sách ánh xạ IP-to-MAC hợp lệ
VALID_IP_TO_MAC = {
    "192.168.1.10": "00:1d:9c:c7:b0:10",  # plc1
    "192.168.1.20": "00:1d:9c:c8:bc:20",  # hmi
    "192.168.1.77": "aa:aa:aa:aa:aa:aa",  # attacker (ví dụ)
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
        log.info(f"valid mac: {valid_mac}")
        log.info(f"mac src: {str(arp.hwsrc)}")
        
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

        # Cài đặt flow để chặn IP giả mạo vĩnh viễn
        block_ip_flow = of.ofp_flow_mod()
        block_ip_flow.match = of.ofp_match(dl_type=0x0806, nw_src=IPAddr(arp.protosrc))
        block_ip_flow.actions = []  # Drop ARP từ attacker
        block_ip_flow.idle_timeout = 0
        block_ip_flow.hard_timeout = 0  # Flow sẽ tồn tại lâu dài
        self.connection.send(block_ip_flow)
        log.info(f"Blocked ARP requests from IP: {arp.protosrc}")

    def _handle_ConnectionUp(self, event):
        """
        Khi có kết nối đến switch, thêm flow rule.
        """
        log.info(f"Switch {event.connection.dpid} has connected")
        self.add_flow(event.dpid, 1, 2)  # Thêm flow từ cổng 1 đến cổng 2
        self.add_flow(event.dpid, 2, 1)

    def add_flow(self, dpid, in_port, out_port):
        """
        Lệnh thêm flow.
        """
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = of.ofp_match(in_port=in_port)
        flow_mod.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(flow_mod)
        log.info(f"Added flow from port {in_port} to port {out_port} on switch {dpid}")

def launch():
    """
    Khởi chạy POX controller.
    """
    def start_switch(event):
        log.info(f"Switch {event.connection.dpid} has connected")
        AntiARPCachePoisoning(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("Anti ARP Cache Poisoning Controller is running")
