from scapy.all import *

# Hàm xử lý gói tin
def process_packet(packet):
    # Xóa checksum để Scapy tự tính toán lại
    if IP in packet:
        del packet[IP].chksum
    if TCP in packet:
        del packet[TCP].chksum
    # Gửi lại gói tin
    sendp(packet, iface="attacker-eth0", verbose=False)

# Chặn gói tin và forward
sniff(filter="ip", prn=process_packet, iface="attacker-eth0", store=0)
