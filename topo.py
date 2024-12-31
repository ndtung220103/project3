
from mininet.topo import Topo
from mininet.node import OVSSwitch


from utils import IP, MAC, NETMASK


class MyTopo(Topo):


    def build(self):

        switch = self.addSwitch('s1', cls=OVSSwitch)

        plc1 = self.addHost(
            'plc1',
            ip=IP['plc1'] + NETMASK,
            mac=MAC['plc1'])
        self.addLink(plc1, switch)

        hmi = self.addHost(
            'hmi',
            ip=IP['hmi'] + NETMASK,
            mac=MAC['hmi'])
        self.addLink(hmi, switch)

        attacker = self.addHost(
            'attacker',
            ip=IP['attacker'] + NETMASK,
            mac=MAC['attacker'])
        self.addLink(attacker, switch)
