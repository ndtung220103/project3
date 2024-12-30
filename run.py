
from mininet.net import Mininet
from mininet.cli import CLI
from minicps.mcps import MiniCPS

from topo import MyTopo

import sys


class MyCPS(MiniCPS):

    def __init__(self, name, net):

        self.name = name
        self.net = net

        net.start()

        for h in net.hosts:
            h.cmd('ifconfig %s-eth0 inet6 add 2001:db8::%s/64' % (h.name, str(hash(h.name))))


        # Kiểm tra cấu hình IPv6
        for h in net.hosts:
            print(h.name, h.cmd('ifconfig'))

        net.pingAll()

        # start devices
        plc1, hmi, attacker, s1 = self.net.get(
            'plc1', 'hmi', 'attacker', 's1')

        # SPHINX_SWAT_TUTORIAL RUN(
        s1.cmd(sys.executable + ' -u ' + ' physical_process.py  &> logs/process.log &')
        plc1.cmd(sys.executable + ' -u ' + ' plc1.py  &> logs/plc1.log &')
        #hmi.cmd(sys.executable + ' -u ' + ' hmi.py  &> logs/hmi.log &')
        # SPHINX_SWAT_TUTORIAL RUN)
        CLI(self.net)

        net.stop()

if __name__ == "__main__":

    topo = MyTopo()
    net = Mininet(topo=topo)

    swat_s1_cps = MyCPS(
        name='project3',
        net=net)
