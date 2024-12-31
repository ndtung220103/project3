
from mininet.net import Mininet
from mininet.cli import CLI
from minicps.mcps import MiniCPS
from mininet.node import RemoteController, OVSSwitch


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

        #net.pingAll()

        # start devices
        plc1, hmi, attacker, s1 = self.net.get(
            'plc1', 'hmi', 'attacker', 's1')

        plc1.setARP(ip='192.168.1.20', mac='00:1D:9C:C8:BC:20')
        plc1.setARP(ip='192.168.1.77', mac='AA:AA:AA:AA:AA:AA')
        hmi.setARP(ip='192.168.1.10', mac='00:1D:9C:C7:B0:10')
        hmi.setARP(ip='192.168.1.77', mac='AA:AA:AA:AA:AA:AA')
        attacker.setARP(ip='192.168.1.20', mac='00:1D:9C:C8:BC:20')
        attacker.setARP(ip='192.168.1.10', mac='00:1D:9C:C7:B0:10')

        # SPHINX_SWAT_TUTORIAL RUN(
        s1.cmd(sys.executable + ' -u ' + ' physical_process.py  &> logs/process.log &')
        plc1.cmd(sys.executable + ' -u ' + ' plc1.py  &> logs/plc1.log &')
        #hmi.cmd(sys.executable + ' -u ' + ' hmi.py  &> logs/hmi.log &')
        # SPHINX_SWAT_TUTORIAL RUN)
        CLI(self.net)

        net.stop()

if __name__ == "__main__":

    topo = MyTopo()
    controller = RemoteController('pox', ip='127.0.0.1', port=6633)  # POX chạy ở cổng 6633

    net = Mininet(topo=topo, controller=controller)

    swat_s1_cps = MyCPS(
        name='project3',
        net=net)
