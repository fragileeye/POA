from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel
from functools import partial
import sys

class MyTopo(Topo):
    def __init__(self, sw_num):
        super(MyTopo, self).__init__(self)
        self.init_topo(sw_num)
    
    def init_topo(self, sw_num):
        switches = []
        h1 = self.addHost('h1', ip='192.168.1.1')
        h2 = self.addHost('h2', ip='192.168.1.2')
        for i in range(sw_num):
            sw_name = 's%d' %i
            switch = self.addSwitch(sw_name)
            if i == 0:
                self.addLink(h1, switch)
            elif i == sw_num - 1:
                self.addLink(switches[-1], switch)
                self.addLink(h2, switch)
            else:
                self.addLink(switches[-1], switch)
            switches.append(switch)
    
def main(sw_num):
    setLogLevel('info')
    topo = MyTopo(sw_num)
    # OVSSwitch13 = partial(OVSSwitch, protocols='OpenFlow13')
    controller = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, controller=controller)
    net.start()
    CLI(net)
    net.stop()
	
if __name__ == '__main__':
    for i, opt in enumerate(sys.argv):
        if opt == '-n':
            sw_num = int(sys.argv[i+1])
    main(sw_num)
