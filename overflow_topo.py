from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel
from functools import partial

class MyTopo(Topo):
	def __init__(self):
		super(MyTopo, self).__init__(self)
		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')
		s3 = self.addSwitch('s3')
		s4 = self.addSwitch('s4')
		s5 = self.addSwitch('s5')

		h1 = self.addHost('h1', ip='192.168.10.1', mac='00:00:00:00:00:01')
		h2 = self.addHost('h2', ip='192.168.10.2', mac='00:00:00:00:00:02')
		h3 = self.addHost('h3', ip='192.168.20.3', mac='00:00:00:00:00:03')
		h4 = self.addHost('h4', ip='192.168.20.4', mac='00:00:00:00:00:04')
		h5 = self.addHost('h5', ip='192.168.30.5', mac='00:00:00:00:00:05')
		h6 = self.addHost('h6', ip='192.168.30.6', mac='00:00:00:00:00:06')
		h7 = self.addHost('h7', ip='192.168.40.7', mac='00:00:00:00:00:07')
		h8 = self.addHost('h8', ip='192.168.40.8', mac='00:00:00:00:00:08')

		self.addLink(h1, s2)
		self.addLink(h2, s2)
		self.addLink(h3, s3)
		self.addLink(h4, s3)
		self.addLink(h5, s4)
		self.addLink(h6, s4)
		self.addLink(h7, s5)
		self.addLink(h8, s5)

		self.addLink(s2, s1)
		self.addLink(s3, s1)
		self.addLink(s4, s1)
		self.addLink(s5, s1)
		
def main():
	setLogLevel('info')
	topo = MyTopo()
	# OVSSwitch13 = partial(OVSSwitch, protocols='OpenFlow13')
	controller = RemoteController('c0', ip='127.0.0.1', port=6653)
	net = Mininet(topo=topo, controller=controller)
	net.start()
	CLI(net)
	net.stop()
	
if __name__ == '__main__':
	main()
