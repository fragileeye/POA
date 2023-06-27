from scapy.all import *
import time
import random
import sys

class GenTraffic(object):
    def __init__(self, iface, valid_hosts, max_flows=25, idle_time=3, pkts_ival=0.1, pkts_size=38):
        super(GenTraffic, self).__init__()
        self.iface = iface
        self.valid_hosts = valid_hosts
        # max flow entries during attacks 
        self.max_flows = max_flows
        self.idle_time = idle_time
        self.pkts_ival = pkts_ival
        self.pkts_size = pkts_size
    
    def gen_pkts(self):
        fab_pkts = []
        for i in range(self.max_flows):
            dst = random.choice(self.valid_hosts)
            sport = i + 54321
            dport = i + 12345
            if self.pkts_size > 0:
                payload = b'\x00' * self.pkts_size
            else:
                payload = b'\x00' * random.randint(100, 1000)
            pkt = Ether()/IP(dst=dst)/TCP(sport=sport, dport=dport, flags="A")/payload
            fab_pkts.append(pkt)
        return fab_pkts

    def start(self, duration=300):
        fab_pkts = self.gen_pkts()
        is_random = True if not self.pkts_ival else False
        print('starting...')
        while duration > 0:
            start_time = time.time()
            sendp(fab_pkts, iface=self.iface, verbose=False)
            send_time = time.time() - start_time
            if is_random:
                rand = random.random()
                time.sleep(rand)
                duration = duration - send_time - rand 
            elif self.pkts_ival > 0.01:
                if send_time < self.pkts_ival:
                    time.sleep(self.pkts_ival-send_time)
                    duration -= self.pkts_ival
                else:
                    duration -= send_time
            else:
                duration -= send_time

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
            elif param == '-t':
                duration = int(sys.argv[idx+1])
            elif param == '-s':
                pkts_size = int(sys.argv[idx+1])
            else:
                pass 
        generator = GenTraffic(iface, hosts, max_flows=max_flows, pkts_ival=pkts_ival, pkts_size=pkts_size)
        generator.start(duration=duration)
    except KeyboardInterrupt:
        print('test done...')
