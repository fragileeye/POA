import random 
import sys
'''
-f generated filename
-n number of flow
-p TCP or UDP, protocol
-k how many kbytes
'''
def main(fname, num, proto, kbytes):
    rand_hosts = ['192.168.10.2', '192.168.20.3', '192.168.20.4',
        '192.168.30.5', '192.168.30.6', '192.168.40.7', '192.168.40.8']
    with open(fname, 'w+') as fp:
        for i in range(num):
            port = 9510 + i
            host = random.choice(rand_hosts)
            command = '-a {0} -T {1} -rp {2} -k {3}'.format(host, proto, port, kbytes)
            fp.write(command + '\n')

if __name__ == '__main__':
    print('Usage: python gen_script.py -f filename -n flownum')
    for i, opt in enumerate(sys.argv):
        if opt == '-f':
            fname = sys.argv[i+1]
        elif opt == '-n':
            flownum = int(sys.argv[i+1])
        elif opt == '-p':
            proto = sys.argv[i+1]
        elif opt == '-k':
            kbytes = int(sys.argv[i+1])
    main(fname, flownum, proto, kbytes)