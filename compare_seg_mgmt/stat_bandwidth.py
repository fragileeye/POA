from scapy.all import *
import sys

def stat_bw(rpath, wpath, stat_time, stat_ival):
    stat_list = list()
    reader = PcapReader(rpath)
    stat_start = False
    stat_num = 0
    for pkt in reader:
        if not stat_start:
            first_time = start_time = pkt.time
            stat_start = True
            continue
        cur_time = pkt.time
        if cur_time - first_time > stat_time:
            break
        elif cur_time - start_time > stat_ival:
            stat_list.append(stat_num)
            stat_num = 0
            start_time = cur_time
        else:
            stat_num += 1
    with open(wpath, 'w+') as fp:
        for bw in stat_list:
            fp.write('{0}\n'.format(bw))
    print(stat_list)

def main():
    for idx, opt in enumerate(sys.argv):
        if opt == '-r':
            rpath = sys.argv[idx+1]
        elif opt == '-w':
            wpath = sys.argv[idx+1]
        elif opt == '-l':
            stat_time = float(sys.argv[idx+1])
        elif opt == '-i':
            stat_ival = float(sys.argv[idx+1])    
    stat_bw(rpath, wpath, stat_time, stat_ival)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('Error: ', e)
    except KeyboardInterrupt:
        print('Test interrupt...')

