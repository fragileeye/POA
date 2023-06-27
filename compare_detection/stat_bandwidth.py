from scapy.all import *
import sys

def stat_bw(rpath, wpath, stat_time, stat_ival):
    stat_list = [0] * int(stat_time // stat_ival) 
    reader = PcapReader(rpath)
    stat_start = True  
    first_time = 0
    for pkt in reader:
        curr_time = pkt.time
        if stat_start:
            stat_start = False 
            first_time = curr_time 
            stat_list[0] += 1
        elif curr_time - first_time > stat_time:
            break 
        else:
            delta_time = pkt.time - first_time    
            idx = int(delta_time / stat_ival)
            stat_list[idx] += 1
        
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
    main()
    try:
        pass 
    except Exception as e:
        print('Error: ', e)
    except KeyboardInterrupt:
        print('Test interrupt...')

