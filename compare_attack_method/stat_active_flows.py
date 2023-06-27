import re
import os
import sys

def read_from_file(fpath):
    with open(fpath, 'r') as fp:
        data = fp.read()
        pattern_time = re.compile(r'Total time\s+=\s+([\.\d]+)')
        pattern_pkts = re.compile(r'Total packets\s+=\s+(\d+)')
        list_time = re.findall(pattern_time, data)
        list_pkts = re.findall(pattern_pkts, data)
        # print(list_time, list_pkts)
        active_flows = 0
        for time, pkts in zip(list_time, list_pkts):
            if float(time) < 10 and int(pkts) == 2000:
                active_flows += 1
        fname = os.path.basename(fpath)
        print('fname: {0}, active_flows: {1}'.format(fname, active_flows))
        return active_flows

def read_from_dir(dpath):
    res_dict = dict()
    for fname in os.listdir(dpath):
        stem, _ = os.path.splitext(fname)
        if stem.isdigit():
            fpath = os.path.join(dpath, fname)
            res_dict[fname] = read_from_file(fpath)
    return res_dict

if __name__ == '__main__':
    for i, opt in enumerate(sys.argv):
        if opt == '-f':
            fname = sys.argv[i+1]
            flow_num = read_from_file(fname)
        elif opt == '-d':
            dname = sys.argv[i+1]
            flow_dict = read_from_dir(dname)

