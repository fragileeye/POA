import re
import sys

def main():
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            in_file = sys.argv[i+1]
        elif opt == '-w':
            out_file = sys.argv[i+1]
    pattern = re.compile(r'evict times:\s+(\d+),\s+mal rules:\s+(\d+)')
    with open(in_file, 'r+') as fp:
        lines = fp.readlines()
    with open(out_file, 'w+') as fp:
        for line in lines:
            res = re.search(pattern, line)
            if res is not None:
                times, mal_entries = res.groups(0)            
                if int(times) >= 500: 
                    fp.write(mal_entries + '\n')

if __name__ == '__main__':
    main()
            