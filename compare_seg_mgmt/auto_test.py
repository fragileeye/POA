import os
import sys
import time

if __name__ == '__main__':
    for i, opt in enumerate(sys.argv):
        if opt == '-n':
            test_num = int(sys.argv[i+1])
        elif opt == '-f':
            test_file = sys.argv[i+1]
        else:
            pass
    for i in range(test_num):
        print('round {0}...'.format(i))
        os.system('''../ITGSend {0} -l {1}.bin'''.format(test_file, i))
        time.sleep(3)
    print('auto test done...')