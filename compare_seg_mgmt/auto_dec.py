import os
import sys
import time

if __name__ == '__main__':
    for fname in os.listdir('.'):
        if fname.endswith('bin'):
            name = os.path.splitext(fname)[0]
            os.system('''../ITGDec {0} >{1}.txt'''.format(fname, name))
    print('auto dec done...')