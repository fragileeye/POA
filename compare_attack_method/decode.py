import os

def main(dpath):
    for fname in os.listdir(dpath):
        if fname.endswith('.bin'):
            base = fname.split('.')[0]
            os.system('../ITGDec {0} >{1}.txt'.format(fname, base))

if __name__ == '__main__':
    main('.')