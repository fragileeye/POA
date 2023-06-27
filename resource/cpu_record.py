import psutil
import time
import sys

class CPU_Mon:
    def __init__(self, params):
        self.params = params
        self.is_stop = False
    
    def run(self):
        try:
            path = self.params.get('path', 'cpu.txt')
            ival = self.params.get('ival', 3)
            with open(path, 'w+') as fp:
                while not self.is_stop:
                    cpu = psutil.cpu_percent(interval=ival)
                    fp.write('{0}: {1}\n'.format(time.time(), cpu))
                    print(cpu)
        except:
            self.is_stop = True
    

def main(params):
    mon = CPU_Mon(params)
    mon.run()


if __name__ == '__main__':
    params = {}
    for i, opt in enumerate(sys.argv):
        if opt == '-f':
            params['path'] = sys.argv[i+1]
        if opt == '-i':
            params['ival'] = int(sys.argv[i+1])
    main(params)    



        

