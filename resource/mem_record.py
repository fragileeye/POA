import psutil
import time
import sys

class Mem_Mon():
    def __init__(self, params):
        self.params = params 
        self.is_stop = False 
        self.proc = self._find_proc_obj()
        
    def _find_proc_obj(self, proc_name='ryu-manager'):
        processes = psutil.process_iter()
        for process in processes:
            if process.name() == proc_name:
                return process
        return None 
    
    def run(self):
        try:
            path = self.params.get('path', 'cpu.txt')
            ival = self.params.get('ival', 3)
            with open(path, 'w+') as fp:
                while not self.is_stop:
                    mem_percent = self.proc.memory_percent()
                    fp.write('{}: {}\n'.format(time.time(), mem_percent))
                    print(mem_percent)
                    time.sleep(ival)
        except Exception as e:
            print(e)
            self.is_stop = True 
        
def main(params):
    mem_mon = Mem_Mon(params)
    mem_mon.run()

if __name__ == '__main__':
    params = {}
    for i, opt in enumerate(sys.argv):
        if opt == '-f':
            params['path'] = sys.argv[i+1]
        if opt == '-i':
            params['ival'] = int(sys.argv[i+1])      
    main(params)    



        

