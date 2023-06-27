import os
import numpy as np

# stat the cpu utiliztion in 180s
def main(stat_dir):
    for file in os.listdir(stat_dir):
        stat_file = os.path.join(stat_dir, file)
        first_line = True
        stat_result = []
        start_time = 0
        end_time = 0
        with open(stat_file, 'r+') as fp:
            while True:
                line = fp.readline()
                if not line:
                    end_time = time
                    break
                v1, v2 = line.split(':')
                time = float(v1)
                cpu_value = float(v2)
                if first_line:
                    start_time = time
                    first_line = False
                elif time - start_time < 180:
                    stat_result.append(cpu_value)  
            print('[{0}] mean: {1}, median: {2}'.format(file, \
                np.mean(stat_result), np.median(stat_result)))

if __name__ == '__main__':
    main('txt/cpu')
                                   
                
                
            