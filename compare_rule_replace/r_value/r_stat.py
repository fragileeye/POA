import os
import re
import numpy as np

# stat the cpu utiliztion in 180s
def main(stat_dir):
    pattern = 'evict times:\s+(\d+), mal rules:\s+(\d+)'    
    for file in os.listdir(stat_dir):
        stat_file = os.path.join(stat_dir, file)
        with open(stat_file, 'r+') as fp:
            data = fp.read()
        results = re.findall(pattern, data)
        # hold the result after evicting 500 times
        results = results[len(results)//2:]
        stat_result = [int(v2)/int(v1) for v1, v2 in results]
        print('file: {}, result: {}\n'.format(file, stat_result))
        # med_value = np.median(stat_result)
        # max_value = np.max(stat_result)
        # min_value = np.min(stat_result)
        # print('[{0}] mean: {1} up_div: {2} bot_div: {3}'.format(
        #     file, med_value, max_value - med_value, med_value - min_value 
        # ))
            
if __name__ == '__main__':
    main('txt')                           