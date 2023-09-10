import os 
import re 

def main(stat_dir):
    if not os.path.exists(stat_dir):
        print('{} not exists'.format(stat_dir))
        return None 
    
    for fname in os.listdir(stat_dir):
        if fname.startswith('m'):
            result = re.search('m(\d+)', fname)
            num_switch,  = result.groups()
            num_switch = int(num_switch)
            fpath = os.path.join(stat_dir, fname)
            with open(fpath, 'r') as fp:
                lines = fp.readlines()
                last_line = lines[-1]
                mem_percent = last_line.split(':')[-1]
            print('{} {:.4f}'.format(num_switch, float(mem_percent)))
            
if __name__ == '__main__':
    main('txt/mem_s')