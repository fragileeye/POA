import numpy as np
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.cluster import SpectralClustering

class DataHandler:
    def __init__(self, delta_g=0.8, delta_e=0.5):
        self.delta_g = delta_g  
        self.delta_e = delta_e

    def process_data(self, records):
        orign_dataset = [] # just for reading 
        std_data = []
        std_index = dict()
        for i, (k, v) in enumerate(records.items()):
            stats = v['stats']
            vec = [k, np.min(stats['pkts']), 
                np.mean(stats['size']), np.var(stats['size']), 
                np.mean(stats['ival']), np.var(stats['ival'])]
            orign_dataset.append(vec)	
            std_data.append(vec)
            std_index[k] = i 
        # self._save(orign_dataset)

        std_data = np.array(std_data)
        scaler = StandardScaler()
        std_data = scaler.fit_transform(std_data)
        return {'idx': std_index, 'data': std_data}

    # calculate the simlarity contribution rate of each node 
    # in the same feature graph
    def calc_sim_cr(self, dataset):
        data = dataset['data']
        simi_value = []
        rows, lines = data.shape
        for i in range(rows):
            vec = data[i]
            mat = np.tile(vec, rows).reshape(rows, lines)
            # here we can add weight
            dist = np.linalg.norm(mat-data, ord=2, axis=1)
            simi_value.append(sum(np.e**(-dist/2)) - 1) #gamma  = 1
        simi_sum = sum(simi_value)
        simi_cr = [v/simi_sum for v in simi_value]
        return simi_cr

    # calculate simlarity of sub graph beween the feature graphs
    def calc_sim_graph(self, sub_g1, sub_g2):
        graph_simi = 0
        graph_map = dict()
        for k1 in sub_g1:
            items = sub_g1[k1]
            max_simi = 0
            for k2 in sub_g2:
                simi_value = 0
                for vec in items:
                    rows = len(sub_g2[k2])
                    mat1 = np.tile(vec, rows)
                    mat2 = sub_g2[k2]
                    dist = np.linalg.norm(mat1-mat2, ord=2, axis=1)
                    simi_value += sum(np.e**(-dist/2))
                edges = len(sub_g1[k1]) * len(sub_g2[k2])
                simi_value = simi_value / edges
                if simi_value > max_simi:
                    max_simi = simi_value
                    graph_map[k1] = k2
            graph_simi += max_simi
        return graph_map, graph_simi

    def calc_entropy(self, sub_graphs):
        nodes = sum([len(v) for _, v in sub_graphs.items()])
        entropy = 0
        for _, v in sub_graphs.items():
            p = len(v) / nodes
            entropy += p*np.log2(1/p)
        return entropy

    def do_cluster(self, dataset, k):
        data = dataset['data']
        cluster = SpectralClustering( \
            n_clusters=k, random_state=0).fit(data)
        labels = cluster.labels_
        sub_graphs = dict()
        for i in range(k):
            class_i = (labels == i)
            sub_graphs[i] = [data[idx] for idx in class_i]
        return sub_graphs

    def detect_graph_simi(self, sub_g1, sub_g2):
        g_map, g_simi = self.calc_sim_graph(sub_g1, sub_g2)
        print('graph map: ', g_map)
        print('graph simi: ', g_simi)
        if g_simi < self.delta_g:
            print('[Warning]: Dismilarity beyond threshold!')
            return True
        return False

    def detect_entropy(self, sub_g1, sub_g2):
        g1_ent = self.calc_entropy(sub_g1)
        g2_ent = self.calc_entropy(sub_g2)
        if g2_ent / g1_ent < self.delta_e:
            print('[Warning]: Entropy beyond threshold!')
            return True
        return False

    def _output(self):
        for item in self.dataset:
            print(str(item).strip('[]'))

    def _save(self, dataset, file='traffic_feature.txt'):
        with open(file, 'w+') as fp:
            for item in dataset:
                data = str(item).strip('[]') 
                fp.write(data + '\r\n')
