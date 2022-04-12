import numpy as np
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.model_selection import StratifiedKFold 
from sklearn.metrics import roc_auc_score as AUC
from sklearn.tree import DecisionTreeClassifier

class DefenderUtil:
    def __init__(self, delta_t=0.7):
        self.delta_t = delta_t

    def process_data(self, records):
        data = [] # just for reading 
        index = dict()
        for i, (k, v) in enumerate(records.items()):
            stats = v['stats']
            vec = [k, np.min(stats['pkts']), 
                np.mean(stats['size']), np.var(stats['size']), 
                np.mean(stats['ival']), np.var(stats['ival'])]
            data.append(vec)	
            index[k] = i
            # self._save(data)
        dataset = {'idx': index, 'data': data}
        return dataset

    # calculate the simlarity contribution rate of each node 
    # in the same feature graph
    def calc_sim_cr(self, dataset):
        data = dataset['data']
        data = StandardScaler().fit_transform(data)
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

    def check_drift(self, old_ds, new_ds):
        clf = DecisionTreeClassifier(random_state=0)
        old_data = old_ds['data']
        old_label = [1] * len(old_data)
        new_data = new_ds['data']
        new_label = [0] * len(new_data)
        data = np.concatenate((old_data, new_data), axis=0)
        label = np.concatenate((old_label, new_label), axis=0)
        preds = np.zeros(label.shape)
        skf = StratifiedKFold(n_splits=2, shuffle=True)
        for train_idx, test_idx in skf.split(data, label):
            X_train, X_test = data[train_idx], data[test_idx]
            y_train, y_test = label[train_idx], label[test_idx]
            clf.fit(X_train, y_train)
            probs = clf.predict_proba(X_test)[:, 1]
            preds[test_idx] = probs
        auc_score = AUC(label, preds)
        print('auc_score: {0}'.format(auc_score))
        if auc_score > self.delta_t:
            print('drift happends')
            return True
        else:
            print('no drift')
            return False

    def _output(self):
        for item in self.dataset:
            print(str(item).strip('[]'))

    def _save(self, dataset, file='traffic_feature.txt'):
        with open(file, 'w+') as fp:
            for item in dataset:
                data = str(item).strip('[]') 
                fp.write(data + '\r\n')
