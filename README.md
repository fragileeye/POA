# POA
Research on preemptive overflow attack (POA). The "preemptive" indicates that attack flows preempt the flow entries of normal application flows by exploiting the flow entry eviction mechanism. The differences between POA and high-rate overflow attack (HROA) as well as low-rate overflow attack (LROA) are described in the following table.
| Method | Overflow rate | Flow features | Attack target |
| :---:  |     :---:     |:---           | :---          |
| HROA   | High          | slow, intermittent | Overload SDN controller | 
| LROA   | Low           | slow, persistent   | Quietly consume flow entries |
| POA    | Arbitrary     | Fast, persistent   | Preempt flow entries of normal applications |

## Description of the folds:
+ compare_attack_detection: results of comparing POA and FOA.
+ compare_seg_mgmt: codes and results of table segmentation exp.
+ compare_rule_replace: codes and results of flow eviction exp, and the pcap files used to conduct the exp.
+ compare_detection: codes and results of attack detection exp.
+ resources: codes and results of resources assumption exp.
+ data_txt: organized experimental results stored in txt files.
+ figs: figures generated by draw.ipynb.

## Notice:
+ In the folders listed above, most of them contain a readme.txt file that describes the main purpose of the files. If there is no readme file, there is no need to worry, as you can tell what they are for by observing the file names.
+ The majority of experiments described in the paper require online testing, making it difficult to detail every step. If you wish to reproduce the experiments, please contact us and we will be happy to assist you.


