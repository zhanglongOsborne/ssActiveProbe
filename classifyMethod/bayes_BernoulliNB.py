#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyleft Osborne_ZL
2017-10-20
'''


from sklearn.feature_extraction import DictVectorizer
from sklearn import preprocessing
from sklearn import tree
from sklearn.naive_bayes import BernoulliNB
import numpy as np
from sklearn.externals.six import StringIO

stander = preprocessing.StandardScaler()
lb = preprocessing.LabelBinarizer()
def iter_generate_train_tuple(train_file_path,batch_size=10000):
    train_set = []
    train_ret_set = []
    file = open(train_file_path)
    line_number = 0
    while 1:
        line = file.readline()
        if not line :
            yield train_set, train_ret_set
            break
        line_number += 1
        li = line.split('\t')[4:]
        li = np.array(li,dtype=float)
        train_set.append(li[:-1])
        train_ret_set.append(li[-1])

        if line_number >= batch_size:
            yield train_set,train_ret_set
            line_number = 0
            train_set = []
            train_ret_set = []
    file.close()


def predict(train_file_path,test_file_path,out_file):
    train_iterators = iter_generate_train_tuple(train_file_path)
    clf = BernoulliNB()
    for i,(x_train,y_train) in enumerate(train_iterators):
        try:
            if len(x_train)==0 or len(y_train)==0:
                continue
            else:
                clf.partial_fit(x_train,y_train,classes=np.array([0., 1.]))
        except:
            print x_train
            print y_train
    test_file = open(test_file_path)
    outfile = open(out_file,'a')

    while 1:
        line = test_file.readline()
        if not line:
            break
        li = line.split('\t')[4:]
        test_para = []
        test_para.append(li)
        test_para = np.array(test_para,dtype=float)
        predicted = clf.predict(test_para)
        outfile.write(line.strip()+'\t'+str(predicted[0])+'\n')
    outfile.close()

if __name__ == "__main__":
    train_file = "C:\\Users\\macworld\\Desktop\\ss_attack\\train_set"
    test_file = "C:\\Users\\macworld\\Desktop\\ss_attack\\predict_set"
    out_file = "C:\\Users\\macworld\\Desktop\\ss_attack\\predict_result_3"
    predict(train_file,test_file,out_file)




