#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Aug 29 12:14:12 2019

@author: hananhindy
"""
import pandas as pd
import numpy as np
import os
import argparse

from sklearn.preprocessing import OneHotEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC, LinearSVC
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report

# Helper Function
def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

#protocols = ['ARP', 'CDP', 'CLDAP', 'DATA', 'DNS', 'DTLS', 'DTP', 'ECHO', 'ICMP', 'ISAKMP','MDNS', 'NAT-PMP', 'NBNS', 'NFS', 'NTP', 'PORTMAP', 'RADIUS', 'RIP', 'SRVLOC', 'SNMP',  'SSH', 'STP', 'TCP', 'UDP', 'XDMCP', 'MQTT', 'MPEG_PMT', 'MP2T', 'MPEG_PAT', 'DVB_SDT']
#label_encoder = LabelEncoder().fit(protocols)

one_hot_encoder = None

def load_file(path, mode, is_attack = 1, label = 1, folder_name='Bi/', sliceno = 0, verbose = True):
    #global label_encoder
    global one_hot_encoder
    
    #attacker_ips = ['192.168.2.5']
    
    columns_to_drop_packet = ['timestamp', 'src_ip', 'dst_ip', 'ip_flags', 'tcp_flags', 'mqtt_flags']
    columns_to_drop_uni = ['proto', 'ip_src', 'ip_dst']
    columns_to_drop_bi = ['proto', 'ip_src', 'ip_dst']
    
    if os.path.getsize(path)//10 ** 9 > 0:
        x = np.zeros((0,0))
        for chunk in pd.read_csv(path, chunksize=10 ** 6):
            chunk.drop(columns = columns_to_drop_packet, inplace = True)
            chunk = chunk[chunk.columns.drop(list(chunk.filter(regex='mqtt')))]
                                     
            chunk = chunk.fillna(-1)
        
            with open(folder_name + 'instances_count.csv','a') as f:
                f.write('{}, {} \n'.format(path, chunk.shape[0]))
                
            x_temp = chunk.loc[chunk['is_attack'] == is_attack]   
            x_temp.drop('is_attack', axis = 1, inplace = True)
            #x_temp['protocol'] = label_encoder.transform(x_temp['protocol'])
            if one_hot_encoder == None:
                one_hot_encoder = OneHotEncoder(categorical_features=[0], n_values=30)
                x_temp = one_hot_encoder.fit_transform(x_temp).toarray()
            else:
                x_temp = one_hot_encoder.transform(x_temp).toarray()
            
            x_temp = np.unique(x_temp, axis = 0)
            
            if x.size == 0:
                x = x_temp
            else:
                x = np.concatenate((x, x_temp), axis = 0)
                x = np.unique(x, axis = 0)
    else:
        dataset = pd.read_csv(path)
    
        if mode == 1 or mode == 2:
            dataset = dataset.loc[dataset['is_attack'] == is_attack]
#            if is_attack == 0:
#                dataset = dataset.loc[operator.and_(dataset['ip_src'].isin(attacker_ips) == False, dataset['ip_dst'].isin(attacker_ips) == False)]
#            else:
#                dataset = dataset.loc[operator.or_(dataset['ip_src'].isin(attacker_ips), dataset['ip_dst'].isin(attacker_ips))]
#            
        if mode == 0:
            dataset.drop(columns=[columns_to_drop_packet], inplace = True)
            dataset = dataset[dataset.columns.drop(list(dataset.filter(regex='mqtt')))]
        elif mode == 1:
            dataset.drop(columns = columns_to_drop_uni, inplace = True)
        elif mode == 2:
            dataset.drop(columns = columns_to_drop_bi, inplace = True)
        
        if verbose:                 
            print(dataset.columns)
        
        dataset = dataset.fillna(-1)
               
        if mode == 0:
            x = dataset.loc[dataset['is_attack'] == is_attack]   
            x.drop('is_attack', axis=1, inplace=True)
            #x['protocol'] = label_encoder.transform(x['protocol'])
            if one_hot_encoder == None:
                one_hot_encoder = OneHotEncoder(categorical_features=[0], n_values=30)
                x = one_hot_encoder.fit_transform(x).toarray()
            else:
                x = one_hot_encoder.transform(x).toarray()
        else:
            x = dataset.values
    
    with open(folder_name + 'instances_count.csv','a') as f:
        f.write('all, {}, {} \n'.format(path, x.shape[0]))
    
    x = np.unique(x, axis = 0)

    with open(folder_name + 'instances_count.csv','a') as f:
        f.write('unique, {}, {} \n'.format(path, x.shape[0]))
    
    if (mode == 1 and x.shape[0] > 100000) or (mode == 2 and x.shape[0] > 50000):
            temp = x.shape[0] // 10
            start = sliceno * temp
            end = start + temp - 1 
            x = x[start:end,:] 
            with open(folder_name + 'instances_count.csv','a') as f:
                f.write('Start, {}, End, {} \n'.format(start, end))
    elif mode == 0:
        if x.shape[0] > 15000000:
            temp = x.shape[0] // 400
            start = sliceno * temp
            end = start + temp - 1 
            x = x[start:end,:] 
            with open(folder_name + 'instances_count.csv','a') as f:
                f.write('Start, {}, End, {} \n'.format(start, end))
        elif x.shape[0] > 10000000:
            temp = x.shape[0] // 200
            start = sliceno * temp
            end = start + temp - 1 
            x = x[start:end,:] 
            with open(folder_name + 'instances_count.csv','a') as f:
                f.write('Start, {}, End, {} \n'.format(start, end))
        elif x.shape[0] > 100000:
            temp = x.shape[0] // 10
            start = sliceno * temp
            end = start + temp - 1 
            x = x[start:end,:] 
            with open(folder_name + 'instances_count.csv','a') as f:
                f.write('Start, {}, End, {} \n'.format(start, end))

            
    y = np.full(x.shape[0], label)
    
    with open(folder_name + 'instances_count.csv','a') as f:
        f.write('slice, {}, {} \n'.format(path, x.shape[0]))
        
    return x, y

def classify_sub(classifier, x_train, y_train, x_test, y_test, cm_file_name, summary_file_name, classifier_name, verbose = True):
    classifier.fit(x_train, y_train)
    pred = classifier.predict(x_test)
    
    cm = pd.crosstab(y_test, pred)
    cm.to_csv(cm_file_name)    
    
    pd.DataFrame(classification_report(y_test, pred, output_dict = True)).transpose().to_csv(summary_file_name)
    
    if verbose:
        print(classifier_name + ' Done.\n')
    
    del classifier
    del pred
    del cm
    
def classify(random_state, x_train, y_train, x_test, y_test, folder_name, prefix = "", verbose = True):
    confusion_matrix_folder = os.path.join(folder_name, 'Confusion_Matrix/') 
    summary_folder =  os.path.join(folder_name, 'Summary/') 

    if os.path.isdir(confusion_matrix_folder) == False:
            os.mkdir(confusion_matrix_folder)
    if os.path.isdir(summary_folder) == False:
            os.mkdir(summary_folder)
            
    # 1- Linear
    linear_classifier = LogisticRegression(random_state = random_state)
    classify_sub(linear_classifier, 
                 x_train, y_train, 
                 x_test, y_test, 
                 confusion_matrix_folder + prefix + '_cm_linear.csv', 
                 summary_folder + prefix + '_summary_linear.csv',
                 'Linear',
                 verbose)
       
    # 2- KNN
    knn_classifier = KNeighborsClassifier()
    classify_sub(knn_classifier, 
                 x_train, y_train, 
                 x_test, y_test, 
                 confusion_matrix_folder + prefix + '_cm_knn.csv', 
                 summary_folder + prefix + '_summary_knn.csv',
                 'KNN',
                 verbose)
    
    #3- RBF SVM
    kernel_svm_classifier = SVC(kernel = 'rbf', random_state = random_state, gamma='scale')
    classify_sub(kernel_svm_classifier, 
                 x_train, y_train, 
                 x_test, y_test, 
                 confusion_matrix_folder + prefix + '_cm_kernel_svm.csv', 
                 summary_folder + prefix + '_summary_kernel_svm.csv',
                 'SVM',
                 verbose)
    
    #4- Naive Bayes
    naive_classifier = GaussianNB()
    classify_sub(naive_classifier, 
                 x_train, y_train, 
                 x_test, y_test, 
                 confusion_matrix_folder + prefix + '_cm_naive.csv', 
                 summary_folder + prefix + '_summary_naive.csv',
                 'Naive',
                 verbose)

    #5- Decision Tree
    decision_tree_classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = random_state)
    classify_sub(decision_tree_classifier, 
                 x_train, y_train, 
                 x_test, y_test, 
                 confusion_matrix_folder + prefix + '_cm_decision_tree.csv', 
                 summary_folder + prefix + '_summary_decision_tree.csv',
                 'Decision Tree',
                 verbose)
    
    #6- Random Forest
    random_forest_classifier = RandomForestClassifier(n_estimators = 10, criterion = 'entropy', random_state = random_state)
    classify_sub(random_forest_classifier, 
                 x_train, y_train, 
                 x_test, y_test, 
                 confusion_matrix_folder + prefix + '_cm_random_forest.csv', 
                 summary_folder + prefix + '_summary_random_forest.csv',
                 'Random Forest',
                 verbose)

    # 7- Linear SVM 
    svm_classifier = LinearSVC(random_state = random_state)
    classify_sub(svm_classifier, 
                 x_train, y_train, 
                 x_test, y_test, 
                 confusion_matrix_folder + prefix + '_cm_svm.csv', 
                 summary_folder + prefix + '_summary_svm.csv',
                 'SVM',
                 verbose)
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', type = int, default = 2)
    parser.add_argument('--output', default='Classification_Bi')
    parser.add_argument('--verbose', type = str2bool, default = True)

    args = parser.parse_args()
    
    for slice_number in range(10):
        prefix = ''
        if args.mode == 1:
            prefix = 'uniflow_' 
        elif args.mode == 2:
            prefix = 'biflow_'
        
        if args.verbose:
            print('Starting Slice #: {}'.format(slice_number))
            print('Start Classification')
            
        random_state = 0
        folder_name = '{}_{}/'.format(args.output, slice_number)
        
        if os.path.isdir(folder_name) == False:
            os.mkdir(folder_name)
            
        x, y = load_file(prefix + 'normal.csv', 
                         args.mode, 
                         0, 0, 
                         folder_name, 
                         slice_number,
                         args.verbose)
        
        x_temp, y_temp = load_file(prefix + 'scan_A.csv', 
                                   args.mode, 
                                   1, 1, 
                                   folder_name,
                                   slice_number,
                                   args.verbose)
        
        x = np.concatenate((x, x_temp), axis = 0)
        y = np.append(y, y_temp)
        del x_temp, y_temp
        
        x_temp, y_temp = load_file(prefix + 'scan_sU.csv', 
                                   args.mode, 
                                   1, 2, 
                                   folder_name,
                                   slice_number,
                                   args.verbose)
        
        x = np.concatenate((x, x_temp), axis = 0)
        y = np.append(y, y_temp)
        del x_temp, y_temp
                
        x_temp, y_temp = load_file(prefix + 'sparta.csv', 
                                   args.mode, 
                                   1, 3,
                                   folder_name,
                                   slice_number,
                                   args.verbose)
        
        x = np.concatenate((x, x_temp), axis = 0)
        y = np.append(y, y_temp)
        del x_temp, y_temp
                
        x_temp, y_temp = load_file(prefix + 'mqtt_bruteforce.csv', 
                                   args.mode,
                                   1, 4, 
                                   folder_name,
                                   slice_number,
                                   args.verbose)
        
        x = np.concatenate((x, x_temp), axis = 0)
        y = np.append(y, y_temp)
        del x_temp, y_temp
                
        x_train, x_test, y_train, y_test = train_test_split(x, y, 
                                                            test_size = 0.25,
                                                            random_state = 42)
        
        classify(random_state, x_train, y_train, x_test, y_test, 
                 folder_name, "slice_{}_no_cross_validation".format(slice_number), args.verbose)
       
        kfold = StratifiedKFold(n_splits = 5, shuffle = True, random_state = 0)
        
        counter = 0
        for train, test in kfold.split(x, y):
            classify(random_state, x[train], y[train], x[test], y[test], 
                     folder_name, "slice_{}_k_{}".format(slice_number, counter), args.verbose)
            counter += 1
            
        del x
        del y
        del x_train
        del x_test
        del y_train
        del y_test
