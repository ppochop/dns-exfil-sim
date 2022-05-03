#!/usr/bin/env python3

import os
import getopt
import sys
import time
import pandas as pd
from collections import deque
from scipy.stats import entropy
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import pickle

HELP = """
    Train and save the model:
        sniffer.py -t <path to directory with .log files> -m <model filename> [COMMON options]

    Load the model and run:
        sniffer.py [-m <saved model filename>] [-l <logfile or path to logs to evaluate>] [-b [-r <N>] [-p]] [COMMON options]

        If model is not provided, anomalies will be evaluated based on the evaluated traffic.
        -b: Evaluate in batch mode/offline, evaluating at once (in contrast to continuous operation);
            -l needs to be a directory containing logs (see code for further explanation)
            -r <number of repetitions> How many times to repeat the detection, the result will print the number of detections for each detected prim domain
            -p providing this option will generate additional data (plot)

    COMMON options:
        -c <contamination rate>: The contamination rate of the outliers in the evaluated data. Has to be float, default is 0.001.
        -d <delay>: How many minutes to wait between collecting data. Default is 5.
        -n <number of datasets> How many of these datasets to use for evaluation. Default is 10.
"""

DNS_LOGFILE = '/var/log/passivedns.log'

DEFAULT_CONT = 0.001


COLL_DELAY = 5 # How many minutes to wait between collecting data
COLLS_NUM = 10 # How many of these datasets to use for evaluation

DNS_ALPHABET = ''.join([chr(i) for i in range(ord('a'), ord('z')+1)] \
     + [chr(i) for i in range(ord('0'), ord('9')+1)] + ['-'])

with open('../wordlists/mist_sub.txt', 'r') as wlist:
    global wordlist
    wordlist = set([word.strip('\n') for word in wlist.readlines()])



def logreader(path, coll_delay):
    with open(path, 'r') as lg:
        lg.seek(0, os.SEEK_END)

        while True:
            lines = lg.readlines()
            time.sleep(coll_delay * 60)
            yield lines

def primary_name(qname):
    return '.'.join(qname.split('.')[-3:-1])

def query_concatenate(qname):
    return ''.join(qname.split('.'))

def my_entropy(qnames):
    joined = ''.join(qnames)
    count_vector = [joined.count(c) for c in DNS_ALPHABET]
    return entropy(count_vector, base=2)

def noniprate(rtypes):
    vals = rtypes.value_counts()
    a_count = vals['A'] if 'A' in vals else 0
    aaaa_count = vals['AAAA'] if 'AAAA' in vals else 0
    return 1 - (a_count + aaaa_count)/len(rtypes)

def unique_rate(qnames):
    return 0 if len(qnames) == 0 else qnames.nunique()/len(qnames)

def mean_wrap(data):
    return data.mean()

# this could cause performance trouble
def lmw_rate(qname):
    subs = sorted(qname.split('.')[:-3], key=len, reverse=True)
    for sub in subs:
        if sub in wordlist:
            return len(sub)/(len(qname)-len(primary_name(qname))) # should be only the subdomain length but it doesn't matter
    return 0

def parse(lines):
    df = pd.DataFrame([line.strip('\n').split('||') for line in lines],
        columns=['timestamp', 'clientIP', 'serverIP', 'query',
            'qlength', 'rtype', 'answer', 'alength', 'ttl', 'count'])
    return df

def preprocess(df):
    df['primary'] = df['query'].apply(primary_name)
    df['query_len'] = df['query'].apply(len)
    df['lmw_rate'] = df['query'].apply(lmw_rate)
    return df

def process(window):
    pre = window.groupby('primary')
    post = pre.agg(
        entropy=pd.NamedAgg(column='query', aggfunc=my_entropy),
        nonIP_rate=pd.NamedAgg(column='rtype', aggfunc=noniprate),
        uniq_rate=pd.NamedAgg(column='query', aggfunc=unique_rate),
        uniq_vol=pd.NamedAgg(column='query', aggfunc='nunique'),
        len_avg=pd.NamedAgg(column='query_len', aggfunc=lambda x: x.mean()),
        lmw_avg=pd.NamedAgg(column='lmw_rate', aggfunc=lambda x: x.mean())
    )
    post = post.dropna()
    return post[post['entropy'] > 0]

def evaluate(data, model, trained):
    if not data.empty:
        if not trained:
            model.fit(data)
        data['score'] = model.predict(data)
        #data['real_score'] = data.apply(lambda row: -1 if row.name.endswith('.xy') or row.name.endswith('.xyz') else 1, axis=1)
        return data

def log_extract(path):
    lines = []
    with open(path, 'r') as logfile:
        lines = logfile.readlines()
    dataset = parse(lines)
    return preprocess(dataset)

def log_extract_batch(path, colls_num):
    dir = os.fsencode(path)
    datasets = []
    log_count = colls_num # we want the training window to be the same
    for file in os.listdir(dir):
        name = os.fsdecode(file)
        if name.endswith('.log'):
            log_count -= 1
            datasets.append(log_extract(os.fsdecode(os.path.join(path, name))))
            if log_count == 0:
                break
    return datasets

def train(path, clf, colls_num):
    """
    The path should contain PassiveDNS logs of a specific format (see the Ansible playbook).
    Logs should capture traffic of the same timespan as COLL_DELAY.
    There should be at least COLLS_NUM of such logs.
    """
    datasets = log_extract_batch(path, colls_num)
    data = pd.concat(datasets)
    proc = process(data)
    return clf.fit(proc)

def save_model(model, name):
    with open(name, 'wb') as f:
        pickle.dump(model, f)

def load_model(name):
    with open(name, 'rb') as f:
        return pickle.load(f)

def monitor(model, path, trained, colls_num, coll_delay):
    """
    Continuous mode of operation, monitor the log by tailing it in a live environment.
    """
    queue = deque(maxlen=colls_num)
    for lines in logreader(path, coll_delay):
        if not lines:
            if queue:
                queue.popleft()
            continue
        dataset = parse(lines)
        queue.append(preprocess(dataset))
        window = pd.concat(queue)
        processed = process(window)
        result = evaluate(processed, model, trained)
        print(result[result['score'] < 0].sort_values(by=['score']))

def check(model, path, trained, colls_num):
    """
    Instead of continuous, real-time monitoring, monitor extracted log files. (Similar to `train` function.)
    """
    datasets = log_extract_batch(path, colls_num)
    data = pd.concat(datasets)
    proc = process(data)
    result = evaluate(proc, model, trained)
    return result

def check_repeat(model, path, trained, colls_num, repetitions):
    evaluated = [None for _ in range(repetitions)]
    for i in range(repetitions):
        checked = check(model, path, trained, colls_num)
        evaluated[i] = checked[checked['score'] < 0].sort_values(by=['score'])
    res = pd.concat(evaluated).reset_index().groupby('primary')
    return res.agg(detections_N=pd.NamedAgg(column='primary', aggfunc='count'))


def main(argv):
    training = False
    trained = False
    continuous = True
    log_path = DNS_LOGFILE
    model_path = None
    contamination = DEFAULT_CONT
    coll_delay = COLL_DELAY
    colls_num = COLLS_NUM
    repetitions = 0
    plot = False

    try:
        opts, _ = getopt.getopt(argv, 'ht:m:l:bc:d:n:r:p', [])
    except getopt.GetoptError:
        return
    
    for opt, arg in opts:
        if opt == '-t':
            log_path = arg
            training = True
        elif opt == '-l':
            log_path = arg
        elif opt == '-m':
            model_path = arg
        elif opt == '-b':
            continuous = False
        elif opt == '-c':
            contamination = float(arg)
        elif opt == '-d':
            coll_delay = int(arg)
        elif opt == '-n':
            colls_num = int(arg)
        elif opt == '-r':
            repetitions = int(arg)
        elif opt == '-p':
            plot = True
        elif opt == '-h':
            print(HELP)
            return

    if model_path is not None:
        trained = True

    if training:    
        clf = IsolationForest(contamination=contamination, max_features=6, max_samples=1000)
        model = train(log_path, clf, colls_num)
        save_model(model, model_path)
    else:
        model = load_model(model_path) if model_path is not None else IsolationForest(contamination=contamination, max_features=6, max_samples=1000)
        if continuous:
            monitor(model, log_path, trained, colls_num, coll_delay)
        elif repetitions:
            res = check_repeat(model, log_path, trained, colls_num, repetitions)
            print(res)
            if plot:
                res.plot(kind='bar', rot=90)
                plt.show()
                print(res)
        else:
            res = check(model, log_path, trained, colls_num)
            print(res[res['score'] < 0])

if __name__ == '__main__':
    main(sys.argv[1:])