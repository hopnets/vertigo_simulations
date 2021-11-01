import csv

import numpy as np
from matplotlib import pyplot as plt

'''
    For processing the results, you have to first
'''

'''
    Variable setup
'''
# General variables
LEAF_SPINE = 0
FAT_TREE = 1
TOPOLOGY = LEAF_SPINE
CATEGORIES = ["dctcp_ecmp", "dctcp_drill", "dctcp_dibs", "dctcp_vertigo"]

TTLS = [250]    # TTL values
RANDOM_POWER_FACTOR = [2]   # Power-of-N choices
RANDOM_POWER_BOUNCE_FACTOR = [2]   # Power-of-N choices
NUM_REQUESTS_PER_BURST = [40]      # Incast scales
BG_INTER_ARRIVAL_MULT = [19.75]    # BG inter-arrival multipliers
INCAST_INTER_ARRIVAL_MULT = [0.5, 0.167, 0.097, 0.071]
INCAST_FLOW_SIZE = [20000]     # Incast flow size
MARKING_TIMER = ["0.00120"]    # Value of timer of the marking component
ORDERING_TIMER = ["0.00120"]    # Value of timer of the ordering component
rep_num = 0
NUM_BURSTY_APPS = 1
BASE_NUM_BACKGROUND_CONNECTIONS_TO_OTHER_SERVERS = 1
REP_NUM = 1

mice_flow_size = 10 * (10 ** 3)
elephant_flow_size = 10 * (10 ** 6)


# Fat tree variables
K = 8

# Leaf-spine variables
BASE_SPINE_NUM = 4
BASE_AGG_NUM = 8
SERVERS_UNDER_EACH_RACK = 40

'''
    Directories used for processing the extracted results
'''
directory = './results_sample_1g/REQUEST_SENT/'
directory2 = './results_sample_1g/FLOW_STARTED/'
directory3 = './results_sample_1g/FLOW_ENDED/'
directory4 = './results_sample_1g/REPLY_LENGTH_ASKED/'
directory5 = './results_sample_1g/FLOW_ENDED_QUERY_ID/'

'''
    Classes for processing Response time and QCT
'''


class Flow:
    def __init__(self, rep_num=None, ID=None, send_time=None, is_bursty=False, record_time=None, start_time=None):
        self.rep_num = rep_num
        self.ID = ID
        self.send_time = send_time
        self.start_time = start_time
        self.end_time = None
        self.is_bursty = is_bursty
        self.length = None
        self.query_id = 0
        self.record_time = record_time


class Query:
    def __init__(self, send_time, rep_num, end_time):
        self.flows = []
        self.send_time = send_time
        self.rep_num = rep_num
        self.end_time = end_time

    def is_completed(self, incast_scale):
        terminated_flows = [i for i in self.flows if i.send_time is not None and i.end_time is not None]
        return len(terminated_flows) == incast_scale

def plot_figs(x, y, labels, markers, colors):
    if len(y) != len(labels):
        raise Exception("len(y) != len(labels)")
    if len(markers) != len(y):
        raise Exception("len(markers) != len(y)")
    if len(colors) != len(y):
        raise Exception("len(colors) != len(y)")
    for i in range(len(y)):
        plt.plot(x, y[i], label=[labels[i]], marker=markers[i], linewidth=6, color=colors[i], markersize=16, markevery=0.08)
    plt.grid()
    plt.xticks(x)
    plt.legend()

'''
    Processing data
'''

# In this case: load
colors = ['k', 'dodgerblue', 'r', 'springgreen']
markers = ['o', 'X', 'v', '|']
x_values = [35, 55, 75, 95]
all_query_completions = []
all_mean_qct = []
all_tail_qct = []

for category in CATEGORIES:
    #records
    query_completions = []
    mean_qct = []
    tail_qct = []

    for ttl in TTLS:
        for random_power_factor in RANDOM_POWER_FACTOR:
            for random_power_bounce_factor in RANDOM_POWER_BOUNCE_FACTOR:
                for marking_timer in MARKING_TIMER:
                    for ordering_timer in ORDERING_TIMER:
                        for bg_inter_arrival_mult in BG_INTER_ARRIVAL_MULT:
                            for incast_inter_arrival_mult in INCAST_INTER_ARRIVAL_MULT:
                                for incast_flow_size in INCAST_FLOW_SIZE:
                                    for incast_scale in NUM_REQUESTS_PER_BURST:
                                        all_flows = []
                                        is_jitter = False
                                        for rep_num in range(REP_NUM):
                                            if TOPOLOGY == FAT_TREE:
                                                file_name = '{}_k_{}_burstyapps_{}_mice' \
                                                            '_{}_reqPerBurst_{}_bgintermult_{}_burstyintermult_{}_ttl' \
                                                            '_{}_rndfwfactor_{}_rndbouncefactor_{}_incastfsize_' \
                                                            '{}_mrktimer_{}_ordtimer_{}_rep_{}.csv'.format(
                                                    K, NUM_BURSTY_APPS,
                                                    BASE_NUM_BACKGROUND_CONNECTIONS_TO_OTHER_SERVERS,
                                                    incast_scale, bg_inter_arrival_mult, incast_inter_arrival_mult,
                                                    ttl, random_power_factor, random_power_bounce_factor, incast_flow_size,
                                                    marking_timer, ordering_timer, rep_num, category)

                                            else:
                                                file_name = '{}_spines_{}_aggs_{}_servers_{}_burstyapps_{}_mice' \
                                                            '_{}_reqPerBurst_{}_bgintermult_{}_burstyintermult_{}_ttl' \
                                                            '_{}_rndfwfactor_{}_rndbouncefactor_{}_incastfsize_' \
                                                            '{}_mrktimer_{}_ordtimer_{}_rep_{}.csv'.format(
                                                    BASE_SPINE_NUM, BASE_AGG_NUM,
                                                    SERVERS_UNDER_EACH_RACK,
                                                    NUM_BURSTY_APPS,
                                                    BASE_NUM_BACKGROUND_CONNECTIONS_TO_OTHER_SERVERS,
                                                    incast_scale, bg_inter_arrival_mult, incast_inter_arrival_mult,
                                                    ttl, random_power_factor, random_power_bounce_factor, incast_flow_size,
                                                    marking_timer, ordering_timer, rep_num, category)
                                            flows_temp = dict()
                                            flow_app_mapper = dict()
                                            with open(directory + file_name, 'rt') as csv_file:
                                                csv_reader = csv.reader(csv_file, delimiter=',')
                                                first_line = True
                                                row1 = None
                                                for row in csv_reader:
                                                    if first_line:
                                                        row1 = row
                                                        first_line = False
                                                        continue
                                                    for k in range(0, len(row), 2):
                                                        try:
                                                            time = float(row[k])
                                                            flow_id = int(row[k+1])
                                                            is_bursty = False
                                                            app_idx = int((row1[k].split('app[')[1]).split(']')[0])
                                                            if app_idx >= 1 + BASE_NUM_BACKGROUND_CONNECTIONS_TO_OTHER_SERVERS:
                                                                is_bursty = True
                                                            flows_temp.update({flow_id : Flow(rep_num=rep_num, ID=flow_id, send_time=time, is_bursty=is_bursty)})
                                                            server_idx = int((row1[k].split('server[')[1]).split(']')[0])
                                                            unique_id = 'server[{}].app[{}]'.format(server_idx, app_idx)
                                                            if unique_id not in flow_app_mapper:
                                                                flow_app_mapper.update({unique_id: []})
                                                            flow_app_mapper[unique_id].append(flow_id)
                                                        except:
                                                            continue

                                            with open(directory4 + file_name, 'rt') as csv_file:
                                                csv_reader = csv.reader(csv_file, delimiter=',')
                                                first_line = True
                                                row1 = None
                                                row_counter = None
                                                for row in csv_reader:
                                                    if first_line:
                                                        row1 = row
                                                        first_line = False
                                                        row_counter = 0
                                                        is_jitter = True
                                                        continue
                                                    row_counter += 1
                                                    for k in range(0, len(row), 2):
                                                        try:
                                                            server_idx = int((row1[k].split('server[')[1]).split(']')[0])
                                                            app_idx = int((row1[k].split('app[')[1]).split(']')[0])
                                                            unique_id = 'server[{}].app[{}]'.format(server_idx, app_idx)
                                                            flow_id_list = flow_app_mapper[unique_id]
                                                            flow_id = flow_id_list[row_counter - 1]
                                                            flow = flows_temp[flow_id]
                                                            time = float(row[k])
                                                            length = int(row[k+1])
                                                            flow.length = length
                                                        except:
                                                            if row_counter <= len(flow_id_list):
                                                                raise Exception("Something isn't quite right! row_counter: {}, len(flow_id_list): {}"
                                                                                .format(row_counter, len(flow_id_list)))
                                                            continue

                                            with open(directory2 + file_name, 'rt') as csv_file:
                                                csv_reader = csv.reader(csv_file, delimiter=',')
                                                first_line = True
                                                row1 = None
                                                for row in csv_reader:
                                                    if first_line:
                                                        row1 = row
                                                        first_line = False
                                                    for k in range(0, len(row), 2):
                                                        try:
                                                            time = float(row[k])
                                                            flow_id = int(row[k + 1])
                                                            flow = flows_temp.get(flow_id)
                                                            flow.start_time = time
                                                        except:
                                                            continue

                                            with open(directory3 + file_name, 'rt') as csv_file:
                                                csv_reader = csv.reader(csv_file, delimiter=',')
                                                first_line = True
                                                row1 = None
                                                for row in csv_reader:
                                                    if first_line:
                                                        row1 = row
                                                        first_line = False
                                                    for k in range(0, len(row), 2):
                                                        try:
                                                            time = float(row[k])
                                                            flow_id = int(row[k + 1])
                                                            flow = flows_temp.get(flow_id)
                                                            flow.end_time = time
                                                        except:
                                                            continue

                                            with open(directory5 + file_name, 'rt') as csv_file:
                                                csv_reader = csv.reader(csv_file, delimiter=',')
                                                first_line = True
                                                row1 = None
                                                row_counter = None
                                                for row in csv_reader:
                                                    if first_line:
                                                        row1 = row
                                                        first_line = False
                                                        row_counter = 0
                                                        is_jitter = True
                                                        continue
                                                    row_counter += 1
                                                    for k in range(0, len(row), 2):
                                                        try:
                                                            server_idx = int((row1[k].split('server[')[1]).split(']')[0])
                                                            app_idx = int((row1[k].split('app[')[1]).split(']')[0])
                                                            unique_id = 'server[{}].app[{}]'.format(server_idx, app_idx)
                                                            flow_id_list = flow_app_mapper[unique_id]
                                                            flow_id = flow_id_list[row_counter - 1]
                                                            flow = flows_temp[flow_id]
                                                            time = float(row[k])
                                                            query_id = int(row[k+1])
                                                            flow.query_id = query_id
                                                        except:
                                                            if row_counter <= len(flow_id_list):
                                                                raise Exception("Something isn't quite right with query id! row_counter: {}, len(flow_id_list): {}"
                                                                                .format(row_counter, len(flow_id_list)))
                                                            continue
                                            all_flows.append(flows_temp)

                                        fct_cdf_info = []
                                        bursty_fct_cdf_info = []
                                        background_fct_cdf_info = []

                                        mice_fct_cdf_info = []
                                        cat_fct_cdf_info = []
                                        elephant_fct_cdf_info = []

                                        num_all_flows_requested = 0
                                        num_all_flows_started = 0
                                        num_all_flows_ended = 0

                                        num_bursty_flows_requested = 0
                                        num_bursty_flows_started = 0
                                        num_bursty_flows_ended = 0

                                        num_background_flows_requested = 0
                                        num_background_flows_started = 0
                                        num_background_flows_ended = 0

                                        num_mice_flows_requested = 0
                                        num_mice_flows_started = 0
                                        num_mice_flows_ended = 0

                                        num_cat_flows_requested = 0
                                        num_cat_flows_started = 0
                                        num_cat_flows_ended = 0

                                        num_elephant_flows_requested = 0
                                        num_elephant_flows_started = 0
                                        num_elephant_flows_ended = 0

                                        for flow_pack in all_flows:
                                            for flow_id in flow_pack:
                                                if flow_pack[flow_id].rep_num != all_flows.index(flow_pack):
                                                    raise Exception('Something is wrong!')
                                                if flow_pack[flow_id].send_time is not None:
                                                    num_all_flows_requested += 1
                                                    if flow_pack[flow_id].is_bursty:
                                                        num_bursty_flows_requested += 1
                                                    else:
                                                        num_background_flows_requested += 1
                                                    if not flow_pack[flow_id].is_bursty:
                                                        if flow_pack[flow_id].length <= mice_flow_size:
                                                            num_mice_flows_requested += 1
                                                        elif flow_pack[flow_id].length >= elephant_flow_size:
                                                            num_elephant_flows_requested += 1
                                                        else:
                                                            num_cat_flows_requested += 1
                                                    if flow_pack[flow_id].start_time is not None:
                                                        num_all_flows_started += 1
                                                        if flow_pack[flow_id].is_bursty:
                                                            num_bursty_flows_started += 1
                                                        else:
                                                            num_background_flows_started += 1
                                                        if not flow_pack[flow_id].is_bursty:
                                                            if flow_pack[flow_id].length <= mice_flow_size:
                                                                num_mice_flows_started += 1
                                                            elif flow_pack[flow_id].length >= elephant_flow_size:
                                                                num_elephant_flows_started += 1
                                                            else:
                                                                num_cat_flows_started += 1
                                                        if flow_pack[flow_id].end_time is not None:
                                                            num_all_flows_ended += 1
                                                            if (flow_pack[flow_id].end_time - flow_pack[flow_id].send_time == 0):
                                                                raise Exception("Response time is 0!!!")
                                                            fct_cdf_info.append(flow_pack[flow_id].end_time - flow_pack[flow_id].send_time)
                                                            if (not flow_pack[flow_id].is_bursty):
                                                                if flow_pack[flow_id].length <= mice_flow_size:
                                                                    num_mice_flows_ended += 1
                                                                    mice_fct_cdf_info.append(flow_pack[flow_id].end_time - flow_pack[flow_id].send_time)
                                                                elif flow_pack[flow_id].length >= elephant_flow_size:
                                                                    num_elephant_flows_ended += 1
                                                                    elephant_fct_cdf_info.append(
                                                                        flow_pack[flow_id].end_time - flow_pack[flow_id].send_time)
                                                                else:
                                                                    num_cat_flows_ended += 1
                                                                    cat_fct_cdf_info.append(flow_pack[flow_id].end_time - flow_pack[flow_id].send_time)
                                                            if flow_pack[flow_id].is_bursty:
                                                                num_bursty_flows_ended += 1
                                                                bursty_fct_cdf_info.append(
                                                                    flow_pack[flow_id].end_time - flow_pack[flow_id].send_time)
                                                            else:
                                                                background_fct_cdf_info.append(
                                                                    flow_pack[flow_id].end_time - flow_pack[flow_id].send_time)
                                                                num_background_flows_ended += 1

                                        if num_bursty_flows_requested == 0:
                                            percentage_bursty_num_requests_finished = 0
                                        else:
                                            percentage_bursty_num_requests_finished = num_bursty_flows_ended / num_bursty_flows_requested * 100

                                        if num_background_flows_requested == 0:
                                            percentage_background_num_requests_finished = 0
                                        else:
                                            percentage_background_num_requests_finished = num_background_flows_ended / num_background_flows_requested * 100

                                        if num_mice_flows_requested == 0:
                                            percentage_mice_num_requests_finished = 0
                                        else:
                                            percentage_mice_num_requests_finished = num_mice_flows_ended / num_mice_flows_requested * 100

                                        if num_cat_flows_requested == 0:
                                            percentage_cat_num_requests_finished = 0
                                        else:
                                            percentage_cat_num_requests_finished = num_cat_flows_ended / num_cat_flows_requested * 100

                                        if num_elephant_flows_requested == 0:
                                            percentage_elephant_num_requests_finished = 0
                                        else:
                                            percentage_elephant_num_requests_finished = num_elephant_flows_ended / num_elephant_flows_requested * 100

                                        if len(fct_cdf_info) == 0:
                                            fct_cdf_info.append(0)
                                        if len(mice_fct_cdf_info) == 0:
                                            mice_fct_cdf_info.append(0)
                                        if len(cat_fct_cdf_info) == 0:
                                            cat_fct_cdf_info.append(0)
                                        if len(elephant_fct_cdf_info) == 0:
                                            elephant_fct_cdf_info.append(0)
                                        if len(bursty_fct_cdf_info) == 0:
                                            bursty_fct_cdf_info.append(0)
                                        if len(background_fct_cdf_info) == 0:
                                            background_fct_cdf_info.append(0)

                                        print(file_name.replace("_",","))

                                        print("type,requested, started, finished, %Flow Completion, mean, p10, p20, p50, p90, p99, p99.9")

                                        print('all,{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\n mice of size, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\ncat of size, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\nelephant of size, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\n bursty,{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}\nbackground,{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}'.format(
                                            num_all_flows_requested / REP_NUM,
                                              num_all_flows_started / REP_NUM,
                                              num_all_flows_ended / REP_NUM,
                                              num_all_flows_ended / num_all_flows_requested * 100,
                                              np.mean(fct_cdf_info),
                                                np.percentile(fct_cdf_info, 10),
                                                np.percentile(fct_cdf_info, 20),
                                                np.percentile(fct_cdf_info, 50),
                                                np.percentile(fct_cdf_info, 90),
                                                np.percentile(fct_cdf_info, 99),
                                                np.percentile(fct_cdf_info, 99.9),
                                                num_mice_flows_requested,
                                                num_mice_flows_started,
                                                num_mice_flows_ended,
                                                percentage_mice_num_requests_finished,
                                                np.mean(mice_fct_cdf_info),
                                                np.percentile(mice_fct_cdf_info, 10),
                                                np.percentile(mice_fct_cdf_info, 20),
                                                np.percentile(mice_fct_cdf_info, 50),
                                                np.percentile(mice_fct_cdf_info, 90),
                                                np.percentile(mice_fct_cdf_info, 99),
                                                np.percentile(mice_fct_cdf_info, 99.9),
                                                num_cat_flows_requested,
                                                num_cat_flows_started,
                                                num_cat_flows_ended,
                                                percentage_cat_num_requests_finished,
                                                np.mean(cat_fct_cdf_info),
                                                np.percentile(cat_fct_cdf_info, 10),
                                                np.percentile(cat_fct_cdf_info, 20),
                                                np.percentile(cat_fct_cdf_info, 50),
                                                np.percentile(cat_fct_cdf_info, 90),
                                                np.percentile(cat_fct_cdf_info, 99),
                                                np.percentile(cat_fct_cdf_info, 99.9),
                                                num_elephant_flows_requested,
                                                num_elephant_flows_started,
                                                num_elephant_flows_ended,
                                                percentage_elephant_num_requests_finished,
                                                np.mean(elephant_fct_cdf_info),
                                                np.percentile(elephant_fct_cdf_info, 10),
                                                np.percentile(elephant_fct_cdf_info, 20),
                                                np.percentile(elephant_fct_cdf_info, 50),
                                                np.percentile(elephant_fct_cdf_info, 90),
                                                np.percentile(elephant_fct_cdf_info, 99),
                                                np.percentile(elephant_fct_cdf_info, 99.9),
                                              num_bursty_flows_requested / REP_NUM,
                                              num_bursty_flows_started / REP_NUM,
                                              num_bursty_flows_ended / REP_NUM,
                                              percentage_bursty_num_requests_finished,
                                              np.mean(bursty_fct_cdf_info),
                                              np.percentile(bursty_fct_cdf_info, 10),
                                            np.percentile(bursty_fct_cdf_info, 20),
                                            np.percentile(bursty_fct_cdf_info, 50),
                                            np.percentile(bursty_fct_cdf_info, 90),
                                            np.percentile(bursty_fct_cdf_info, 99),
                                            np.percentile(bursty_fct_cdf_info, 99.9),
                                              num_background_flows_requested / REP_NUM,
                                              num_background_flows_started/REP_NUM,
                                              num_background_flows_ended/REP_NUM,
                                              percentage_background_num_requests_finished,
                                                np.mean(background_fct_cdf_info),
                                              np.percentile(background_fct_cdf_info, 10),
                                            np.percentile(background_fct_cdf_info, 20),
                                            np.percentile(background_fct_cdf_info, 50),
                                            np.percentile(background_fct_cdf_info, 90),
                                            np.percentile(background_fct_cdf_info, 99),
                                            np.percentile(background_fct_cdf_info, 99.9)))

                                        all_queries = []
                                        for flow_pack in all_flows:
                                            temp_queries = dict()
                                            for flow_id in flow_pack:
                                                if flow_pack[flow_id].rep_num != all_flows.index(flow_pack):
                                                    raise Exception('Something is wrong!')
                                                if flow_pack[flow_id].is_bursty:
                                                    if int(flow_pack[flow_id].query_id) in temp_queries:
                                                        query = temp_queries[flow_pack[flow_id].query_id]
                                                        if query.send_time > flow_pack[flow_id].send_time:
                                                            query.send_time = flow_pack[flow_id].send_time
                                                        if flow_pack[flow_id].end_time is not None:
                                                            if query.end_time is None or query.end_time < flow_pack[flow_id].end_time:
                                                                query.end_time = flow_pack[flow_id].end_time
                                                    else:
                                                        query = Query(flow_pack[flow_id].send_time, flow_pack[flow_id].rep_num, flow_pack[flow_id].end_time)
                                                        temp_queries.update({flow_pack[flow_id].query_id: query})
                                                    query.flows.append(flow_pack[flow_id])
                                            all_queries.append(temp_queries)
                                        num_late_queries = 0
                                        for query_pack in all_queries:
                                            qct_info = []
                                            for query_id in query_pack:
                                                if query_pack[query_id].send_time is not None and query_pack[query_id].send_time >= 0.340:
                                                    num_late_queries += 1
                                                if query_pack[query_id].is_completed(incast_scale):
                                                    if query_pack[query_id].end_time is None or query_pack[query_id].send_time is None:
                                                        raise Exception("How is this possible?")
                                                    if query_pack[query_id].end_time - query_pack[query_id].send_time <= 0:
                                                        raise Exception("QCT cannot be <= 0")
                                                    qct_info.append(query_pack[query_id].end_time - query_pack[query_id].send_time)
                                            if (len(qct_info) == 0):
                                                qct_info.append(0)

                                            query_completions.append((len(qct_info) / len(query_pack))*100)
                                            mean_qct.append(np.mean(qct_info))
                                            tail_qct.append(np.percentile(qct_info, 99))

                                            print('Queries, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}'
                                                    .format(0, len(query_pack), len(qct_info),
                                                            (len(qct_info) / len(query_pack))*100,
                                                            np.mean(qct_info),
                                                            np.percentile(qct_info, 10),
                                                            np.percentile(qct_info, 20),
                                                            np.percentile(qct_info, 50),
                                                            np.percentile(qct_info, 90),
                                                            np.percentile(qct_info, 99),
                                                            np.percentile(qct_info, 99.9)))

                                            print()

    all_query_completions.append(query_completions)
    all_mean_qct.append(mean_qct)
    all_tail_qct.append(tail_qct)

if len(all_query_completions) != len(CATEGORIES):
    raise Exception("len(all_query_completions) != len(CATEGORIES)")

if len(all_mean_qct) != len(CATEGORIES):
    raise Exception("len(all_query_completions) != len(CATEGORIES)")

if len(all_tail_qct) != len(CATEGORIES):
    raise Exception("len(all_query_completions) != len(CATEGORIES)")

if len(all_query_completions[0]) != len(x_values):
    raise Exception("len(all_query_completions[0]) != len(x_values)")

if len(all_mean_qct[0]) != len(x_values):
    raise Exception("len(all_query_completions[0]) != len(x_values)")

if len(all_tail_qct[0]) != len(x_values):
    raise Exception("len(all_query_completions[0]) != len(x_values)")

# plot_figs(x_values, all_query_completions, CATEGORIES, markers, colors)
# plt.xlabel('Load (%)')
# plt.ylabel('Query Completion %')
# plt.savefig("figs/{}.png".format('simple_query_completions'))
# plt.close()

plot_figs(x_values, all_mean_qct, CATEGORIES, markers, colors)
plt.xlabel('Load (%)')
plt.ylabel('Mean QCT (s)')
plt.savefig("figs/{}.png".format('simple_mean_qct'))
plt.close()

plot_figs(x_values, all_tail_qct, CATEGORIES, markers, colors)
plt.xlabel('Load (%)')
plt.ylabel('Tail QCT (s)')
plt.savefig("figs/{}.png".format('simple_tail_qct'))
plt.close()