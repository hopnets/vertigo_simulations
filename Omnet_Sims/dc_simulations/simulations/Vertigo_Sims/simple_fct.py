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
TOTAL_DC_SERVER_NUM = BASE_AGG_NUM * SERVERS_UNDER_EACH_RACK

'''
    Directories used for processing the extracted results
'''
directory = './results_sample_1g/REQUEST_SENT/'
directory2 = './results_sample_1g/FLOW_STARTED/'
directory3 = './results_sample_1g/FLOW_ENDED/'
directory4 = './results_sample_1g/REPLY_LENGTH_ASKED/'
directory5 = './results_sample_1g/FLOW_ENDED_QUERY_ID/'

'''
    Classes for processing Response time and FCT
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


# In this case: load
colors = ['k', 'dodgerblue', 'r', 'springgreen']
markers = ['o', 'X', 'v', '|']
x_values = [35, 55, 75, 95]
all_flow_completions = []
all_mean_fct = []
all_tail_fct = []

for category in CATEGORIES:
    #records
    flow_completions = []
    mean_fct = []
    tail_fct = []
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
                                            server_flow_list = [[] for i in range(TOTAL_DC_SERVER_NUM)]
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
                                                            flow_id = row[k+1]
                                                            server_idx = int((row1[k].split('server[')[1]).split(']')[0])
                                                            server_flow_list[server_idx].append(Flow(rep_num=rep_num, ID=flow_id, record_time=time,
                                                                                                     start_time=time))
                                                        except:
                                                            continue

                                            with open(directory2 + file_name, 'rt') as csv_file:
                                                csv_reader = csv.reader(csv_file, delimiter=',')
                                                first_line = True
                                                row1 = None
                                                row_counter = None
                                                for row in csv_reader:
                                                    if first_line:
                                                        row1 = row
                                                        first_line = False
                                                        row_counter = -1
                                                        is_jitter = True
                                                        continue
                                                    row_counter += 1
                                                    for k in range(0, len(row), 2):
                                                        try:
                                                            server_idx = int((row1[k].split('server[')[1]).split(']')[0])
                                                            time = float(row[k])
                                                            is_bursty = int(row[k+1])
                                                            if is_bursty == 1:
                                                                # we need to update it
                                                                if time == server_flow_list[server_idx][row_counter].record_time:
                                                                    server_flow_list[server_idx][row_counter].is_bursty = True
                                                                else:
                                                                    raise Exception("Record mismatch!")
                                                        except:
                                                            continue

                                            # put flows in hash tables
                                            server_flow_hash_list = [dict() for i in range(TOTAL_DC_SERVER_NUM)]
                                            for server_idx, flows in enumerate(server_flow_list):
                                                for flow in flows:
                                                    if flow.ID in server_flow_hash_list[server_idx]:
                                                        pass
                                                    else:
                                                        server_flow_hash_list[server_idx].update({flow.ID: flow})

                                            with open(directory3 + file_name, 'rt') as csv_file:
                                                csv_reader = csv.reader(csv_file, delimiter=',')
                                                first_line = True
                                                row1 = None
                                                for row in csv_reader:
                                                    if first_line:
                                                        row1 = row
                                                        first_line = False
                                                        is_jitter = True
                                                        continue
                                                    for k in range(0, len(row), 2):
                                                        try:
                                                            server_idx = int((row1[k].split('server[')[1]).split(']')[0])
                                                            time = float(row[k])
                                                            flow_id = row[k+1]
                                                            if flow_id in server_flow_hash_list[server_idx]:
                                                                flow = server_flow_hash_list[server_idx].get(flow_id)
                                                                flow.end_time = time
                                                                if flow.end_time - flow.start_time <= 0:
                                                                    raise Exception("<=0 FCT?")
                                                        except:
                                                            continue

                                            # put all flows in one hash table
                                            flows_temp = dict()
                                            for flow_hash_table in server_flow_hash_list:
                                                for flow_id in flow_hash_table:
                                                    flow = flow_hash_table.get(flow_id)
                                                    flows_temp.update({flow_id: flow})
                                            all_flows.append(flows_temp)

                                        fct_cdf_info = []
                                        bursty_fct_cdf_info = []
                                        background_fct_cdf_info = []

                                        num_all_flows_started = 0
                                        num_all_flows_ended = 0

                                        num_bursty_flows_started = 0
                                        num_bursty_flows_ended = 0

                                        num_background_flows_started = 0
                                        num_background_flows_ended = 0

                                        for flow_pack in all_flows:
                                            for flow_id in flow_pack:
                                                if flow_pack[flow_id].rep_num != all_flows.index(flow_pack):
                                                    raise Exception('Something is wrong!')
                                                if flow_pack[flow_id].start_time is not None:
                                                    num_all_flows_started += 1
                                                    if flow_pack[flow_id].is_bursty:
                                                        num_bursty_flows_started += 1
                                                    else:
                                                        num_background_flows_started += 1
                                                    if flow_pack[flow_id].end_time is not None:
                                                        num_all_flows_ended += 1
                                                        fct_cdf_info.append(flow_pack[flow_id].end_time - flow_pack[flow_id].start_time)
                                                        if flow_pack[flow_id].is_bursty:
                                                            num_bursty_flows_ended += 1
                                                            bursty_fct_cdf_info.append(
                                                                flow_pack[flow_id].end_time - flow_pack[flow_id].start_time)
                                                        else:
                                                            background_fct_cdf_info.append(
                                                                flow_pack[flow_id].end_time - flow_pack[flow_id].start_time)
                                                            num_background_flows_ended += 1

                                        if num_bursty_flows_started == 0:
                                            percentage_bursty_num_requests_finished = 0
                                        else:
                                            percentage_bursty_num_requests_finished = num_bursty_flows_ended / num_bursty_flows_started * 100
                                        if num_background_flows_started == 0:
                                            percentage_background_num_requests_finished = 0
                                        else:
                                            percentage_background_num_requests_finished = num_background_flows_ended / num_background_flows_started * 100

                                        print(file_name.replace("_",","))
                                        print('flow type,started, finished,% completed,mean, p10, p20, p50, p90, p99, p99.9')

                                        if len(fct_cdf_info) == 0:
                                            fct_cdf_info.append(0)

                                        if len(bursty_fct_cdf_info) == 0:
                                            bursty_fct_cdf_info.append(0)

                                        if len(background_fct_cdf_info) == 0:
                                            background_fct_cdf_info.append(0)

                                        flow_completions.append(num_all_flows_ended / num_all_flows_started * 100)
                                        mean_fct.append(np.mean(fct_cdf_info))
                                        tail_fct.append(np.percentile(fct_cdf_info, 99))
                                        print('all,{},{},{},{},{},{},{},{},{},{}\nbursty,{},{},{},{},{},{},{},{},{},{}\nbackground,{},{},{},{},{},{},{},{},{},{}'
                                                .format(num_all_flows_started / REP_NUM,
                                                    num_all_flows_ended / REP_NUM,
                                                    num_all_flows_ended / num_all_flows_started * 100,np.mean(fct_cdf_info),
                                                    np.percentile(fct_cdf_info, 10),
                                                    np.percentile(fct_cdf_info, 20),
                                                    np.percentile(fct_cdf_info, 50),
                                                    np.percentile(fct_cdf_info, 90),
                                                    np.percentile(fct_cdf_info, 99),
                                                    np.percentile(fct_cdf_info, 99.9),
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
                                                    num_background_flows_started/REP_NUM,
                                                    num_background_flows_ended/REP_NUM,
                                                    percentage_background_num_requests_finished,
                                                    np.mean(background_fct_cdf_info),
                                                        np.percentile(background_fct_cdf_info, 10),
                                                        np.percentile(background_fct_cdf_info, 20),
                                                        np.percentile(background_fct_cdf_info, 50),
                                                        np.percentile(background_fct_cdf_info, 90),
                                                        np.percentile(background_fct_cdf_info, 99),
                                                        np.percentile(background_fct_cdf_info, 99.9)

                                                    ))
                                        print()
    all_flow_completions.append(flow_completions)
    all_mean_fct.append(mean_fct)
    all_tail_fct.append(tail_fct)


if len(all_flow_completions) != len(CATEGORIES):
    raise Exception("len(all_query_completions) != len(CATEGORIES)")

if len(all_mean_fct) != len(CATEGORIES):
    raise Exception("len(all_query_completions) != len(CATEGORIES)")

if len(all_tail_fct) != len(CATEGORIES):
    raise Exception("len(all_query_completions) != len(CATEGORIES)")

if len(all_flow_completions[0]) != len(x_values):
    raise Exception("len(all_query_completions[0]) != len(x_values)")

if len(all_mean_fct[0]) != len(x_values):
    raise Exception("len(all_query_completions[0]) != len(x_values)")

if len(all_tail_fct[0]) != len(x_values):
    raise Exception("len(all_query_completions[0]) != len(x_values)")

# plot_figs(x_values, all_flow_completions, CATEGORIES, markers, colors)
# plt.xlabel('Load (%)')
# plt.ylabel('Flow Completion %')
# plt.savefig("figs/{}.png".format('simple_flow_completions'))
# plt.close()

plot_figs(x_values, all_mean_fct, CATEGORIES, markers, colors)
plt.xlabel('Load (%)')
plt.ylabel('Mean FCT (s)')
plt.savefig("figs/{}.png".format('simple_mean_fct'))
plt.close()

plot_figs(x_values, all_tail_fct, CATEGORIES, markers, colors)
plt.xlabel('Load (%)')
plt.ylabel('Tail FCT (s)')
plt.savefig("figs/{}.png".format('simple_tail_fct'))
plt.close()
