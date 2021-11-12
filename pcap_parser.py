import numpy as np
import pandas as pd
import dpkt
from print_packets import *
import time
import sys
import datetime

start_time = time.time()

output_uniflows_separately = True

pkt_num_list = []
time_list = []
ip_src_list = []
ip_dst_list = []
ip_len_list = []
proto_list = []
prt_src_list = []
prt_dst_list = []
tcp_psh_flag_list = []
tcp_rst_flag_list = []
tcp_urg_flag_list = []

def get_mean(l):
    if len(l) == 0:
        return 0
    elif len(l) == 1:
        return l[0]
    else:
        return np.absolute(np.diff(np.sort(l))).mean()
    
packet_dict = {'pkt_num': pkt_num_list,
               'time': time_list,
               'ip_src': ip_src_list,
               'ip_dst': ip_dst_list,
               'ip_len': ip_len_list,
               'proto': proto_list,
               'prt_src': prt_src_list,
               'prt_dst': prt_dst_list,
               'tcp_psh': tcp_psh_flag_list,
               'tcp_rst': tcp_rst_flag_list,
               'tcp_urg': tcp_urg_flag_list}



# All traffic is either TCP or UDP
#f = open('nmap_scan_all_10x_network_sU_Scan.pcap', 'rb')
#f = open('normal_operation.pcap', 'rb')
sliding_window = False

if len(sys.argv) > 1:
    print(sys.argv[1])
    f = open(sys.argv[1], 'rb')
    output_file = sys.argv[1].replace(".pcap", "_WithWindowing.csv")
else:
    f = open('bruteforce.pcap', 'rb')
    output_file = 'bruteforce.csv'
  
if len(sys.argv) > 2 and sys.argv[2] == "0":
    output_file = sys.argv[1].replace(".pcap", ".csv")
    sliding_window = False
    
pcap = dpkt.pcap.Reader(f)


count = 1
l2count = 0
icmpcount = 0
igmpcount = 0
udpcount=0
tcpcount=0
unknown_transport_layer = 0

for ts, buf in pcap:

    if count == 1:
        global_t0 = datetime.datetime.utcfromtimestamp(ts)

    if (count > 0):
        
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            l2count+=1
            continue
        l3 = eth.data
        if isinstance(l3.data, dpkt.icmp.ICMP):
            icmpcount+=1
            #print("ICMP Packet disarded")
            continue
        
        if isinstance(l3.data, dpkt.igmp.IGMP):
            igmpcount+=1
            continue
        
        ###### If packet is icmp then continue
        
        
        
        #print(l3)
        l4 = l3.data
        
        if not isinstance(l4, dpkt.tcp.TCP) and not isinstance(l4, dpkt.udp.UDP):
            unknown_transport_layer += 1
            continue
        
        pkt_num_list.append(count)
        time_list.append(ts)
        ip_src_list.append(inet_to_str(l3.src))
        ip_dst_list.append(inet_to_str(l3.dst))
        ip_len_list.append(len(eth.data))
        #ip_tos_list.append(l3.tos)

        if isinstance(l4, dpkt.tcp.TCP):
            tcpcount+=1
            proto_list.append('TCP')
            prt_src_list.append(l4.sport)
            prt_dst_list.append(l4.dport)
            #syn_flag = ( l4.flags & dpkt.tcp.TH_SYN ) != 0
            rst_flag = ( l4.flags & dpkt.tcp.TH_RST ) != 0
            psh_flag = ( l4.flags & dpkt.tcp.TH_PUSH) != 0
            #ack_flag = ( l4.flags & dpkt.tcp.TH_ACK ) != 0
            urg_flag = ( l4.flags & dpkt.tcp.TH_URG ) != 0
            tcp_psh_flag_list.append(psh_flag)
            tcp_rst_flag_list.append(rst_flag)
            tcp_urg_flag_list.append(urg_flag)



        if isinstance(l4, dpkt.udp.UDP):
            udpcount+=1
            proto_list.append('UDP')
            prt_src_list.append(l4.sport)
            prt_dst_list.append(l4.dport)
            # Need to add a value to these to maintain consistent rows across lists - will add zeros
            tcp_psh_flag_list.append(False)
            tcp_rst_flag_list.append(False)
            tcp_urg_flag_list.append(False)
    count+=1

print("L2 packets dicarded = ", l2count)
print("ICMP packets dicarded = ", icmpcount)
print("IGMP packets dicarded = ", igmpcount)
print("Unknown Trnsport Layer packets dicarded = ", unknown_transport_layer)
print("UDP packets  = ", udpcount)
print("TCP packets  = ", tcpcount)




packet_df = pd.DataFrame(packet_dict)
packet_df.set_index('pkt_num', inplace=True)


#   ************Create a list of tuples that identify each indepent flow

tuplist_flowid = {}
flow_count = 0

flow_list_dict = {}
tcpflowcount = 0
udpflowcount = 0

for index in range(len(pkt_num_list)):
    mytup = (ip_src_list[index], ip_dst_list[index], prt_src_list[index], prt_dst_list[index], proto_list[index])
    
    str_temp = "_".join(str(v) for v in mytup)
    if str_temp not in tuplist_flowid:
        tuplist_flowid[str_temp] = flow_count
        flow_list_dict[flow_count] = []
        flow_count += 1
        
    current_flow_id = tuplist_flowid[str_temp]
    flow_tup = (
        ip_src_list[index], ip_dst_list[index], prt_src_list[index], prt_dst_list[index], proto_list[index],
        pkt_num_list[index], time_list[index], ip_len_list[index], tcp_psh_flag_list[index], tcp_rst_flag_list[index],
        tcp_urg_flag_list[index], current_flow_id)
    
    flow_list_dict[current_flow_id].append(flow_tup)
    
    if len(flow_list_dict[current_flow_id]) == 1:
        if flow_list_dict[current_flow_id][0][4] == 'TCP':
            tcpflowcount+=1
        if flow_list_dict[current_flow_id][0][4] == 'UDP':
            udpflowcount+=1

del tuplist_flowid 

print("\nNumber of flows = ", flow_count)

packet_dict = {'pkt_num': pkt_num_list,
               'time': time_list,
               'ip_src': ip_src_list,
               'ip_dst': ip_dst_list,
               'ip_len': ip_len_list,
               'proto': proto_list,
               'prt_src': prt_src_list,
               'prt_dst': prt_dst_list, 
               'tcp_psh': tcp_psh_flag_list,
               'tcp_rst': tcp_rst_flag_list,
               'tcp_urg': tcp_urg_flag_list}





print("\nUnique flows = ", len(flow_list_dict))

print("\nflow list list element = ", flow_list_dict[0][0])
if len(flow_list_dict[0]) > 1:
    print("\nflow list list element = ", flow_list_dict[0][1])
if len(flow_list_dict[0]) > 2:
    print("\nflow list list element = ", flow_list_dict[0][2])

print("UDP flows = ", udpflowcount)
print("TCP flows = ", tcpflowcount)

class uniFlow:
    def __init__(self, ip_src, ip_dst, prt_src, prt_dst, proto, num_pkts, 
                 mean_iat, std_iat, min_iat, max_iat, mean_offset, mean_pkt_len, 
                 std_pkt_len, min_pkt_len, max_pkt_len, num_bytes, num_psh_flags,
                 num_rst_flags, num_urg_flags):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.prt_src = prt_src
        self.prt_dst = prt_dst
        self.proto = proto
        self.num_pkts = num_pkts # num pkts in this flow
        self.mean_iat = mean_iat # ave interarrival time
        self.std_iat = std_iat # std dev of IAT (jitter-ish)
        self.min_iat = min_iat
        self.max_iat = max_iat
        self.mean_offset = mean_offset
        self.mean_pkt_len = mean_pkt_len # ave pckt len per flow
        self.std_pkt_len = std_pkt_len # std deviation of packet lengths
        self.max_pkt_len = max_pkt_len
        self.min_pkt_len = min_pkt_len
        self.num_bytes = num_bytes
        self.num_psh_flags = num_psh_flags
        self.num_rst_flags = num_rst_flags
        self.num_urg_flags = num_urg_flags
        self.processed = False
           
meta_list = []
meta_list_time_0 = []
f_count = 0
for key in flow_list_dict:
    flow_list = flow_list_dict[key]
    pkt = flow_list[0] # get first pkt in the flow
    
    
    #0 is ip_src
    #1 is ip_dst
    #2 is prt_src
    #3 is prt_dst
    #4 is proto
    #5 is pkt_num
    #6 is time
    #7 is ip_len
    #8 is tcp_psh_flag
    #9 is tcp_rst_flag
    #10 is tcp_urg_flag
    #11 is flow_id
    
    
    ip_src = pkt[0]
    ip_dst = pkt[1]
    prt_src = pkt[2]
    prt_dst = pkt[3]
    proto = pkt[4]
    if proto == 'TCP':
        proto = 6
    elif proto == 'UDP':
        proto = 17
    num_pkts = len(flow_list)
    # need to calc inter-arrival time and ave pkt length
    length_list = []
    time_list = []
    psh_list = []
    rst_list = []
    urg_list = []
    for p in flow_list:
        length_list.append(p[7])
        time_list.append(p[6])
        psh_list.append(p[8])
        rst_list.append(p[9])
        urg_list.append(p[10])
    mean_pkt_len = sum(length_list) / num_pkts
    pkt_len_arry = np.array(length_list)
    std_pkt_len = float(np.std(pkt_len_arry))
    min_pkt_len = float(min(pkt_len_arry))
    max_pkt_len = float(max(pkt_len_arry))
    num_bytes = sum(length_list)
    num_psh_flags = sum(psh_list)
    num_rst_flags = sum(rst_list)
    num_urg_flags = sum(urg_list)
    if num_pkts > 1:
        time_list.sort(reverse = True) # put times in descending order
        t_diff = abs(np.diff(time_list))
        mean_iat = sum(t_diff) / (num_pkts - 1)
        std_iat = np.std(t_diff) # std dev of IAT
        min_iat = min(t_diff)
        max_iat = max(t_diff)
        # Kenzi's apparently good feature is the mean time between the first
        # packet and each sucessive packet: (t2-t1) + (t3-t1) + (t4-t1) / n
        time_list.sort() # sort into ascending order now
        t0 = time_list[0]
        time_total = 0.0
        for f in range(1, num_pkts):
            time_total += abs(t0 - time_list[f])
        mean_offset = time_total / (num_pkts - 1)
            
    else:
        mean_iat = 0.0
        std_iat = 0.0
        min_iat = 0.0
        max_iat = 0.0
        mean_offset = 0.0
    uniflow = uniFlow(ip_src, ip_dst, prt_src, prt_dst, proto, num_pkts, mean_iat, 
                      std_iat, min_iat, max_iat, mean_offset, mean_pkt_len, std_pkt_len,
                      min_pkt_len, max_pkt_len, num_bytes, num_psh_flags,
                      num_rst_flags, num_urg_flags)
    meta_list.append(uniflow)
    meta_list_time_0.append((datetime.datetime.utcfromtimestamp(time_list[0]) - global_t0).seconds // 60)
    f_count +=1


def uniFlow2df(uniflow):
    df = pd.DataFrame(columns=['ip_src', 'ip_dst', 'prt_src', 'prt_dst', 'proto', 'num_pkts', 
                               'mean_iat', 'std_iat', 'min_iat', 'max_iat', 'mean_offset', 'mean_pkt_len',
                               'std_pkt_len', 'min_pkt_len', 'max_pkt_len', 'num_bytes',
                               'num_psh_flags', 'num_rst_flags', 'num_urg_flags'])
    df.loc[0,'ip_src'] = str(uniflow.ip_src)
    df.loc[0,'ip_dst'] = str(uniflow.ip_dst)
    df.loc[0,'prt_src'] = int(uniflow.prt_src)
    df.loc[0,'prt_dst'] = int(uniflow.prt_dst)
    df.loc[0,'proto'] = int(uniflow.proto)
    df.loc[0,'num_pkts'] = int(uniflow.num_pkts)
    df.loc[0,'mean_iat'] = float(uniflow.mean_iat)
    df.loc[0,'std_iat'] = float(uniflow.std_iat)
    df.loc[0,'min_iat'] = float(uniflow.min_iat)
    df.loc[0,'max_iat'] = float(uniflow.max_iat)
    df.loc[0,'mean_offset'] = float(uniflow.mean_offset)
    df.loc[0,'mean_pkt_len'] = float(uniflow.mean_pkt_len)
    df.loc[0,'std_pkt_len'] = float(uniflow.std_pkt_len)
    df.loc[0,'min_pkt_len'] = float(uniflow.min_pkt_len)
    df.loc[0,'max_pkt_len'] = float(uniflow.max_pkt_len)
    df.loc[0,'num_bytes'] = int(uniflow.num_bytes)
    df.loc[0,'num_psh_flags'] = int(uniflow.num_psh_flags)
    df.loc[0,'num_rst_flags'] = int(uniflow.num_rst_flags)
    df.loc[0,'num_urg_flags'] = int(uniflow.num_urg_flags)
    return df


if output_uniflows_separately:
#feature_df = pd.DataFrame()
    feature_df = pd.DataFrame(columns=['ip_src', 'ip_dst', 'prt_src', 'prt_dst', 'proto', 
                                       'num_pkts', 'mean_iat', 'std_iat', 'min_iat',
                                       'max_iat', 'mean_offset', 'mean_pkt_len', 'num_bytes', 'num_psh_flags',
                                       'num_rst_flags', 'num_urg_flags'])
    
    for flow in meta_list:
        flow_df = uniFlow2df(flow)
        feature_df = feature_df.append(flow_df, ignore_index=True, sort=False)
        
    
    #feature_df.to_csv('robert_stealth.csv', sep=',') 
    feature_df.to_csv('uniflow_' + output_file, sep=',') 

print('\nAll uniflows processed')

# No convert uniflows into biflows
#ßfor uniflow in feature_df:
        
##################################
# Combine uniflows into biflows

df_biflow = pd.DataFrame(columns=['ip_src', 'ip_dst', 'prt_src', 'prt_dst', 'proto', 'fwd_num_pkts', 'bwd_num_pkts',
                 'fwd_mean_iat', 'bwd_mean_iat', 'fwd_std_iat', 'bwd_std_iat', 'fwd_min_iat', 'bwd_min_iat',
                 'fwd_max_iat', 'bwd_max_iat','fwd_mean_offset', 'bwd_mean_offset', 'fwd_mean_pkt_len', 'bwd_mean_pkt_len',
                 'fwd_std_pkt_len', 'bwd_std_pkt_len', 'fwd_min_pkt_len', 'bwd_min_pkt_len',
                 'fwd_max_pkt_len', 'bwd_max_pkt_len', 'fwd_num_bytes', 'bwd_num_bytes', 
                 'fwd_num_psh_flags', 'bwd_num_psh_flags',
                 'fwd_num_rst_flags', 'bwd_num_rst_flags', 'fwd_num_urg_flags', 'bwd_num_urg_flags'])

#feature_df['processed'] = False

#feature_row = feature_df.iloc[0,:].copy()
# process the TCP flows
print('\nProcessing TCP flows')
sibilings_counts = {}
delta_avg = {}
bi_flow_time = []

num_uniflows = len(meta_list)
for row_num in range(num_uniflows):
    current = meta_list[row_num]
    current_time = meta_list_time_0[row_num]
    if (current.processed == False):
        ip_src=current.ip_src
        ip_dst=current.ip_dst
        prt_src=current.prt_src
        prt_dst = current.prt_dst
        proto = current.proto
        # Get reverse tuple values
        rev_ip_src = ip_dst
        rev_ip_dst = ip_src
        rev_prt_src = prt_dst
        rev_prt_dst = prt_src
        for inner_row in range(row_num, num_uniflows):
            if (current.processed == True):
                continue;
                
            inner = meta_list[inner_row]
            inner_ip_src=inner.ip_src
            inner_ip_dst=inner.ip_dst
            inner_prt_src=inner.prt_src
            inner_prt_dst = inner.prt_dst
            inner_proto = inner.proto
            
            if (rev_ip_src == inner_ip_src) and (rev_ip_dst == inner_ip_dst) and (rev_prt_src == inner_prt_src) and (rev_prt_dst == inner_prt_dst) and (proto == inner_proto):
                # matching flow found!
                meta_list[row_num].processed = True
                meta_list[inner_row].processed = True
                
                biflowlist = [str(current_time)+'_'+current.ip_src, current.ip_src, current.ip_dst, current.prt_src, current.prt_dst, current.proto,
                                  current.num_pkts, inner.num_pkts, current.mean_iat, inner.mean_iat, current.std_iat,
                                  inner.std_iat, current.min_iat, inner.min_iat, current.max_iat, inner.max_iat,current.mean_offset, inner.mean_offset,
                                  current.mean_pkt_len, inner.mean_pkt_len, current.std_pkt_len, inner.std_pkt_len,
                                  current.min_pkt_len, inner.min_pkt_len, current.max_pkt_len, inner.max_pkt_len,
                                  current.num_bytes, inner.num_bytes, current.num_psh_flags, inner.num_psh_flags,
                                  current.num_rst_flags, inner.num_rst_flags, current.num_urg_flags, inner.num_urg_flags]
                columns_list=['sec_ip_src', 'ip_src', 'ip_dst', 'prt_src', 'prt_dst', 
                                                                                   'proto', 'fwd_num_pkts', 'bwd_num_pkts',
                                                                                   'fwd_mean_iat', 'bwd_mean_iat', 'fwd_std_iat', 
                                                                                   'bwd_std_iat', 'fwd_min_iat', 'bwd_min_iat',
                                                                                   'fwd_max_iat', 'bwd_max_iat', 'fwd_mean_offset', 'bwd_mean_offset', 'fwd_mean_pkt_len', 
                                                                                   'bwd_mean_pkt_len', 'fwd_std_pkt_len', 'bwd_std_pkt_len', 
                                                                                   'fwd_min_pkt_len', 'bwd_min_pkt_len', 
                                                                                   'fwd_max_pkt_len', 'bwd_max_pkt_len', 'fwd_num_bytes', 
                                                                                   'bwd_num_bytes', 'fwd_num_psh_flags', 'bwd_num_psh_flags',
                                                                                   'fwd_num_rst_flags', 'bwd_num_rst_flags', 'fwd_num_urg_flags', 
                                                                                   'bwd_num_urg_flags']
                                   
                df_biflow = df_biflow.append(pd.DataFrame([biflowlist], columns = columns_list), ignore_index=True, sort=False)
            else:
                continue
    else:
        continue

    

print('\nProcessing UDP flows')
# Process the UDP flows
for row_num in range(num_uniflows):
    current = meta_list[row_num]
    current_time = meta_list_time_0[row_num]
    if (current.processed == False):
        ip_src=current.ip_src
        ip_dst=current.ip_dst
        prt_src=current.prt_src
        prt_dst = current.prt_dst
        proto = current.proto
        # Get reverse tuple values
        rev_ip_src = ip_dst
        rev_ip_dst = ip_src
        rev_prt_src = prt_dst
        rev_prt_dst = prt_src
        if proto == 17:
            meta_list[row_num].processed = True
            # UDP flows have no reverse direction so i have filled the redundant fields with
            # dupicate forward direction data 
            biflowlist = [str(current_time)+'_'+current.ip_src,current.ip_src, current.ip_dst, current.prt_src, current.prt_dst, current.proto,
                          current.num_pkts, current.num_pkts, current.mean_iat, current.mean_iat, current.std_iat,
                          current.std_iat, current.min_iat, current.min_iat, current.max_iat, current.max_iat, current.mean_offset, current.mean_offset,
                          current.mean_pkt_len, current.mean_pkt_len, current.std_pkt_len, current.std_pkt_len,
                          current.min_pkt_len, current.min_pkt_len, current.max_pkt_len, current.max_pkt_len,
                          current.num_bytes, current.num_bytes, current.num_psh_flags, current.num_psh_flags,
                          current.num_rst_flags, current.num_rst_flags, current.num_urg_flags, current.num_urg_flags]
            columns_list=['sec_ip_src','ip_src', 'ip_dst', 'prt_src', 'prt_dst', 
                                                                                   'proto', 'fwd_num_pkts', 'bwd_num_pkts',
                                                                                   'fwd_mean_iat', 'bwd_mean_iat', 'fwd_std_iat', 
                                                                                   'bwd_std_iat', 'fwd_min_iat', 'bwd_min_iat',
                                                                                   'fwd_max_iat', 'bwd_max_iat','fwd_mean_offset', 'bwd_mean_offset','fwd_mean_pkt_len', 
                                                                                   'bwd_mean_pkt_len', 'fwd_std_pkt_len', 'bwd_std_pkt_len', 
                                                                                   'fwd_min_pkt_len', 'bwd_min_pkt_len', 
                                                                                   'fwd_max_pkt_len', 'bwd_max_pkt_len', 'fwd_num_bytes', 
                                                                                   'bwd_num_bytes', 'fwd_num_psh_flags', 'bwd_num_psh_flags',
                                                                                   'fwd_num_rst_flags', 'bwd_num_rst_flags', 'fwd_num_urg_flags', 
                                                                                   'bwd_num_urg_flags']   
                     
            df_biflow = df_biflow.append(pd.DataFrame([biflowlist], columns = columns_list), ignore_index=True, sort=False)
        else:
            continue



del pkt_num_list
del proto_list
del prt_dst_list
del prt_src_list
del tcp_psh_flag_list
del tcp_rst_flag_list
del time_list
del ip_dst_list
del ip_src_list
del ip_len_list
del tcp_urg_flag_list
del packet_df
del packet_dict
del meta_list
del flow_list
del flow_list_dict
if 'feature_df' in globals():
    del feature_df
    

# Now add flow-bundle data
# Add the numbe of flowws from each IP address and measure of the
# variability of destination port numbers that packets are sent to
# we will sort the port numbers in order then take the mean difference
# a value of 1 should indicate an incremental port scanner

print('Number of bi flows = {}'.format(np.size(df_biflow, axis = 0)))

df_biflow['num_src_flows'] = 0
df_biflow['src_ip_dst_prt_delta'] = 0

biflow_column = 'sec_ip_src'

if sliding_window == False:
    biflow_column = 'ip_src'

addr_dict = dict(df_biflow[biflow_column].value_counts())
print(addr_dict)
print('-------------')
print( dict(df_biflow['ip_src'].value_counts()))
print('\nComputing number of flows per source')
for key, value in addr_dict.items():
    df_biflow.loc[df_biflow[biflow_column] == key, 'num_src_flows'] = value
print('\nComputing number of port destinations per source')
for key, value in addr_dict.items():
    rows = df_biflow[df_biflow[biflow_column] == key]['prt_dst']
    l = list(rows)
    l.sort()
    ave_diff = 0
    if len(l) == 1:
        ave_diff = l[0]
    elif len(l) > 0:
        ave_diff = np.absolute(np.diff(l)).mean()
    df_biflow.loc[df_biflow[biflow_column] == key, 'src_ip_dst_prt_delta']= ave_diff



df_biflow.to_csv('biflow_' + output_file, sep=',') 



# normal.pcap has 3305 packets and 1719 unique flows

print('Parsing the file took {} seconds'.format(time.time() - start_time))