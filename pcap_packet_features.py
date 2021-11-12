#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 26 14:22:32 2019

@author: hananhindy
"""

import pyshark
import csv
import argparse
import traceback
import os

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')
        
validation_attributes = ['timestamp', 
                         'src_ip', 'dst_ip'
                         ]

attributes = ['protocol', 
              'ttl', 'ip_len', 
              'ip_flags', 
              'ip_flag_df', 'ip_flag_mf', 'ip_flag_rb',
              'src_port', 'dst_port', 
              'tcp_flags',
              'tcp_flag_res', 'tcp_flag_ns', 'tcp_flag_cwr', 'tcp_flag_ecn', 'tcp_flag_urg', 'tcp_flag_ack', 'tcp_flag_push', 'tcp_flag_reset', 'tcp_flag_syn', 'tcp_flag_fin',
              'mqtt_messagetype', 'mqtt_messagelength',
              'mqtt_flags',
              'mqtt_flag_uname', 'mqtt_flag_passwd', 'mqtt_flag_retain', 'mqtt_flag_qos', 'mqtt_flag_willflag', 'mqtt_flag_clean', 'mqtt_flag_reserved',
              'is_attack'
              ]


def extract_attributes(src, dst, attacker_ip, split_flags = False, include_validation_attributes = False):
    pcap = pyshark.FileCapture(src_file_name, keep_packets = False)

    first = True
    with open(dst_file_name, "a") as csv_file:
        for packet in pcap: 
            entry = {}
            if include_validation_attributes:
                for key in validation_attributes:
                    entry[key] = ''
                
            for key in attributes:
                if 'flag_' in key and split_flags == False:
                    continue
                entry[key] = ''
            
            try:
                entry['is_attack'] = 0
                if include_validation_attributes:
                    entry['timestamp'] = packet.sniff_time.strftime('%m/%d/%Y, %H:%M:%S:%f')
                    
                entry['protocol'] = packet.highest_layer        
                
                if 'ip' in packet:
                    if include_validation_attributes:
                        entry['src_ip'] = packet.ip.src
                        entry['dst_ip'] = packet.ip.dst
                    if packet.ip.src == attacker_ip or packet.ip.dst == attacker_ip:
                        entry['is_attack'] = 1
                        
                    entry['ttl'] = packet.ip.ttl
                    entry['ip_len'] = packet.ip.len
                    
                    if split_flags:
                        entry['ip_flag_df'] = packet.ip.flags_df
                        entry['ip_flag_mf'] = packet.ip.flags_mf
                        entry['ip_flag_rb'] = packet.ip.flags_rb
                    else:
                        entry['ip_flags'] = packet.ip.flags
                        
                if 'udp' in packet:
                    entry['src_port'] = packet.udp.srcport
                    entry['dst_port'] = packet.udp.dstport
                    
                elif 'tcp' in packet:
                    entry['src_port'] = packet.tcp.srcport
                    entry['dst_port'] = packet.tcp.dstport
                    
                    if split_flags:
                        entry['tcp_flag_res'] = packet.tcp.flags_res
                        entry['tcp_flag_ns'] = packet.tcp.flags_ns
                        entry['tcp_flag_cwr'] = packet.tcp.flags_cwr
                        entry['tcp_flag_ecn'] = packet.tcp.flags_ecn
                        entry['tcp_flag_urg'] = packet.tcp.flags_urg
                        entry['tcp_flag_ack'] = packet.tcp.flags_ack
                        entry['tcp_flag_push'] = packet.tcp.flags_push
                        entry['tcp_flag_reset'] = packet.tcp.flags_reset
                        entry['tcp_flag_syn'] = packet.tcp.flags_syn
                        entry['tcp_flag_fin'] = packet.tcp.flags_fin
                    else:
                        entry['tcp_flags'] = packet.tcp.flags
                else:
                    continue
                    
                if 'mqtt' in packet:
                    entry['mqtt_messagetype'] = packet.mqtt.msgtype
                    entry['mqtt_messagelength'] = packet.mqtt.len
                    
                    if 'conflags' in packet.mqtt.field_names:
                        if split_flags:
                            entry['mqtt_flag_uname'] = packet.mqtt.conflag_uname
                            entry['mqtt_flag_passwd'] = packet.mqtt.conflag_passwd
                            entry['mqtt_flag_retain'] = packet.mqtt.conflag_retain
                            entry['mqtt_flag_qos'] = packet.mqtt.conflag_qos
                            entry['mqtt_flag_willflag'] = packet.mqtt.conflag_willflag
                            entry['mqtt_flag_clean'] = packet.mqtt.conflag_cleansess
                            entry['mqtt_flag_reserved'] = packet.mqtt.conflag_reserved
                        else:
                            entry['mqtt_flags'] = packet.mqtt.conflags
                    
                
                writer = csv.DictWriter(csv_file, list(entry.keys()), delimiter=',')
                if first:
                    writer.writeheader()  
                    first = False
                        
                writer.writerow(entry) 
                
            except Exception:
                traceback.print_exc()
                break
        
    pcap.close()
        
            


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default = './')
    parser.add_argument('--split_flags', default = True, type = str2bool)
    parser.add_argument('--attacker_ip', default = '192.168.2.5')
    parser.add_argument('--include_validation_attributes', default = True, type = str2bool)
    
    args = parser.parse_args()
    root = args.root
    split_flags = args.split_flags
    attacker_ip = args.attacker_ip
    include_validation_attributes = args.include_validation_attributes
    
    for file in os.listdir(root):
        if file.endswith('.pcap'):
            
            src_file_name = os.path.join(root, file) 
            dst_file_name = src_file_name.replace('.pcap', '.csv')
            if os.path.isfile(dst_file_name) == False:
                print('Start processing: {}'.format(file))
                extract_attributes(src_file_name, dst_file_name, attacker_ip, split_flags, include_validation_attributes)
                print('End processing: {}'.format(file))
            