import scapy.all as scapy

import TMLib.ReWrapper as ReWrapper
import TMLib.Utility as MUtil
import TMLib.TMdict as TMdict

import TMLib.Definitions as TMdef

import TMLib.TMmanager as TMm

def parse_config(config_path):
    """
    Parses config into a dictionary, no format checking.

    :param config_path: path to config file
    """
    if config_path[-1] == 'n': ## naive check for json by last letter
        param_dict = MUtil.parse_json_args(config_path)
    else:
        param_dict = MUtil.parse_yaml_args(config_path)
    return param_dict

def build_rewrapper(attack, param_dict):
    """
    Fill dictinaries with data from config.

    :param attack: Mix attack.
    :param param_dict: parsed config
    :return: rewrapper
    """

    ## statistics stored in global dict under the keys
    global_dict = TMdict.GlobalRWdict(statistics = {}, attack_statistics = {})
    packet_dict = TMdict.PacketDataRWdict()
    conversation_dict = TMdict.ConversationRWdict()
    ## dicts stored in a dict under param data_dict under keys from TMdef
    rewrap = ReWrapper.ReWrapper({}, global_dict, conversation_dict, packet_dict)

    return rewrap


def enqueue_functions(param_dict, rewrap):
    """
    Enqueue transformation functions and timestamp generation.

    :param param_dict: parsed config file dict
    :param rewrap: Rewrapper
    """
    ## check for timestamp generation section
    fill = set()
    config_validate = set()

    TMm.change_timestamp_function(rewrap, 'timestamp_shift')

    functions = [
    # Ether
    'mac_change_default'
    # ARP
    , 'arp_change_default'
    # IPv4 & IPv6
    , 'ip_src_change'
    , 'ip_dst_change'
    , 'ipv6_src_change'
    , 'ipv6_dst_change'
    , 'ip_auto_checksum'
    # ICMP
    , 'icmp_ip_src_change'
    , 'icmp_ip_dst_change'
    # DNS
    , 'dns_change_ips'
    # HTTP
    , 'httpv1_regex_ip_swap'
    ]

    for f in functions:
        _f, _c_v = TMm.enqueue_function(rewrap, f)
        fill.update(_f)
        config_validate.update(_c_v)

    return fill, config_validate

def validate_and_fill_dict(param_dict, rewrap, fill, validate):
    valid = True
    data = rewrap.data_dict
    for f in validate:
        valid &= f(param_dict)
    ## ignored for now
    if not valid:
        print('[WARNING] Invalid config')

    data = rewrap.data_dict
    for f in fill:
        f(data, param_dict)

def rewrapping(pcap, res_path, param_dict, rewrap, timestamp_next_pkt):
    """
    Parsing and rewrapping (and writing) of attack pcap.

    :param attack: Mix
    :param param_dict: parsed config, dict
    :param rewrap: Rewrapper
    """
    ## check for readwrite mode
    rw = param_dict.get('read.write')
    if rw:
        readwrite = rw
    else: ## default
        readwrite = 'sequence'

    ## read & write all at once
    pkt_num=0
    if readwrite == 'bulk':
        ## read all packets
        packets = scapy.utils.rdpcap(pcap)
        res_packets = []

        ## timestamp shift based on first packet and input param
        rewrap.set_timestamp_shift(timestamp_next_pkt - packets[0].time)

        ## rewrapp packets
        for packet in packets:
            rewrap.digest(packet)
            res_packets.append(packet)

        pkt_num = len(attack.packets)
        scapy.wrpcap(res_path, res_packets)

    ## read & write packet by packet
    elif readwrite == 'sequence':
        ## create packet reader
        packets = scapy.PcapReader(pcap)

        ## temporary list, avoid recreating lists for writing
        tmp_l = [0]

        attack.pkt_num = 0

        packet = packets.read_packet() # read next packet

        pktdump = None
        while (packet): # empty packet == None
            tmp_l[0] = packet # store current packet for writing 

            if attack.pkt_num == 0: # first packet
                rewrap.set_timestamp_shift(timestamp_next_pkt - packet.time)
                rewrap.digest(packet)
                ## Create new pcap
                scapy.wrpcap(res_path, packet)
            else:
                rewrap.digest(packet)
                attack.attack_end_utime = packet.time
                ## Apend to existing pcap
                scapy.wrpcap(res_path, packet, append=True)

            pkt_num += 1
            packet = packets.read_packet() # read next packet

def normalize(config_path, pcap, res_path):
    timestamp_next_pkt = 0
    
    ###
    ### Parsing 
    ###

    param_dict = parse_config(config_path)

    ###
    ### Filling dictionaries
    ###

    rewrap = build_rewrapper(param_dict)

    ###
    ### Queuing functions
    ###

    fill, config_validate = enqueue_functions(param_dict, rewrap)

    ###
    ### Queuing functions
    ###
    
    validate_and_fill_dict(param_dict, rewrap, fill, config_validate)

    ###
    ### Recalculating dictionaries 
    ###

    rewrap.recalculate_global_dict()

    ###
    ### Reading & rewrapping 
    ###

    rewrapping(pcap, res_path, param_dict, rewrap, timestamp_next_pkt)    

if __name__ == '__main__':
    pass
