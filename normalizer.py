import scapy.all as scapy

import TMLib.ReWrapper as ReWrapper
import TMLib.utils.utils as MUtil
import TMLib.TMdict as TMdict

import TMLib.Definitions as TMdef

import TMLib.SubMng as TMm

import TMLib.subscribers.normalizers

import sys

import argparse
from pathlib import Path

#######
###  Normalizer funcs
########

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

def build_rewrapper(param_dict):
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
    rewrap = ReWrapper.ReWrapper({}, global_dict, conversation_dict, packet_dict, scapy.NoPayload)

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
    readwrite=None
    rw = param_dict.get('read.write')
    if rw:
        readwrite = rw
    else: ## default
        readwrite = 'sequence'

    ## read & write all at once
    pkt_num=0
    if readwrite == 'bulk':
        ## read all packets
        packets = scapy.rdpcap(pcap)
        res_packets = []

        ## timestamp shift based on first packet and input param
        rewrap.set_timestamp_shift(timestamp_next_pkt - packets[0].time)

        ## rewrapp packets
        for packet in packets:
            rewrap.digest(packet, recursive=True)
            res_packets.append(packet)

        pkt_num = len(res_packets)
        scapy.wrpcap(res_path, res_packets)

    ## read & write packet by packet
    elif readwrite == 'sequence':
        ## create packet reader
        packets = scapy.PcapReader(pcap)

        ## temporary list, avoid recreating lists for writing
        tmp_l = [0]

        pkt_num = 0

        packet = packets.read_packet() # read next packet

        pktdump = None
        while (packet): # empty packet == None
            tmp_l[0] = packet # store current packet for writing 

            if pkt_num == 0: # first packet
                rewrap.set_timestamp_shift(timestamp_next_pkt - packet.time)
                rewrap.digest(packet, recursive=True)
                ## Create new pcap
                scapy.wrpcap(res_path, packet)
            else:
                rewrap.digest(packet, recursive=True)
                ## Apend to existing pcap
                scapy.wrpcap(res_path, packet, append=True)

            pkt_num += 1
            packet = packets.read_packet() # read next packet

####
## Config gen
####

class IPv4Space(object):
    def __init__(self, block, _from, _to):
        self.to = _to

        self.rng = [block, _from, 0 ,0 ]

    def get_next(self):
        r = '{}.{}.{}.{}'.format(
            str(self.rng[0])
            , str(self.rng[1])
            , str(self.rng[2])
            , str(self.rng[3])
            )
        c = 1
        for i in range(3, 0,-1):
            self.rng[i], c = _carry(self.rng[i], c, 256)
        if self.rng[1] > self.to:
            raise ValueError('IP range exceeded')
        return r 
                   
# class MacSpace(object):
#     def __init__(self, block, _from, _to, preserve_prefix=True):
#         self.prefix=preserve_prefix
#         self.to = _to

#         if self.prefix:
#             self.rng = [_from, 0 ,0]
#         else:
#             self.rng = [_from, 0, 0, 0, 0, 0]

#     def get_next(self, addr):
#         if self.prefix:
#             r = addr[0:4] + self.rng
#         else:
#             r = self.rng
#         r = [str(i) for i in r].join('.')
#         c = 1
#         adr_len = 6
#         if self.prefix:
#             adr_len = 3
#         for i in range(adr_len-1, 0,-1):
#             self.rng[i], c = _carry(self.rng[i], c, 256)
#         if self.rng[1] > self.to:
#             raise ValueError('MAC range exceeded')
#         return r 


def _carry(a, b, m):
    a += b
    return a%m, a==m

def generate_config(cfg_path):
    """
    Generate rewrapper config based on IP map.

    Limited to a single B block 240.0.0.0

    ip map = {
        source : []
        , intermediate : []
        , destination : []
    }
    """
    _cfg = parse_config(cfg_path)
    _blocks = [(255*i)//len(_cfg.keys()) for i in range(1, len(_cfg.keys())+1, 1) ]
    ips = {
        'source' : IPv4Space(240, 0, _blocks[0])
        , 'intermediate' : IPv4Space(240, _blocks[0], _blocks[1])
        , 'destination' : IPv4Space(240, _blocks[1], _blocks[2])
    }
    # _ip_cfg = _cfg.get('ip')
    _map = []
    for key, val in _cfg.items():
        ip = ips[key]
        for adr in val:
            _map.append(
                {
                    'ip' : {
                        'old' : adr
                        , 'new' : ip.get_next()
                    }
                }
            ) 
    # _mac_cfg = _cfg.get('mac')
    # _mac = []
    # add mac gen
    # for key, val in _mac_cfg.items():
    #     ip = ips[key]
    #     for adr in val:
    #         _mac.append(
    #             {
    #                 'ip' : {
    #                     'old' : adr
    #                     , 'new' : ip.get_next()
    #                 }
    #             }
    #         ) 

    rev = {}
    for key, val in _cfg.items():
        for adr in val:
            rev[adr] = key
    return {'ip.map' : _map, 'ip.norm' : rev}


    

def normalize(config_path, pcap, res_path):

    timestamp_next_pkt = 0
    
    ###
    ### Parsing 
    ###

    param_dict = generate_config(config_path)

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
    # print(generate_config(r'D:\Untitled-1.yaml'))
    # normalize(config_path = sys.argv[1], pcap=sys.argv[2], res_path=sys.argv[3])

    description = "TODO"

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-c', '--configuration', help='Path to a Json or Yaml configuration file.'
    , type=Path, required=True)
    parser.add_argument('-p', '--pcap', help='Path to a PCAP file.', type=Path, required=True)
    parser.add_argument('-o', '--output', help='Path to output PCAP file (creates or overwrites).'
    , type=Path, required=True)

    args = parser.parse_args()
    normalize(args.configuration, args.pcap, args.output)


