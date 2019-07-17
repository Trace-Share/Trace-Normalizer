import scapy.all as scapy

import TMLib.ReWrapper as ReWrapper
import TMLib.utils.utils as MUtil
import TMLib.TMdict as TMdict

import TMLib.Definitions as TMdef

import TMLib.SubMng as TMm

import TMLib.subscribers.normalizers

import sys
import ipaddress
import argparse
from pathlib import Path

import yaml

#######
###  Normalizer funcs
########

def parse_config(config_path):
    """
    Parses config into a dictionary, no format checking.

    :param config_path: path to config file
    """
    if config_path.suffix[-1] == 'n': ## naive check for json by last letter
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
    #TCP
    , 'tcp_auto_checksum'
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
    """
    Execute validation functions

    :param param_dict: parsed config
    :type param_dict: dict
    :param rewrap: rewrapper
    :type rewrap: ReWrapper
    :param fill: filling functions
    :type fill: List[Callable]
    :param validate: validation functions
    :type validate: List[Callable]
    """
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
    pkt_end=0
    pkt_ts=[]
    if readwrite == 'bulk':
        ## read all packets
        packets = scapy.rdpcap(pcap)
        res_packets = []

        ## timestamp shift based on first packet and input param
        rewrap.set_timestamp_shift(timestamp_next_pkt - packets[0].time)

        ## rewrapp packets
        for packet in packets:
            try:
                rewrap.digest(packet, recursive=True)
            except Exception as e:
                print('Error while digesting packet num {}'.format(pkt_num))
                raise e
            res_packets.append(packet)
            pkt_num+=1

        pkt_num = len(res_packets)
        pkt_end = res_packets[-1].time
        pkt_ts = [i.time for i in res_packets]
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
        pkt_ts = []
        while (packet): # empty packet == None
            tmp_l[0] = packet # store current packet for writing 
            try:
                if pkt_num == 0: # first packet
                    rewrap.set_timestamp_shift(timestamp_next_pkt - packet.time)
                    rewrap.digest(packet, recursive=True)
                    ## Create new pcap
                    scapy.wrpcap(res_path, packet)
                else:
                    rewrap.digest(packet, recursive=True)
                    ## Apend to existing pcap
                    scapy.wrpcap(res_path, packet, append=True)
            except Exception as e:
                print('Error while digesting packet num {}'.format(pkt_num))
                raise e
            pkt_num += 1
            pkt_end = packet.time
            pkt_ts.append(pkt_end)
            packet = packets.read_packet() # read next packet
    
    return {
        'packets.count' : pkt_num
        , 'packets.start' : 0
        , 'packets.end' : pkt_end
        # , 'packets.timestamps' : pkt_ts
    }

####
## Config gen
####

class IPSpace(object):
    def __init__(self, ipv4, ipv6):
        self.ipv4 = ipv4
        self.ipv6 = ipv6
    def get_next(self, adr):
        ip = ipaddress.ip_address(adr)
        if ip.version == 4:
            return self.ipv4.get_next()
        return self.ipv6.get_next()


class IPv4Space(object):
    """
    Generator of IPv4 space.
    """
    def __init__(self, block, _from, _to):
        self._from = _from
        self.to = _to

        self.rng = [block, _from, 0 ,2 ]

    def get_next(self):
        """
        Generates new IP address within space. Raises ValueError if no more IPv4 addresses can be generated.
        """
        r = '{}.{}.{}.{}'.format(
            str(self.rng[0])
            , str(self.rng[1])
            , str(self.rng[2])
            , str(self.rng[3])
            )
        c = 1
        for i in range(3, 0,-1):
            self.rng[i], c = _carry(self.rng[i], c, 256)
        if self.rng[1] > self.to or self.rng[1] < self._from:
            raise ValueError('IP range exceeded')
        return r 

def to_hex(i,l=4):
    a = hex(i).replace('0x', '')
    return '0'*(l-len(a))+a
## Use https://tools.ietf.org/html/rfc3849  2001:DB8::/32
class IPv6Space(object):
    """
    Generator of IPv6 space
    """
    mod = int('ffff', 16)+1 ## modulo for single ip block
    def __init__(self, block:str, _from, _to):
        self.block=block
        self._from=_from
        self.to=_to
        self.rng = [_from] + [0 for _ in range( 7 - len(block.split(':')) )]
        self.len = len(self.rng)
    def get_next(self):
        """
        Generates new IP Address within space. Raises ValueError if no more IPv6 addresses can be genrated.
        """
        r = self.block + ":" + ':'.join([to_hex(i) for i in self.rng])
        r = str(ipaddress.ip_address(r))

        c = 1
        for i in range(self.len-1, 0,-1):
            self.rng[i], c = _carry(self.rng[i], c, self.mod)
        if self.rng[0] > self.to or self._from > self.rng[0]:
            raise ValueError('MAC range exceeded')
        return r


def _carry(a, b, m):
    """
    Add with carry

    :return: (a+b)%m, 1 or 0
    """
    a += b
    return a%m, a==m

def build_mac_categories(macs, ips):
    """
    Creates dictionary splitting mac addresses into categories based on IPs
    {
        source : []
        , intermediate : []
        , destination : []
    }
    :param macs: mac.associations entry
    :param ips: ip.groups entry
    :return: dictionary similliar to ip.group, for mac addresses
    """
    _ip_map = {}
    for key, val in ips.items():
        for ip in val:
            _ip_map[ip] = key
    _cfg = {
        'source' : []
        , 'intermediate' : []
        , 'destination' : []
    }
    intermediate_set= set('intermediate')
    for asssociation in macs:
        _a = set()
        for i in asssociation['ips']:
            if ip_isException(i):
                continue
            _a.add(_ip_map[i])
        if len(_a) != 1:
            ## is it illegal for both to be in?
            ## For now, drop intermediate
            if 'source' in _a and 'destination' in _a:
                raise ValueError('{} belogs to both source and destination!'.format(asssociation['mac']))
            _a = _a.difference(intermediate_set)
        _cfg[_a.pop()].append(asssociation['mac'])
    return _cfg
            
def mac_isException(adr):
    return adr == '00:00:00:00:00:00' or adr == 'ff:ff:ff:ff:ff:ff'

def ip_isException(adr):
    return adr == '0.0.0.0' or adr == '::'

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
    # _blocks = [(255*i)//len(_cfg.keys()) for i in range(1, len(_cfg.keys())+1, 1) ]
    ips = {
        'source' : IPSpace(IPv4Space(240, 0, 84), IPv6Space( '2001:DB8', 0, 21845-1))
        , 'intermediate' : IPSpace(IPv4Space(240, 85, 169), IPv6Space( '2001:DB8', 21845, 43690-1))
        , 'destination' : IPSpace(IPv4Space(240, 170, 255), IPv6Space( '2001:DB8', 43690, 65535))
    }
    ##
    ## Build up ip.map
    ##
    _ip_cfg = _cfg.get('ip.groups')
    _map = []
    for key, val in _ip_cfg.items():
        ip = ips[key]
        for adr in val:
            if ip_isException(adr):
                new_adr = adr
            else:
                new_adr = ip.get_next(adr)
            _map.append(
                {
                    'ip' : {
                        'old' : adr
                        , 'new' : new_adr
                    }
                }
            )
    ##
    ## Build up Mac map
    ##
    macs = TMLib.subscribers.normalizers.macs
    _mac_cfg = build_mac_categories(_cfg.get('mac.associations'), _ip_cfg )
    _mac_map = []
    for key, val in _mac_cfg.items():
        mac = macs[key]
        for adr in val:
            if mac_isException(adr):
                new_adr = adr
            else:
                new_adr = mac.get_next(adr)
            _mac_map.append(
                {
                    'mac' : {
                        'old' : adr
                        , 'new' : new_adr
                    }
                }
            ) 
    
    rev = {}
    for key, val in _ip_cfg.items():
        for adr in val:
            rev[adr] = key
    return {'ip.map' : _map, 'ip.norm' : rev, 'mac.map' : _mac_map}, _cfg

def label(_cfg, glob_dict, rewrap):
    """
    Writes labels into yaml file

    :param _cfg: parsed input configuration file
    :param glob_dict: global data dict
    :param rewrap: dict of packet info generated during rewrapping
    """
    r = {}
    for key,val in _cfg['ip.groups'].items():
        r[key] = []
        for adr in val:
            new_adr = glob_dict[TMdef.TARGET]['ip_address_map'][adr]
            r[key].append(new_adr)
    lbl = {
        'ip' :
            {
                'ip.source' : r['source']
                , 'ip.intermediate' : r['intermediate']
                , 'ip.destination' : r['destination']
            }
        , 'packets' : rewrap    
    }
    return lbl

    

def normalize(config_path:Path, pcap:str, res_path:str, label_path:Path):
    """
    1. Parse config as Yaml (or json)

    2. Generate rewrapper config (FILL functions of transformation functions have predefined keys
    they look for in configs) from normalizer config.
    !2. Uses config to precalculate MAC address associations.
    !2. New IPs and their associations for labels can be collected here.

    3. Build rewrapper and fill up data dicts.
    !3. Uses functiosn found under TMLib.subscribers.normalizers

    4. Normalize (rewrapp) config.
    !4. Timestamps, timestamp count, end/start timestamp labels can be collected here

    5. Generate labels
    """

    timestamp_next_pkt = 0
    
    ###
    ### Parsing 
    ###

    param_dict, _cfg = generate_config(config_path)

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

    rw = rewrapping(pcap, res_path, param_dict, rewrap, timestamp_next_pkt)  

    ###
    ### Generating labels
    ### 

    lbs = label(_cfg, rewrap.data_dict[TMdef.GLOBAL], rw)
    with label_path.open('w') as ff:
        yaml.dump(lbs, ff)
    


if __name__ == '__main__':
    # print(generate_config(r'D:\Untitled-1.yaml'))
    # normalize(config_path = sys.argv[1], pcap=sys.argv[2], res_path=sys.argv[3])

    description = "TODO"

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-c', '--configuration', help='Path to a Json or Yaml configuration file.'
    , type=Path, required=True)
    parser.add_argument('-p', '--pcap', help='Path to a PCAP file.', type=Path, required=True)
    parser.add_argument('-o', '--output', help='Path to output PCAP file (creates or overwrites), or output directory (new filename will be "normalized_<pcap name>").'
    , type=Path, required=False, default=Path('.'))
    parser.add_argument('-l', '--label_output', help='Path to output labels (creates or overwrites).',
    type=Path, required=False, default=None)

    args = parser.parse_args()

    if args.output.is_dir():
        args.output = args.output / Path('normalized_{}'.format(args.pcap.name))

    if args.label_output is None:
        args.label_output = args.output.parent / Path(args.output.stem + '.yaml')

    normalize(args.configuration, str(args.pcap), str(args.output), args.label_output)


