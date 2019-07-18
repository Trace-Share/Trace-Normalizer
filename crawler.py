#!/usr/bin/env python3

import re
import argparse
from pathlib import Path

import scapy.all as scapy

import yaml

def mac_isException(adr):
    return adr == '00:00:00:00:00:00' or adr == 'ff:ff:ff:ff:ff:ff'

def ip_isException(adr):
    return adr == '0.0.0.0' or adr == '::'

def crawl(packet, f, pnum):
    """
    Function that iterates over packet fields and applies input function
    :param packet: packet
    :param f: function
    :param pnum: number of the packet
    """
    if isinstance(packet, scapy.NoPayload) or packet is None:
        return
    
    for field in type(packet).fields_desc:
        f(packet, packet.getfieldval(field.name), pnum=pnum)

    crawl(packet.payload, f, pnum)

ipv4_regex = re.compile(r'(?:(?:\D|^)((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))[^0-9]*(?:\D|$))')
ipv6_regex = re.compile(
    r'('
    r'(?:[^0-9-a-fA-F\w:]||^)' # SKipp if it looks like part of a word
    r'(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'          # 1:2:3:4:5:6:7:8
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'                         # 1::                              1:2:3:4:5:6:7::
    r'[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|'       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8  
    r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|'                     # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::     
    r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'     # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}'
    r'(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'(?:[0-9a-fA-F]{1,4}:){1,4}:'
    r'(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
    r'(?:[^0-9-a-fA-F\w:]|$)' # Skip if it looks like part of a word
    r')'
)

regexes = [ipv4_regex, ipv6_regex]

def ip_in_str(x):
    """
    Finds ip address in the string

    :param x: field value
    """
    found = []
    for r in regexes:
        found += r.findall(x)
    return found

encodings=['ascii', 'utf-8', 'utf-16', 'utf-32']
def ip_in_bytes(x):
    """
    Finds ip address in bytes by converting the field to string

    :param x: field value
    """
    found = []
    for encoding in encodings:
        try:
            s = x.decode(encoding)
            found += ip_in_str(s)
        except:
            continue
    return found

mac_regex = re.compile(r'')

class MacAssociations:
    """
    Class that searches for mac-ip associations.

    :ivar mac_ip_map: mapping of mac to ip addresses
    """
    arp_fields = [
        ('hwsrc', 'psrc')
        , ('hwdst', 'pdst')
    ]

    def __init__(self):
        self.mac_ip_map = {}
        self.local = {}
    
    def __call__(self, packet, x, pnum):
        """
        Crawling function
        """
        self.ip_in_mac(packet)
        self.ip_in_arp(packet)
    
    def ip_in_mac(self, packet):
        """
        IP matching for Ether and IPv4/IPv6 protocol
        """
        if isinstance(packet, scapy.Ether):
            ## If Ether packet, Record the mac address
            _mac = packet.getfieldval('src')
            self.local['src'] = _mac
            entry:set = self.mac_ip_map.get(_mac)
            if entry is None:
                entry = set()
                self.mac_ip_map[_mac] = entry
            
            _mac = packet.getfieldval('dst')
            self.local['dst'] = _mac
            entry:set = self.mac_ip_map.get(_mac)
            if entry is None:
                entry = set()
                self.mac_ip_map[_mac] = entry

        elif isinstance(packet, scapy.IP) or isinstance(packet, scapy.IPv6):
            ## IF IP, associate IP address with Mac address
            _ip = packet.getfieldval('src')
            _mac = self.local.get('src')
            if _ip is not None and _mac is not None:
                entry:set = self.mac_ip_map.get(_mac)
                entry.add(_ip)

            _ip = packet.getfieldval('dst')
            _mac = self.local.get('dst')
            if _ip is not None and _mac is not None:
                entry:set = self.mac_ip_map.get(_mac)
                entry.add(_ip)

                    
    def ip_in_arp(self, packet):
        """
        Looks for association in ARP packet.
        Associates based on linked hardware and protocol fields.

        :param packet:
        """
        def _it(packet, ha, pa):
            ha_val = packet.getfieldval(ha)
            pa_val = packet.getfieldval(pa)
            if ha_val is not None:
                entry:set = self.mac_ip_map.get(ha_val)
                if entry is None:
                    entry = set()
                    self.mac_ip_map[ha_val] = entry
                if pa_val is not None:
                    entry.add(pa_val)
        if not isinstance(packet, scapy.ARP):
            return
        for hw, p in self.arp_fields:
            _it(packet, hw, p)
                
    def mac_detector(self, x):
        pass

    def next(self):
        """
        Announces end of packet
        """
        self.local.clear()

class IPDetector(object):
    """
    Crawling class for IP address lookup based on regex
    """
    def __init__(self):
        self.ips = []
        self.orphaned_mac = []
        self.had_IP = False
        self.tmp_macs = []
        self.layer_counter=0
        self.found_macs=set()
        self.ip_protocol_map={}
        self.ip_pktnum_map={}
    
    def __call__(self, packet, x, pnum):
        self.ip_detector(x,packet, pnum)
        self.ip_layer_detector(packet)
        self.layer_counter += 1

    def ip_layer_detector(self, packet):
        """
        Applies if IP layer was present. Legacy mac search.

        :param packet:
        """
        if self.layer_counter==1:
            self.had_IP = self.had_IP or isinstance(packet, scapy.IP) or isinstance(packet, scapy.IPv6)
        elif self.layer_counter==0:
            if isinstance(packet, scapy.Ether):
                self.tmp_macs.append(packet.getfieldval('src'))
                self.tmp_macs.append(packet.getfieldval('dst'))


    def ip_detector(self,x, packet, pnum):
        """
        Searches for ip address. Records first occurance, number of packets and protocol

        :param x: field val
        :param packet: packet
        :param pnum: packet number
        """
        q=[]
        if isinstance(x, str):
            q += ip_in_str(x)
        elif isinstance(x, bytes):
            q += ip_in_bytes(x)
        if len(q) > 0:
            for i in q:
                ip_p:set = self.ip_protocol_map.get(i)
                if ip_p is None:
                    ip_p=set()
                    self.ip_protocol_map[i]=ip_p
                ip_p.add(str(type(packet)))
                ip_c:dict = self.ip_pktnum_map.get(i)
                if ip_c is None:
                    ip_c={'first_observed':pnum, 'count':0}
                    self.ip_pktnum_map[i]=ip_c
                ip_c['count'] += 1
                
    def next(self):
        """
        Announces end of packet.
        """
        if not self.had_IP:
            for i in self.tmp_macs:
                if i not in self.found_macs:
                    self.orphaned_mac.append(i)
        else:
            for i in self.tmp_macs:
                self.found_macs.add(i)
        self.had_IP=False
        self.tmp_macs=[]
        self.layer_counter=0

class Bush(object):
    """
    Hides multiple crawl classes within it
    """
    def __init__(self):
        self.fs=[]
    def __call__(self, packet, x, pnum):
        for f in self.fs:
            f(packet, x, pnum)  
    def next(self):
        for f in self.fs:
            f.next()      

ignored_macs = ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']
ignored_ips = ['0.0.0.0', '::']

def ip_scrape(pcap, outfile):
    """
    Scrapes pcap and outputs data in yaml format

    :param pcap: path to pcap
    :type pcap: Path
    :param outfile: path to output yaml
    :type outfile: Path
    """
    pcap=str(pcap)
    ## Build up crawlers
    ipd = IPDetector()
    mpd = MacAssociations()
    _George = Bush() 
    _George.fs += [ipd, mpd] ## Crawlers like to hide in bushes

    packets = scapy.PcapReader(pcap)

    packet = packets.read_packet() # read next packet
    pnum=0
    while (packet): # empty packet == None
        crawl(packet, _George, pnum=pnum) ## Crawl
        packet = packets.read_packet() # read next packet
        _George.next() ## cleanup
        pnum+=1
    packets.close()

    ## Filter the ignored addresses
    for m in ignored_macs:
        mpd.mac_ip_map.pop(m, None)
    for i in ignored_ips:
        ipd.ip_protocol_map.pop(i, None)

    ## Build up output
    ipd.ips = list(ipd.ip_protocol_map.keys()) ## keys are set of all ips
    output = {
        'ip.groups' : {
            'source' : []
            ,'intermediate' : ipd.ips
            , 'destination' : []
        }
        , 'ip.searched_protocols' : [ {'ip':key, 'protocols':list(val)} for key,val in ipd.ip_protocol_map.items() ]
        #### Black magic to move key from {key:value} into into value
        , 'ip.occurrences' : [val for key, val in  ipd.ip_pktnum_map.items() if (lambda x,y : x.update(ip=y))(val, key) is None ]
        , 'mac.associations' : [{'mac' : key, 'ips' : list(val)} for key, val in mpd.mac_ip_map.items()]
        # , 'mac.orphaned' : list(set(ipd.orphaned_mac)) 
    }

    with outfile.open('w') as ff:
        yaml.dump(output, ff)

if __name__ == '__main__':
    description = "TODO"

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-p', '--pcap', help='Path to input PCAP file.'
    , type=Path, required=True)
    parser.add_argument('-o', '--output', help='Path to output IP yaml (creates or overwrites).',
    type=Path, required=False, default=None)

    args = parser.parse_args()

    if args.output is None:
        args.output = args.pcap.parent
    if args.output.is_dir():
        args.output = args.output / Path(args.pcap.stem + '.yaml')

    ip_scrape(args.pcap, args.output)
