import re
import argparse
from pathlib import Path

import scapy.all as scapy

import yaml

def crawl(packet, f, pnum):
    if isinstance(packet, scapy.NoPayload) or packet is None:
        return
    
    for field in type(packet).fields_desc:
        f(packet, packet.getfieldval(field.name), pnum=pnum)

    crawl(packet.payload, f, pnum)

ipv4_regex = re.compile(r'(?:(?:\D|^)((?:(?:25[0-5]|2[0-4][0-9]|[1]?[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[1]?[1-9]?[0-9]))[^0-9]*(?:\D|$))')
ipv6_regex = re.compile(
    r'('
    r'(?:[^0-9-a-fA-F\w:]||^)'
    r'(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'          # 1:2:3:4:5:6:7:8
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'                         # 1::                              1:2:3:4:5:6:7::
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
    r'[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|'       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8  
    r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|'                     # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::     
    r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'     # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}'
    r'(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'(?:[0-9a-fA-F]{1,4}:){1,4}:'
    r'(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
    r'(?:[^0-9-a-fA-F\w:]|$)'
    r')'
)

regexes = [ipv4_regex, ipv6_regex]

def ip_in_str(x):
    found = []
    for r in regexes:
        found += r.findall(x)
    return found

encodings=['ascii', 'utf-8', 'utf-16', 'utf-32']
def ip_in_bytes(x):
    found = []
    for encoding in encodings:
        try:
            s = x.decode(encoding)
            found += ip_in_str(s)
        except:
            continue
    return found

class IPDetector(object):
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
        if self.layer_counter==1:
            self.had_IP = self.had_IP or isinstance(packet, scapy.IP) or isinstance(packet, scapy.IPv6)
        elif self.layer_counter==0:
            if isinstance(packet, scapy.Ether):
                self.tmp_macs.append(packet.getfieldval('src'))
                self.tmp_macs.append(packet.getfieldval('dst'))


    def ip_detector(self,x, packet, pnum):
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
        

def ip_scrape(pcap, outfile):
    pcap=str(pcap)
    ipd = IPDetector()

    packets = scapy.PcapReader(pcap)

    packet = packets.read_packet() # read next packet
    pnum=0
    while (packet): # empty packet == None
        crawl(packet, ipd, pnum=pnum)
        packet = packets.read_packet() # read next packet
        ipd.next()
        pnum+=1
    packets.close()

    ipd.ips = ipd.ip_protocol_map.keys()
    output = {
        'ip' : list(set(ipd.ips))
        , 'ip.searched_protocols' : { key: list(val) for key,val in ipd.ip_protocol_map.items() }
        , 'ip.occurrences' : ipd.ip_pktnum_map
        , 'mac.orphaned' : list(set(ipd.orphaned_mac)) 
    }

    with outfile.open('w') as ff:
        yaml.dump(output, ff)

if __name__ == '__main__':
    description = "TODO"

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-p', '--pcap', help='Path to input PCAP file.'
    , type=Path, required=True)
    parser.add_argument('-o', '--output', help='Path to output IP yaml (creates or overwrites).',
    type=Path, required=True)

    args = parser.parse_args()
    ip_scrape(args.pcap, args.output)
