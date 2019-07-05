import re
import argparse
from pathlib import Path

import scapy.all as scapy

import yaml

def crawl(packet, f):
    if isinstance(packet, scapy.NoPayload) or packet is None:
        return
    
    for field in type(packet).fields_desc:
        f(packet.getfieldval(field.name))

    crawl(packet.payload, f)

ipv4_regex = re.compile(r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
ipv6_regex = re.compile(
    r'('
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
    def ip_detector(self,x):
        if isinstance(x, str):
            self.ips += ip_in_str(x)
        elif isinstance(x, bytes):
            self.ips += ip_in_bytes(x)

def ip_scrape(pcap, outfile):
    pcap=str(pcap)
    ipd = IPDetector()

    packets = scapy.PcapReader(pcap)

    packet = packets.read_packet() # read next packet
    while (packet): # empty packet == None
        crawl(packet, ipd.ip_detector)
        packet = packets.read_packet() # read next packet
    packets.close()

    output = {
        'ip' : list(set(ipd.ips))
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
