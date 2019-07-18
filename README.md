# Trace-Share: Trace-Normalizer

[![Build Status](https://travis-ci.org/Trace-Share/Trace-Normalizer.svg?branch=master)](https://travis-ci.org/Trace-Share/Trace-Normalizer)

Toolset for normalization of network traffic traces.

### Table of Contents

- [Trace-Share: Trace-Normalizer](#Trace-Share-Trace-Normalizer)
    - [Table of Contents](#Table-of-Contents)
  - [Description](#Description)
  - [Requirements](#Requirements)
  - [Usage](#Usage)
    - [Crawler](#Crawler)
    - [Normalizer](#Normalizer)
  - [Contribution](#Contribution)


## Description

Trace-Normalizer is a toolset for normalization of network traffic traces to ease their further sharing, manipulation, and injection into the background traffic. The normalization consists of **IP and MAC addresses replacement** to reserved blocks, and **shifting capture time** to zero epoch time. After the normalization, the capture can be annotated and provided as an annotated unit.

IP addresses are divided into the following reserved blocks according to role of the corresponding host:
* **source:** <240.0.0.2, 240.84.255.254> / <2001:db8::, 2001:DB8:5554:ffff:ffff:ffff:ffff:ffff>
* **intermediate:** <240.85.0.2, 240.169.255.254> / <2001:DB8:5555::, 2001:DB8:aaa9:ffff:ffff:ffff:ffff:ffff>
* **destination:** <240.170.0.2, 240.255.255.254> / <2001:DB8:aaaa::, 2001:DB8:ffff:ffff:ffff:ffff:ffff:ffff>

Similarly, MAC addresses are split based on the division of IP addresses, however, retaining OUIs.


## Requirements

Trace-Normalizer toolset consists of two scripts written in [Python 3](https://www.python.org/) language. All required Python modules are listed in [./requirements.txt](./requirements.txt) file. Use the following command to simple requirements installation:
```bash
$ pip3 install -r requirements.txt
```


## Usage

Trace-Normalizer toolset provides two scripts to ease normalization of network traffic traces. The first script is [**crawler.py**](./crawler.py) able to search all occurrences of IPv4 and IPv6 addresses in given PCAP. The second script is [**normalizer.py**](./normalizer.py) for normalization of given traces according to the given configuration.

### Crawler

Script for searching for all occurrences of IPv4 and IPv6 addresses in given trace file. The output is produced as YAML file listing all the addresses found.

Use the following command to start searching for addresses in given trace:
```bash
$ ./crawler.py -p <input_file> -o <output>
```
* `-p`, `--pcap` Path to the PCAP file
* `-o`, `--output` Output path for YAML file with all IPs found

See the following example with searching of IP addresses in *capture.pcap* file and producing the result in *output.yml* file:
```bash
$ ./crawler.py -p capture.pcap -o output.yml
```

### Normalizer

Script for normalization of a given trace file according to the configuration with addresses characterization. The script produces normalized file and labels in YAML format.

Normalizer requires a simple configuration file providing a categorization of IPv4 and IPv6 addresses. Any additional unknown keys will be ignored. Use Crawler to get info about all addresses in the given trace. Based on input trace analysis, the input YAML configuration may look as follows:
```yaml
ip.groups:
  source:
    - 10.0.0.2
  intermediate:
  destination:
    - 10.0.0.3
    - 10.0.0.6
mac.associations:
  - ips:
    - 10.0.0.2
    mac: D4:63:1F:A0:1A:08
  - ips:
    - 10.0.0.3
    mac: 6F:B0:02:44:2C:BA
  - ips:
    - 10.0.0.6
    mac: AF:E0:74:D4:AC:5B
```

Use the following command to start normalization of given trace abased on the given configuration:
```bash
$ ./normalizer.py -c <configuration_file> -p <input_file> -o <output_file> -l <output_labels_file>
```
* `-c`, `--configuration` Path to the configuration file
* `-p`, `--pcap` Path to the trace file
* `-o`, `--output` Output path for normalized trace file
* `-l`, `--label_output` Output for labels in YAML format

See the following example with normalization of *capture.pcap* file based on the configuration in *config.yml* producing *normalized.pcap* trace file ane labels in *labels.yml*:
```bash
$ ./normalizer.py -c config.yml -p capture.pcap -o normalized.pcap -l labels.yaml
```


## Contribution

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

*If you are interested in research collaborations, don't hesitate to contact us at  [https://csirt.muni.cz](https://csirt.muni.cz/about-us/contact?lang=en)!*
