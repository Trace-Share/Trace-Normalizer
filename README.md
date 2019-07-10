# Trace-Share: Trace-Normalizer

Toolset for normalization of network traffic traces.

### Table of Contents

* [Description](#description)
* [Requirements](#requirements)
* [Usage](#usage)
  + [Crawler](#crawler)
  + [Normalizer](#normalizer)
* [Contribution](#contribution)


## Description

Trace-Normalizer is a toolset for normalization of network traffic traces to ease their further sharing, manipulation, and injection into the background traffic. The normalization consists of **IP and MAC addresses replacement** to reserved blocks, and **shifting capture time** to zero epoch time. After the normalization, the capture can be annotated and provided as an annotated unit.

IP addresses are divided into the following reserved blocks according to role of the corresponding host:
* **source:** <240.0.0.2, 240.84.255.254>
* **intermediate:** <240.85.0.2, 240.169.255.254>
* **destination:** <240.170.0.2, 240.255.255.254>

Similarly, MAC addresses are split based on the division of IP addresses, however, retaining OUIs.


## Requirements

Trace-Normalizer toolset consists of two scripts written in [Python 3](https://www.python.org/) language. All required Python modules are listed in [./requirements.txt](./requirements.txt) file. Use the following command to simple requirements installation:
```bash
$ pip3 install -r requirements.txt
```


## Usage



### Crawler

Script for searching for all IPv4 and IPv6 addresses in PCAP. Addresses outputted in yaml format.
```yaml
ip:
-0.0.0.0
```

`python crawler.py --pcap capture.pcap --output output.yaml`

#### Parameters
* `--pcap` Path to the PCAP file
* `--output` Output path for yaml of IPs, including filename


### Normalizer

`python normalizer.py --configuration config.json --pcap capture.pcap --output normalized.pcap --label_output labels.yaml`
#### Parameters

* `--configuration` Path to the configuration file
* `--pcap` Path to the PCAP file
* `--output` Output path for normalized PCAP, including filename
* `--label_output` Output for labels in yaml format, including filename

#### Configuration

Json or Yaml file in following format
```yaml
source:
    - 0.0.0.0
    - 0.0.0.1
intermediate:
    - 1.1.1.1
    - 1.1.1.2
destination:
    - 2.2.2.2
    - 2.2.2.3
```


## Contribution

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

*If you are interested in research collaborations, don't hesitate to contact us at  [https://csirt.muni.cz](https://csirt.muni.cz/about-us/contact?lang=en)!*
