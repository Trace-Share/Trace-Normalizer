# Trace-Normalizer
Toolset for nromalization of network traffic traces

Normalizer replaces IP & MAC addresses, shifts pcap to start with 0th epoch. IP addresses are split into 3 categories (source, intermediate, destination) and assigned into blocks based on them (-240.85.0.0, 240.85.0.0-240.170.0.0, 240.170.0.0-). Similliary MAC addresses are split based on division of IP addresses, however, retaining OUIs.

Normalizer outputs normalized PCAP (using functions defined in Trace-Mix module) and labels.

## Usage

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
