import tempfile
from pathlib import Path
from hashlib import sha256
import yaml

_path = Path(Path(__file__).parent)
_pcap_path = _path / Path('pcap')
_config_path = _path / Path('normalized_config')
_label_path = _path / Path('normalized_labels')
_normed_path = _path / Path('normalized_pcap')
tests = [
    {
        'expected_pcap' : sorted(_pcap_path.glob(i.stem+'.*'))[0]
        , 'expected_labels' : sorted(_label_path.glob(i.stem+'.*'))[0]
        , 'pcap' : sorted(_pcap_path.glob(i.stem+'.*'))[0] 
        , 'config' : _config_path / i
    } for i in (_path/Path('normalized_config')).iterdir() if i.suffix in ('.yaml', '.yml')
]

def check(pcap, labels, expected_pcap, expected_labels, pcap_name):
    def buffered_hash(fpath:Path, buffer=2**16):
        h = sha256()
        with fpath.open('rb') as ff:
            dt = ff.read(buffer)
            while dt is not None:
                h.update(dt)
                dt = ff.read(buffer)
        return h.digest()
    
    assert buffered_hash(pcap) == buffered_hash(expected_pcap), 'PCAP hash doesnt match expected'
    
    with labels.open() as ff:
        ns:dict = yaml.load(ff, Loader=yaml.FullLoader)
    with expected_labels.open() as ff:
        es:dict = yaml.load(ff, Loader=yaml.FullLoader)
    
    expected = es.get('ip')
    ips = ns['ip']
    for field in ['ip.source', 'ip.intermediate', 'ip.destination']:
        e = set(expected.get(field))
        i = ips.get(field)
        assert isinstance(i, list), '[{}] No keyword ip found in output'.format(pcap_name)
        assert len(i) == len(e), '[{}] {} ips found, {} was expected'.format(pcap_name, len(ips), len(e))
        assert len(e.intersection(set(i))) == len(e), '[{}] Unexpected IPs found.'.format(pcap_name)
    
    e_p = es.get('packets')
    n_p = ns['packets']
    assert e_p['packets.count'] == n_p['packets.count'], 'Packet count doesnt match expected'
    assert e_p['packets.end'] == n_p['packets.end'], 'Capture end doesn\'t match expected'
    assert e_p['packets.start'] == n_p['packets.start'], 'Capture start doesn\' match expected'

def test_normalizer_main(normlizer_function):
    with tempfile.TemporaryDirectory() as tmpdir:
        for test in tests:
            try:
                outfile=tempfile.NamedTemporaryFile(dir=tmpdir,delete=False)
                outfile.close()
                labelfile=tempfile.NamedTemporaryFile(dir=tmpdir,delete=False)
                labelfile.close()
                normlizer_function(
                    config_path=test['config']
                    , pcap=test['pcap']
                    , res_path=Path(outfile.name)
                    , label_path=Path(labelfile.name)
                )
                check(Path(outfile.name), Path(labelfile.name), test['expected_pcap'], test['expected_labels'], test['pcap'].name)
                outfile.close()
                labelfile.close()
            except Exception as e:
                print(test['pcap'], 'failed.')
                print(e)
            else:
                print(test['pcap'], 'passed.')
