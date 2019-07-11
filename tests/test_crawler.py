import tempfile
from pathlib import Path
import yaml

_path = Path(Path(__file__).parent)
_pcap_path = _path / Path('pcap')
tests = [
    {'expected' : _path / i, 'pcap' : sorted(_pcap_path.glob(i.stem+'.*'))[0] } for i in (_path/Path('crawler_output')).iterdir() if i.suffix in ('.yaml', '.yml')
]

def check(outfile : str, _expected : Path, filename: str):
    with open(outfile) as ff:
        xs:dict = yaml.load(ff, Loader=yaml.FullLoader)
    with _expected.open() as ff:
        es:dict = yaml.load(ff, Loader=yaml.FullLoader)

    expected = es.get('ip.groups')
    ips = xs.get('ip.groups')
    for field in ['source', 'intermediate', 'destination']:
        e = set(expected.get(field))
        i = ips.get(field)
        assert isinstance(i, list), '[{}] No keyword ip found in output'.format(filename)
        assert len(i) == len(e), '[{}] {} ips found, {} was expected'.format(filename, len(ips), len(e))
        assert len(e.intersection(set(i))) == len(e), '[{}] Unexpected IPs found.'.format(filename)

    def transform_occurances(xs):
        r = {}
        for i in xs:
            r[i['ip']] = {'count' : i['count'], 'first_observed' : i['first_observed']}
        return r
    
    e_occur = transform_occurances(es.get('ip.occurrences'))
    i_occur = transform_occurances(xs.get('ip.occurrences'))
    assert len(e_occur.keys()) == len(i_occur.keys()), 'Unexpected number of ips in occurances'
    for e_key, e_val in e_occur.items():
        i_val = i_occur[e_key]
        assert i_val['count'] == e_val['count'], 'Unexpected occurrence count'
        assert i_val['first_observed'] == e_val['first_observed'], 'Unexpected first observed packet number'
    
    def transform_searched_protocols(xs):
        r = {}
        for i in xs:
            r[i['ip']] = i['protocols']
        return r
    
    e_prot = transform_searched_protocols(es.get('ip.searched_protocols'))
    i_prot = transform_searched_protocols(xs.get('ip.searched_protocols'))
    assert len(e_prot.keys()) == len(i_prot.keys()), 'Unexpected number of ips found in searched protocols'
    for e_key, e_val in e_prot.items():
        i_val = i_prot.get(e_key)
        assert i_val is not None, 'None protocols'
        assert len(i_val) == len(e_val), 'Unexpected number of protocols in searched protocols'
        assert len(set(e_val).intersection(set(i_val))) == len(e_val), 'Unexpected protocols found'
    
    def transform_associations(xs):
        r = {}
        for i in xs:
            r[i['mac']] = i['ips']
        return r
    
    e_asoc = transform_associations(es.get('mac.associations'))
    i_asoc = transform_associations(xs.get('mac.associations'))
    assert len(e_asoc.keys()) == len(i_asoc.keys()), 'Unexpected number of macs found in searched protocols'
    for e_key, e_val in e_asoc.items():
        i_val = i_asoc.get(e_key)
        assert i_val is not None, 'None ips in mac associations'
        assert len(i_val) == len(e_val), 'Unexpected number of ips in associations'
        assert len(set(e_val).intersection(set(i_val))) == len(e_val), 'Unexpected ips found in mac ip association'

def get_pcap(name):
    return _path / Path(name)    

def test_crawler_main(crawl_function):
    with tempfile.TemporaryDirectory() as tmpdir:
        for test in tests:
            try:
                outfile=tempfile.NamedTemporaryFile(dir=tmpdir,delete=False)
                outfile.close()
                crawl_function(
                    pcap=test['pcap']
                    , outfile=Path(outfile.name)
                )
                check(outfile.name, test['expected'], filename=test['pcap'].name)
                outfile.close()
            except Exception as e:
                print(test['pcap'], 'failed.')
                print(e)
            else:
                print(test['pcap'], 'passed.')

