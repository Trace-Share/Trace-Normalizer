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
        xs = yaml.load(ff)
    with _expected.open() as ff:
        expected = yaml.load(ff)
    expected = set(expected.get('ip'))
    ips = xs.get('ip')
    assert isinstance(ips, list), '[{}] No keyword ip found in output'.format(filename)
    assert len(ips) == len(expected), '[{}] {} ips found, {} was expected'.format(filename, len(ips), len(expected))
    assert len(expected.intersection(set(ips))) == len(expected), '[{}] Unexpected IPs found.'.format(filename)

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

