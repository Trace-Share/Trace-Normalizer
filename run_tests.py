import crawler
import normalizer
from tests import test_crawler, test_normalizer

def run_tests():
    print('Running crawler tests...')

    test_crawler.test_crawler_main(crawler.ip_scrape)
    print('Done')
    print('Running normlizier tests...')
    test_normalizer.test_normalizer_main(normalizer.normalize)
    print('Done')

if __name__ == '__main__':
    run_tests()
