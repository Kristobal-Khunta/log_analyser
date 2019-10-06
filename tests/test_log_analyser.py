import datetime
import os
#import sys
#sys.path.append('../')
from log_analyser.log_analyser import  gen_grep, finding_last_log, calc_stats
from log_analyser.log_analyser  import otus_log_parser, create_log_line_pattern
import unittest
import shutil


class Test_log_analyser(unittest.TestCase):
    def test_match_log_line(self):
        log_line_pattern = create_log_line_pattern()
        str1 = ('1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] ' +
                '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" ' +
                '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 ' +
                'GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759"' +
                ' "dc7161be3" 0.390\n')
        d = next(otus_log_parser([str1], log_line_pattern))

        answer = {'remote_addr': '1.196.116.32',
                  'remote_user': '-',
                  'http_x_real_ip': ' -',
                  'time_local': '29/Jun/2017:03:50:22 +0300',
                  'url': '/api/v2/banner/25019354 HTTP/1.1',
                  'statuscode': 200,
                  'body_bytes_sent': '927',
                  'http_referer': '-',
                  'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5',
                  'http_x_forwarded_for': '-',
                  'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759',
                  'http_X_RB_USER': 'dc7161be3',
                  'request_time': 0.39}
        self.assertEqual(d, answer)


class Test_find_parse_file(unittest.TestCase):

    tmp_path = './tmp_log_dir/'

    def setUp(self):

        file_names = [
            'nginx-access-ui.log-20190830.txt',
            'nginx-access-ui.log-20150629.gz'
            'nginx-access-ui.log-20180629.bz2',
            'nginx-access-ui.log-20170629.gz']
        if not os.path.exists(self.tmp_path):
            os.makedirs(self.tmp_path)
        for f in file_names:
            open(self.tmp_path+f, 'a').close()

    def test_parse_file(self):

        nginx_logpat = r'(nginx-access-ui.log-)(\d{8})(.gz|$)'
        grep_g = gen_grep(nginx_logpat, self.tmp_path)
        last_log_nt = finding_last_log(grep_g)
        self.assertEqual(
            last_log_nt.path_to_file,
            './tmp_log_dir/nginx-access-ui.log-20170629.gz')
        self.assertEqual(
            last_log_nt.date, datetime.datetime(2017, 6, 29, 0, 0))
        self.assertEqual(
            last_log_nt.ext, '.gz')

    def tearDown(self):
        shutil.rmtree(self.tmp_path, ignore_errors=True)
# print(os.listdir('./log_dir'))


class Test_calc_statistics(unittest.TestCase):

    def test_calc_stats(self):
        url_dict = {'url1': [10, 15, 20, 25, 30, 45, 50, 100],
                    'url2': list(range(20))}
        url_list_stats = calc_stats(url_dict, 100, 500)
        url_list_stats = sorted(
            url_list_stats, key=lambda x: x['time_sum'], reverse=True)

        answer_list = [
            {'url': 'url1', 'count': 8, 'count_perc': 8.0,
             'time_sum': 295, 'time_perc': 59.0, 'time_avg': 36.875,
             'time_max': 100, 'time_med': 27.5
             },
            {'url': 'url2', 'count': 20, 'count_perc': 20.0,
             'time_sum': 190, 'time_perc': 38.0,
             'time_avg': 9.5, 'time_max': 19, 'time_med': 9.5}
        ]
        self.assertEqual(url_list_stats, answer_list)


if __name__ == '__main__':

    unittest.main()
