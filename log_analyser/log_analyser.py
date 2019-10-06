import argparse
import gzip
import json
import logging
import os
import re
import sys
from collections import defaultdict, namedtuple
from datetime import datetime
from string import Template

import numpy as np


def finding_last_log(grep_gen):
    last_log = None
    log_nt = namedtuple('log', ['path_to_file', 'date', 'ext'])
    for path, cur_date, cur_ext in grep_gen:
        if last_log is None:
            last_log = log_nt(path, cur_date, cur_ext)
        if cur_date > last_log.date:
            last_log = log_nt(path, cur_date, cur_ext)
    return last_log


def gen_grep(pat, LOG_DIR):
    patc = re.compile(pat)
    for f in os.listdir(LOG_DIR):
        if (patc.search(f)):
            yield parse_log_filename(f, patc, LOG_DIR)


def parse_log_filename(filename, patc, LOG_DIR):
    matched = patc.match(filename)
    _, cur_date, cur_ext = matched.groups()
    path_to_file = os.path.join(LOG_DIR, filename)
    cur_date = datetime.strptime(cur_date, '%Y%m%d')
    return path_to_file, cur_date, cur_ext


def open_log(last_log, encoding='utf-8'):
    if last_log.ext == ".gz":
        open_func = gzip.open
    else:
        open_func = open
    with open_func(last_log.path_to_file, mode='rt',
                   encoding=encoding) as f:
        log_file = f.readlines()
    return log_file


def field_map(dictseq, name, func):
    for d in dictseq:
        d[name] = func(d[name])
        yield d


count_all_records = 0
count_bad_records = 0
threshold = 0.3


def gen_match_line_log(patc, lines):
    global count_all_records
    global count_bad_records
    for line in lines:
        count_all_records += 1
        match = patc.search(line)
        if match is None:
            count_bad_records += 1
        else:
            yield match.groupdict()


def otus_log_parser(lines, log_line_pattern):
    logpat = re.compile(log_line_pattern, re.IGNORECASE)
    log_line_gen = gen_match_line_log(logpat, lines)
    log_line_gen = field_map(log_line_gen, "statuscode", int)
    log_line_gen = field_map(log_line_gen, "request_time",
                             lambda s: float(s) if s != '-' else 0)
    return log_line_gen


def collect_url_stats(log):
    url_dict = defaultdict(list)
    count_all_urls = 0
    all_time = 0
    for log_line in log:
        count_all_urls += 1
        request_time = log_line['request_time']
        all_time += request_time
        url = log_line['url']
        url_dict[url].append(request_time)
    return url_dict, count_all_urls, all_time


def calc_stats(url_req_time_dict, count_all, all_time):
    list_of_dicts = []
    for key, vals in url_req_time_dict.items():
        singl_url_dict = {}
        count = len(vals)
        singl_url_dict['url'] = key
        singl_url_dict['count'] = round(count, 3)
        singl_url_dict['count_perc'] = round(count/count_all*100, 3)
        time_sum = np.sum(vals)
        singl_url_dict['time_sum'] = round(time_sum, 3)
        singl_url_dict['time_perc'] = round(time_sum/all_time*100, 3)
        singl_url_dict['time_avg'] = round(np.mean(vals), 3)
        singl_url_dict['time_max'] = round(np.max(vals), 3)
        singl_url_dict['time_med'] = round(np.median(vals), 3)
        list_of_dicts.append(singl_url_dict)
    return list_of_dicts


def create_new_report(
        url_list_stats, REPORT_SIZE, path_to_example,
        path_to_report_dir, report_name):
    with open(path_to_example, 'r') as file:
        sample = file.read()
    basic_val = 'var lastRow = 150'
    new_val = 'var lastRow = {}'.format(REPORT_SIZE)
    sample = sample.replace(basic_val, new_val)

    sample_template = Template(sample)
    new_report = sample_template.safe_substitute(table_json=url_list_stats)
    path_to_report = os.path.join(path_to_report_dir, report_name)
    with open(path_to_report, 'w') as f:
        f.write(new_report)
    return None


def create_log_line_pattern():
    log_format = (r'$remote_addr $remote_user ' +
                  r'$http_x_real_ip \[$time_local\] ' +
                  r'\"$request\" $status $body_bytes_sent ' +
                  r'\"$http_referer\" \"$http_user_agent\" ' +
                  r'\"$http_x_forwarded_for\" \"$http_X_REQUEST_ID\" ' +
                  r'\"$http_X_RB_USER\" $request_time')

    parser_dict = {}
    parser_dict['remote_addr'] = r'(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    parser_dict['remote_user'] = r'(?P<remote_user>\-|.+)'
    parser_dict['http_x_real_ip'] = r'(?P<http_x_real_ip>\-|.+)'
    parser_dict['time_local'] = r'(?P<time_local>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} [\+|\-]\d{4})'
    parser_dict['request'] = r'(GET|POST) (?P<url>.+)'
    parser_dict['status'] = r'(?P<statuscode>\d{3})'
    parser_dict['body_bytes_sent'] = r'(?P<body_bytes_sent>\d+)'
    parser_dict['http_referer'] = r'(?P<http_referer>\-|.+)'
    parser_dict['http_user_agent'] = r'(?P<http_user_agent>.+)'
    parser_dict['http_x_forwarded_for'] = r'(?P<http_x_forwarded_for>\-|.+)'
    parser_dict['http_X_REQUEST_ID'] = r'(?P<http_X_REQUEST_ID>.+)'
    parser_dict['http_X_RB_USER'] = r'(?P<http_X_RB_USER>.+)'
    parser_dict['request_time'] = r'(?P<request_time>\d{1,4}\.\d{1,4})'
    
    template_log_f = Template(log_format)
    log_line_pattern = template_log_f.substitute(parser_dict)
    return log_line_pattern


def main():
    print(os.listdir('./'))
    parser = argparse.ArgumentParser(description='log analyzer')
    parser.add_argument(
        '--config',
        type=str,
        default='./default_config.json',
        help='path to config'
    )
    args = parser.parse_args()
    if args is not None:
        with open(args.config, 'r') as f:
            config_from_file = json.load(f)

    config = {
        "REPORT_SIZE": 1000,
        "REPORT_DIR": "./reports",
        "LOG_DIR": "./log"
    }

    config = {**config, **config_from_file}
    path_to_program_logs = config.get('program_logs')
    logging.basicConfig(format='[%(asctime)s] %(levelname).1s %(message)s',
                        level=logging.DEBUG,
                        datefmt='%Y.%m.%d %H:%M:%S',
                        filename=path_to_program_logs,
                        )
    logging.info('Start')
    logging.info('Finding last log')

    nginx_logpat = r'(nginx-access-ui.log-)(\d{8})(.gz|$)'

    try:
        file_generator = gen_grep(nginx_logpat, config['LOG_DIR'])
        last_log_nt = finding_last_log(file_generator)
    except Exception:
        logging.exception("Error occurred while finding last log")

    if last_log_nt is None:
        logging.info('logs not found')
        sys.exit()

    report_name = 'report-'+last_log_nt.date.strftime("%Y.%m.%d")+'.html'
    if report_name in os.listdir(config["REPORT_DIR"]):
        logging.info('report already exist')
        sys.exit()

    logging.info('opening last log')
    try:
        log_file = open_log(last_log_nt)
    except Exception:
        logging.exception("Error occurred while load log file")

    log_line_pattern = create_log_line_pattern()
    logging.info('parse and collect url records to one dict')

    try:
        log_gen = otus_log_parser(log_file, log_line_pattern)
        url_dict, count_all, all_time = collect_url_stats(log_gen)
        # print(count_bad_records, count_all_records)
        if count_bad_records/count_all_records > threshold:
            logging.ERROR('most of the file could not be parsed, ' +
                          'current unparsed part of log: '
                          + str(count_bad_records/count_all_records))
            sys.exit()
    except Exception:
        logging.exception("Error occurred while parsing log")
        sys.exit()

    logging.info('calculate statistics')
    try:
        url_list_stats = calc_stats(url_dict, count_all, all_time)
        url_list_stats = sorted(
            url_list_stats, key=lambda x: x['time_sum'], reverse=True)
    except Exception:
        logging.exception("Error occurred while calculate url stats")
        sys.exit()

    logging.info('create new report')
    path_to_blueprint = './report.html'
    try:
        create_new_report(
            url_list_stats, config['REPORT_SIZE'], path_to_blueprint,
            config['REPORT_DIR'], report_name
        )
    except Exception:
        logging.exception("Error occurred while create new report")
        sys.exit()


if __name__ == "__main__":
    main()
