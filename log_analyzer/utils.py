import json


def create_config(path):
    config_report_dir = '../report_dir/'

    config_log_dir = '../log_dir/'
    program_log_file = None

    custom_config = {
        'REPORT_SIZE': 1000,
        'REPORT_DIR': config_report_dir,
        'LOG_DIR': config_log_dir,
        'program_logs': program_log_file
    }
    with open(path, 'w') as f:
        json.dump(custom_config, f)
# create_config('./default_config.json')
