#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests, uuid
from datetime import datetime, timedelta
from configparser import ConfigParser
import json
import os

"""
C3ISP upload utility.
"""

__author__ = "Vincenzo Farruggia, Oleksii Osliak"
__license__ = "GPL"
__version_info__ = ('2021', '06', '21')
__version__ = ''.join(__version_info__)

CONFIG = {
    'server_uri': None,
    'misp_key': None,
    'authinfo': None,
    'dsa': None
}


def upload_to_c3isp(file_path):
    # post data in C3ISP platform
    link = CONFIG['server_uri'] + '/pilot-interface/v1/uploadFile'
    start_time = datetime.now()
    end_time = start_time + timedelta(hours=1)
    metadata = {
        'id': str(uuid.uuid1()),
        'event_type': "DDoS",
        'start_time': start_time.strftime('%Y-%m-%dT%H:%M:%S.%f'),
        'end_time': end_time.strftime('%Y-%m-%dT%H:%M:%S.%f'),
        'dsa_id': CONFIG['dsa'],
        'subject_id': 'user',
        'stixed': 'false'
    }
    files = {'files': (os.path.basename(file_path), open(file_path, 'rb'), 'text/csv')}
    metadata = {'metadata': (json.dumps(metadata), 'application/json')}
    r = requests.post(url=link, files=files, data=metadata, auth=CONFIG['authinfo'])
    return r.json()


def export_misp(dpo_id, logger):
    # export DPO to the Sparta MISP instance if it is allowed by DSA
    url = CONFIG['server_uri'] + '/pilot-interface/export/{}/misp'.format(dpo_id)
    queryParams = {'exportParams': json.dumps({'mispKey': CONFIG['misp_key']})}

    r = requests.get(url, params=queryParams, auth=CONFIG['authinfo'])
    if r.ok:
        logger.debug('The DPO {} has been exported succesfully'.format(dpo_id))
        logger.debug('The UUID of the MISP Event is {}'.format(r.json()['Event']['uuid']))
    else:
        logger.error('An error has occurred while exporting DPO {}'.format(dpo_id))
        logger.error(r.json())


def read_config(config_path):
    cfg = ConfigParser()
    cfg.read(config_path)

    cfg_sec = cfg["DEFAULT"]
    CONFIG['server_uri'] = cfg_sec['server_uri']
    CONFIG['authinfo'] = (cfg_sec['portal_user'], cfg_sec['portal_pass'])
    CONFIG['misp_key'] = cfg_sec['misp_key']
    CONFIG['dsa'] = cfg_sec['dsa']
    return True
