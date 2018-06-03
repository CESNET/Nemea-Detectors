
import xml.etree.ElementTree as ET
import requests
import logging
import re
import sched
import time

fh = logging.FileHandler('bl_downloader.log')
cs = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
cs.setLevel(logging.DEBUG)
fh.setLevel(logging.DEBUG)
cs.setFormatter(formatter)
fh.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.addHandler(fh)
logger.addHandler(cs)
logger.setLevel(logging.DEBUG)

ip_regex = re.compile('\\b((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)((/(3[012]|[12]?[0-9]))?)\\b')

check_interval = 1 * 60  # Time period (secs) to check for blacklist changes

blacklists = []


class Blacklist:
    def __init__(self, bl_type_name, bl_type_id, bl):
        self.type = bl_type_name
        self.type_id = bl_type_id
        self.id = bl.attrib['id']
        self.entities = []
        self.last_download = None

        # Generate variables from the XML config file
        for element in bl:
            setattr(self, element.attrib['name'], element.text)

    def __str__(self):
        return str(self.__dict__)

    def extract_ips(self, data):
        extracted = []

        for line in data.decode('utf-8').splitlines():
            match = re.search(ip_regex, line)
            if match:
                extracted.append(match.group(0))

        return extracted

    def download_and_update(self):
        try:
            req = requests.get(self.source, timeout=10)

            if req.status_code == 200:
                data = req.content

                new_entities = self.extract_ips(data)

                if new_entities == self.entities:
                    # Blacklist entites not changed since last download
                    return 0

                self.entities = new_entities

                # filename = 'blacklists/{}_{}.blist'.format(self.type, self.id)
                # with open(filename, 'w') as f:
                #     f.write(data.decode())

                logger.debug('Updated blacklist {}'.format(self.name))

                return 1

            else:
                logger.warning('Couldnt fetch blacklist: {}\n'
                               'Status code: {}'.format(self.source, req.status_code))

        except requests.exceptions.Timeout:
            logger.warning('Couldnt fetch blacklist: {}\n'
                           'Timeout reached'.format(self.source))



# Sorting comparator, splits the IP in format "A.B.C.D(/X),Y,Z"
# into tuple of IP (A, B, C, D), which is comparable by python (numerically)
def split_ip(ip):
    # Extract only IP, without the prefix and indexes
    if '/' in ip:
        ip = ip.split('/')[0]
    else:
        ip = ip.split(',')[0]

    """Split a IP address given as string into a 4-tuple of integers."""
    return tuple(int(part) for part in ip.split('.'))


def merge_and_sort():
    all_entities = []

    # Enrich the entities with blacklist indexes (type id, id)
    for bl in blacklists:
        enriched = [entity + ',{},{}'.format(bl.type_id, bl.id) for entity in bl.entities]
        all_entities.extend(enriched)

    with open('../ipdetect/bl_records_sorted.txt'.format(time.time()), 'w') as f:
        f.write('\n'.join(sorted(all_entities, key=split_ip)))


def parse_config():
    tree = ET.parse("../ipdetect/bld_userConfigFile.xml")
    bl_type_array = tree.getroot().getchildren()[0].getchildren()

    for bl_type in bl_type_array:
        bl_type_name = bl_type.attrib['type']
        bl_type_id = bl_type.attrib['type_id']
        for bl in bl_type:
            blacklists.append(Blacklist(bl_type_name, bl_type_id, bl))


def runa(s):
    # schedule next check immediately
    s.enter(check_interval, 1, runa, (s,))

    updated_count = 0

    for bl in blacklists:
        # if bl.last_download + 60 * bl.download_interval < time.time():
        updated_count += bl.download_and_update()

    if updated_count:
        merge_and_sort()
        logger.info('NEW IP Blacklist created')

    else:
        logger.info('Check for updates done, no changes')


if __name__ == '__main__':
    parse_config()

    s = sched.scheduler(time.time, time.sleep)

    s.enter(check_interval, 1, runa, (s,))
    s.run()











