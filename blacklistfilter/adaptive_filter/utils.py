
import sys
import xml.etree.ElementTree as xml


def get_botnet_blacklist_indexes(blacklists: dict):
    botnet_idxs = set()
    ip_blists = blacklists['ip']
    print(ip_blists)
    for id, blist in ip_blists.items():
        if blist['category'] == 'Intrusion.Botnet':
            botnet_idxs.add(id)
    return botnet_idxs


def load_blacklists(config_file):
    """
    Load `config` file of blacklistfilter module (bl_downloader_config.xml).
    This file contains a list of blacklists, their names and URLs.

    load_config() returns dictionary, where the key is id (= 2**ID from file) and
    value is a dictionary of "name", "type", "source" and other parameters.

    Args:
        config_file: config file

    Returns:
        dict: blacklists
    """

    bls = {}
    with open(config_file, "r") as f:
        tree = xml.parse(f)

    ip_root_element = tree.find(".//array[@type='IP']")
    url_dns_root_element = tree.find(".//array[@type='URL/DNS']")

    ip_blacklists = list(ip_root_element)
    url_dns_blacklists = list(url_dns_root_element)

    for blacklists in [ip_blacklists, url_dns_blacklists]:
        bl_type = 'ip' if blacklists is ip_blacklists else 'url_dns'
        bls[bl_type] = {}

        for struct in blacklists:
            elems = list(struct)
            bl_id = None
            bl_name = None
            bl_category = None
            bl_source = None
            for el in elems:
                attr = el.attrib["name"]
                if attr == "name":
                    bl_name = el.text
                elif attr == "id":
                    bl_id = 2 ** (int(el.text) - 1)
                elif attr == "category":
                    bl_category = el.text
                elif attr == "source":
                    bl_source = el.text
            if not bl_id or not bl_name or not bl_category or not bl_source:
                sys.stderr.write("Incomplete configuration. " + str((bl_id, bl_name, bl_category)))
                break

            bls[bl_type][bl_id] = {"name": bl_name, "category": bl_category, "source": bl_source}

    return bls
