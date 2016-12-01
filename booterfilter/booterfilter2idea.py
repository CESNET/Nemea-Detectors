#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/ and we want to import from repo:
import os, sys
import argparse
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "booterfilter2idea"
MODULE_DESC = "Converts output of booterfilter module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 HTTP_REQUEST_AGENT_ID,uint32 HTTP_REQUEST_METHOD_ID,uint32 HTTP_RESPONSE_STATUS_CODE,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,string HTTP_REQUEST_AGENT,string HTTP_REQUEST_HOST,string HTTP_REQUEST_REFERER,string HTTP_REQUEST_URL,string HTTP_RESPONSE_CONTENT_TYPE"


# Blacklist ID to name lookup table

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    global bl_conv, bl_scale_tholds


    endTime = getIDEAtime(rec.TIME_LAST)
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": endTime,
        'CeaseTime': endTime,
        "Category": [ "Suspicious.Booter" ],
        "PacketCount": rec.PACKETS,
        "ByteCount": rec.BYTES,

        "Source": [{
            "Type": [ "Booter" ],
            "Proto": [ "http" ],
            "Port": [ rec.DST_PORT ],
            "Hostname": [ rec.HTTP_REQUEST_HOST ]
        },
        {
            "Proto": [ "http" ],
            "Port": [ rec.SRC_PORT ],
            "UserAgent": rec.HTTP_REQUEST_AGENT
        }
        ],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'booterfilter' ],
            'Type': [ 'Flow', 'Blacklist' ]
        }],
    }

    setAddr(idea["Source"][0], rec.DST_IP)
    setAddr(idea["Source"][1], rec.SRC_IP)

    idea['Note'] = 'Source IP {0} communicated with destination IP {1} and used {2} as hostname, which is on booter blacklist.'.format(rec.SRC_IP, rec.DST_IP, rec.HTTP_REQUEST_HOST)
    idea['Description'] = "Used {0} hostname which is on http://booterblacklist.com/.".format(rec.HTTP_REQUEST_HOST)
    return idea

# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = None
    )

