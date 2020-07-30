#!/usr/bin/env python3

import os, sys
import argparse
from report2idea import *

# Module name, description and required input data format
MODULE_NAME = "ddos_detector2idea"
MODULE_DESC = "Converts output of ddos_detector module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,uint64 BYTES,time TIME_FIRST,time TIME_LAST"

# Main conversion function
def convert_to_idea(rec, opts=None):
    global bl_conv, bl_scale_tholds

    endTime = getIDEAtime(rec.TIME_LAST)
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "AltNames": [rec.EVENT_ID],
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": endTime,
        'CeaseTime': endTime,
        "Category": ['Availability.DoS'],
        "ByteCount": rec.BYTES,
        "Target": [{}],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'ddos_detector' ],
            'Type': ['Flow', 'Statistical'],
        }],
    }

    setAddr(idea["Target"][0], rec.DST_IP)

    idea['Description'] = "Volume of traffic and number of its sources increased."
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


