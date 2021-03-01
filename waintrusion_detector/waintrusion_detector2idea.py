#!/usr/bin/env python3
# -*- mode: python; python-indent-offset: 4; coding: utf-8; -*-
#
# Converts output of waintrusion_detector module to IDEA.
# It receives UniRec message and sends IDEA message.
#
# Author: Tomas Duracka <duractom@fit.cvut.cz>
#
# Copyright (C) 2018 CESNET
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL) version 2 or later, in which case the provisions
# of the GPL apply INSTEAD OF those given above.
#
# This software is provided ``as is'', and any express or implied
# warranties, INCluding, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, INCidental, special, exemplary, or consequential
# damages (INCluding, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (INCluding negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.

import os, sys
import argparse
from report2idea import *

# Module name, description and required input data format
MODULE_NAME = "waintrusion_detector2idea"
MODULE_DESC = "Converts output of waintrusion_detector module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,ipaddr DST_IP,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,time EVENT_TIME, string WAI_RULE, string WAI_MALICIOUS_FIELD, string WAI_MALICIOUS_VALUE"

# Main conversion function
def convert_to_idea(rec, opts=None):
    global bl_conv, bl_scale_tholds

    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.EVENT_TIME),
        "DetectTime": getIDEAtime(rec.EVENT_TIME),
        "Category": ['Recon.Scanning', 'Attempt.Exploit'],
        "Target": [{
            "Port": [rec.DST_PORT],
            "Proto": ["tcp", "http"]
        }],
        "Source": [{
            "Port": [rec.SRC_PORT],
            "Proto": ["tcp", "http"]
        }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'waintrusion_detector' ],
            'Type': ['Flow', 'Signature'],
        }],
    }

    setAddr(idea["Target"][0], rec.DST_IP)
    setAddr(idea["Source"][0], rec.SRC_IP)

    idea['Description'] = "HTTP traffic containing suspicious data that looks like vulnerability test."
    idea['Note'] = "Detection Rule: " + str(rec.WAI_RULE) + ", HTTP request Field: " + str(rec.WAI_MALICIOUS_FIELD) + ", HTTP request field contained value: " + str(rec.WAI_MALICIOUS_VALUE)
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



