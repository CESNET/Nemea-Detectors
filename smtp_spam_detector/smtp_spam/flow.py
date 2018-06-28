"""
Copyright (C) 2016-2018 CESNET

LICENSE TERMS

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.
3. Neither the name of the Company nor the names of its contributors
   may be used to endorse or promote products derived from this
   software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this
product may be distributed under the terms of the GNU General Public
License (GPL) version 2 or later, in which case the provisions
of the GPL apply INSTEAD OF those given above.

This software is provided ``as is'', and any express or implied
warranties, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose are disclaimed.
In no event shall the company or contributors be liable for any
direct, indirect, incidental, special, exemplary, or consequential
damages (including, but not limited to, procurement of substitute
goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether
in contract, strict liability, or tort (including negligence or
otherwise) arising in any way out of the use of this software, even
if advised of the possibility of such damage.
"""

#!/usr/bin/env python3
import sys

from global_def import *

# Class for basic flow without SMTP Headers
class Flow(object):
    def __init__(self, rec):
        # Basic flow
        self.DST_IP = rec.DST_IP
        self.SRC_IP = rec.SRC_IP
        self.BYTES = rec.BYTES
        self.TIME_FIRST = rec.TIME_FIRST
        self.TIME_LAST = rec.TIME_LAST
        self.PACKETS = rec.PACKETS
        self.DST_PORT = rec.DST_PORT
        self.SRC_PORT = rec.SRC_PORT
        self.TCP_FLAGS = rec.TCP_FLAGS

    def __str__(self):
        return "SRC_IP:" + str(self.SRC_IP) + ",DST_IP:" + str(self.DST_IP) + \
               ",BYTES:" + str(self.BYTES) + ",TIME_FIRST;" + str(self.TIME_FIRST) + \
               ",TIME_LAST:" + str(self.TIME_LAST) + ",PACKETS:" + str(self.PACKETS)
    def __repr__(self):
        return str(self.SRC_IP) + ":" + str(self.DST_IP) + ":" + str(self.BYTES) + ":" + \
               str(self.TIME_FIRST) + ":" + str(self.TIME_LAST) + ":" + str(self.PACKETS)

# Class for SMTP flow handling
class SMTP_Flow(Flow):
    def __init__(self, rec):
        # Base constructor
        super().__init__(rec)
        # SMTP Header extension
        self.SMTP_2XX_STAT_CODE_COUNT = rec.SMTP_2XX_STAT_CODE_COUNT
        self.SMTP_3XX_STAT_CODE_COUNT = rec.SMTP_3XX_STAT_CODE_COUNT
        self.SMTP_4XX_STAT_CODE_COUNT = rec.SMTP_4XX_STAT_CODE_COUNT
        self.SMTP_5XX_STAT_CODE_COUNT = rec.SMTP_5XX_STAT_CODE_COUNT
        self.SMTP_COMMAND_FLAGS = rec.SMTP_COMMAND_FLAGS
        self.SMTP_MAIL_CMD_COUNT = rec.SMTP_MAIL_CMD_COUNT
        self.SMTP_RCPT_CMD_COUNT = rec.SMTP_RCPT_CMD_COUNT
        self.SMTP_STAT_CODE_FLAGS = rec.SMTP_STAT_CODE_FLAGS
        try:
            self.SMTP_DOMAIN = rec.SMTP_DOMAIN
            self.SMTP_FIRST_RECIPIENT = rec.SMTP_FIRST_RECIPIENT
            self.SMTP_FIRST_SENDER = rec.SMTP_FIRST_SENDER
        except:
            self.SMTP_DOMAIN = None
            self.SMTP_FIRST_RECIPIENT = None
            self.SMTP_FIRST_SENDER = None

    def __str__(self):
        return "SMTP_FLOW:\nSRC:" + str(self.SRC_IP) + "\nDST:" + str(self.DST_IP) \
                + "\nCMD_FLAGS:" + str(self.SMTP_COMMAND_FLAGS) + "\n"
    def __repr__(self):
        return str(self.SRC_IP) + ":" + str(self.DST_IP) + ":" + str(self.SMTP_COMMAND_FLAGS)

    """
    Function that detecs whether current flow could be a spam
    based on SMTP FLAGS, it returns positive value on suspicion
    flow otherwise negative one
    """
    def filter(self):
        rep = 0.0
        if int(self.SMTP_STAT_CODE_FLAGS) & int(SC_SPAM) > 0:
        # It contains a spam key word
            rep += 0.9
            print("Alert(SPAM flag present) [{0},{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))
        if not self.SMTP_FIRST_SENDER or not self.SMTP_FIRST_RECIPIENT:
            rep += 0.3
            #print("Alert(Address not filled) [{0},{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))

        cmd_flag = self.SMTP_COMMAND_FLAGS

    def get_name(self):
        return self.SMTP_FIRST_SENDER.partition("@")[0][1:]
