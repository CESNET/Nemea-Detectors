#!/usr/bin/env python3
import sys
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

    # function that detecs whether current flow could be a spam
    # based on SMTP FLAGS, it returns positive value on suspicion
    # flow otherwise negative one
    def BCP_Filter(self):
        spam_flag = 0
        if int(self.SMTP_STAT_CODE_FLAGS) & int(SC_SPAM) > 0:
        # It contains a spam key word
            spam_flag += 50
            print("Alert(SPAM flag present) [{0},{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))
        if self.SMTP_FIRST_SENDER == "" or self.SMTP_FIRST_RECIPIENT == "":
            spam_flag += 20
            print("Alert(Address not filled) [{0},{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))
        # todo more filters
        return spam_flag

    def get_name(self):
        return self.SMTP_FIRST_SENDER.partition("@")[0][1:]
