#!/usr/bin/env python3

# Class for basic flow without SMTP Headers
class Flow:
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

    def __repr__(self):
        return "SRC_IP:" + self.SRC_IP + ",DST_IP:" + self.DST_IP + ",BYTES:" \
                 + self.BYTES + ",TIME_FIRST;" + self.TIME_FIRST + ",TIME_LAST:" \
                 + self.TIME_LAST + ",PACKETS:" + self.PACKETS

# Class for SMTP flow handling
class SMTP_Flow(Flow):
    def __init__(self, rec):
        # Base constructor
        Flow.__init__(self, rec)

        # SMTP Header extension
        self.SMTP_2XX_STAT_CODE_COUNT = rec.SMTP_2XX_STAT_CODE_COUNT
        self.SMTP_3XX_STAT_CODE_COUNT = rec.SMTP_3XX_STAT_CODE_COUNT
        self.SMTP_4XX_STAT_CODE_COUNT = rec.SMTP_4XX_STAT_CODE_COUNT
        self.SMTP_5XX_STAT_CODE_COUNT = rec.SMTP_5XX_STAT_CODE_COUNT
        self.SMTP_COMMAND_FLAGS = rec.SMTP_COMMAND_FLAGS
        self.SMTP_MAIL_CMD_COUNT = rec.SMTP_MAIL_CMD_COUNT
        self.SMTP_RCPT_CMD_COUNT = rec.SMTP_RCPT_CMD_COUNT
        self.SMTP_STAT_CODE_FLAGS = rec.SMTP_STAT_CODE_FLAGS
        self.SMTP_DOMAIN = rec.SMTP_DOMAIN
        self.SMTP_FIRST_RECIPIENT = rec.SMTP_FIRST_RECIPIENT
        self.SMTP_FIRST_SENDER = rec.SMTP_FIRST_SENDER

    def __repr__(self):
        return "FLOW:\nSRC:" + self.SRC_IP + "\nDST:" + self.DST_IP \
                + "\nCMD_FLAGS:" + self.SMTP_COMMAND_FLAGS + "\n"

    def __str__(self):
        return "FLOW:\nSRC:" + self.SRC_IP + "\nDST:" + self.DST_IP \
                + "\nCMD_FLAGS:" + self.SMTP_COMMAND_FLAGS + "\n"

    # function that detecs whether current flow could be a spam
    # based on SMTP FLAGS, it returns positive value on suspicion
    # flow otherwise negative one
    def BCP_Filter(self):
        spam_flag = 0
        if int(self.SMTP_STAT_CODE_FLAGS) & int(SC_SPAM) > 0:
        # It contains a spam key word
            spam_flag += 50
            print("Alert(SPAM flag present) [{0},{1}]".format(self.SRC_IP,
                                                   str(self.SMTP_FIRST_SENDER)))
        if self.SMTP_FIRST_SENDER == "" or self.SMTP_FIRST_RECIPIENT == "":
            spam_flag += 20
            print("Alert(Address not filled) [{0},{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))
        # todo more filters
        return spam_flag

    def get_name(self):
        return self.SMTP_FIRST_SENDER.partition("@")[0][1:]
