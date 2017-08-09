#!/usr/bin/python

import pytrap
import sys
# ******************************************************************************
# ******************************  GLOBAL DEFINITIONS ***************************
# ******************************************************************************
# SMTP COMMANDS
# =============
SMTP_CMD_EHLO = 0x0001
SMTP_CMD_HELO = 0x0002
SMTP_CMD_MAIL = 0x0004
SMTP_CMD_RCPT = 0x0008
SMTP_CMD_DATA = 0x0010
SMTP_CMD_RSET = 0x0020
SMTP_CMD_VRFY = 0x0040
SMTP_CMD_EXPN = 0x0080
SMTP_CMD_HELP = 0x0100
SMTP_CMD_NOOP = 0x0200
SMTP_CMD_QUIT = 0x0400
CMD_UNKNOWN   = 0x8000
# SMTP status codes
# =================
SMTP_SC_211 =   0x00000001
SMTP_SC_214 =   0x00000002
SMTP_SC_220 =   0x00000004
SMTP_SC_221 =   0x00000008
SMTP_SC_250 =   0x00000010
SMTP_SC_251 =   0x00000020
SMTP_SC_252 =   0x00000040
SMTP_SC_354 =   0x00000080
SMTP_SC_421 =   0x00000100
SMTP_SC_450 =   0x00000200
SMTP_SC_451 =   0x00000400
SMTP_SC_452 =   0x00000800
SMTP_SC_455 =   0x00001000
SMTP_SC_500 =   0x00002000
SMTP_SC_501 =   0x00004000
SMTP_SC_502 =   0x00008000
SMTP_SC_503 =   0x00010000
SMTP_SC_504 =   0x00020000
SMTP_SC_550 =   0x00040000
SMTP_SC_551 =   0x00080000
SMTP_SC_552 =   0x00100000
SMTP_SC_553 =   0x00200000
SMTP_SC_554 =   0x00400000
SMTP_SC_555 =   0x00800000
SC_SPAM     =   0x40000000        # indicates that answer contains SPAM keyword
SC_UNKNOWN  =   0x80000000
# ******************************************************************************
# Global variables
# ================
# path to temp data
file_data="/home/current/macoun/data/smtp_data_sample.csv"
# ******************************************************************************

trap = pytrap.TrapCtx()
trap.init(sys.argv, 1, 1)

# Set the list of required fields in received messages.
# This list is an output of e.g. flow_meter - basic flow.
inputspec = ("ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD," +
            "time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 SMTP_2XX_STAT_CODE_COUNT," +
            "uint32 SMTP_3XX_STAT_CODE_COUNT,uint32 SMTP_4XX_STAT_CODE_COUNT," +
            "uint32 SMTP_5XX_STAT_CODE_COUNT,uint32 SMTP_COMMAND_FLAGS," +
            "uint32 SMTP_MAIL_CMD_COUNT,uint32 SMTP_RCPT_CMD_COUNT," +
            "uint32 SMTP_STAT_CODE_FLAGS,uint16 DST_PORT,uint16 SRC_PORT," +
            "uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS," +
            "uint8 TTL,string SMTP_DOMAIN,string SMTP_FIRST_RECIPIENT,string SMTP_FIRST_SENDER")
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
rec = pytrap.UnirecTemplate(inputspec)

# Define a template of alert (can be extended by any other field)
alertspec = "ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,string SMTP_DOMAIN,string SMTP_FIRST_SENDER"
alert = pytrap.UnirecTemplate(alertspec)
# Set the data format to the output IFC
trap.setDataFmt(0, pytrap.FMT_UNIREC, alertspec)

# Allocate memory for the alert, we do not have any variable fields
# so no argument is needed.
alert.createMessage()

# Class for SMTP flow handling
class SMTP_FLOW:
    def __init__(self, rec):
        self.DST_IP = rec.DST_IP
        self.SRC_IP = rec.SRC_IP
        self.BYTES = rec.BYTES
        self.TIME_FIRST = rec.TIME_FIRST
        self.TIME_LAST = rec.TIME_LAST
        self.PACKETS = rec.PACKETS
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
        return "FLOW:\nSRC:" + self.SRC_IP + "\nDST:" + self.DST_IP + "\nCMD_FLAGS:" + self.SMTP_COMMAND_FLAGS + "\n"
    def __str__(self):
        return "FLOW:\nSRC:" + self.SRC_IP + "\nDST:" + self.DST_IP + "\nCMD_FLAGS:" + self.SMTP_COMMAND_FLAGS + "\n"

    # function that detecs whether current flow could be a spam
    # based on SMTP FLAGS, it returns positive value on suspicion
    # flow otherwise negative one
    def is_spam(self):
        spam_flag = 0
        if (int(self.SMTP_STAT_CODE_FLAGS) & int(SC_SPAM) > 0):
        # It contains a spam key word
            spam_flag += 50
            print("SPAM FLAG PRESENT [FROM:{0}{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))
        if (self.SMTP_FIRST_SENDER == "" or self.SMTP_FIRST_RECIPIENT == ""):
            spam_flag += 20
            print("SENDER OR RECIEVER ADDRESS NOT FILLED[FROM:{0}{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))
        # todo more filters
        return spam_flag


# Main loop ********************************************************************
# =========

# Stores data about previous flows and saves them
# to dictionary with SRC_IP as a key
flow_history = {}

checked = 0
alerts = 0

while True:
    # Recieve data from libtrap
    try:
        data = trap.recv()
    except pytrap.FormatChanged as e:
        fmttype, inputspec = trap.getDataFmt(0)
        rec = pytrap.UnirecTemplate(inputspec)
        data = e.data

    if len(data) <= 1:
        break
    rec.setData(data)

    # create a new flow record
    flow = SMTP_FLOW(rec)
    if (flow.is_spam()):
        alerts += 1
    # add it to the history flow trashold
    #flow_history[flow.SRC_IP] = flow
    checked += 1

# Free allocated TRAP IFCs
trap.finalize()
print("Flow scan report:\n")
print("Found {0} in {1} flows\n").format(alerts, checked)
print("Reported X flows.\n")
#import pdb
#pdb.set_trace()
#print(repr(loaded))
