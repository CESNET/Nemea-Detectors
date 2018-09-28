#!/usr/bin/env python3
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
SMTP_STATUS_CODES = {
    "SMTP_SC_211" : 0x00000001,
    "SMTP_SC_214" : 0x00000002,
    "SMTP_SC_220" : 0x00000004,
    "SMTP_SC_221" : 0x00000008,
    "SMTP_SC_250" : 0x00000010,
    "SMTP_SC_251" : 0x00000020,
    "SMTP_SC_252" : 0x00000040,
    "SMTP_SC_354" : 0x00000080,
    "SMTP_SC_421" : 0x00000100,
    "SMTP_SC_450" : 0x00000200,
    "SMTP_SC_451" : 0x00000400,
    "SMTP_SC_452" : 0x00000800,
    "SMTP_SC_455" : 0x00001000,
    "SMTP_SC_500" : 0x00002000,
    "SMTP_SC_501" : 0x00004000,
    "SMTP_SC_502" : 0x00008000,
    "SMTP_SC_503" : 0x00010000,
    "SMTP_SC_504" : 0x00020000,
    "SMTP_SC_550" : 0x00040000,
    "SMTP_SC_551" : 0x00080000,
    "SMTP_SC_552" : 0x00100000,
    "SMTP_SC_553" : 0x00200000,
    "SMTP_SC_554" : 0x00400000,
    "SMTP_SC_555" : 0x00800000,
    "SC_UNKNOWN" : 0x80000000
}

SC_SPAM = 0x40000000

# Email Protocols Ports
# =====================
email_protocols =  { 'POP3' : 143, 'POP3_SECURE' : 995,
                     'IMAP' : 143, 'IMAP_SECURE' : 993,
                     'SMTP' :  25, 'SMTP_SECURE' : 465
                   }
# ******************************************************************************
# Global variables
# ================
#SIMILARITY_INDEX = 0.8
CLEAN_INTERVAL = 5*60          # How often should data pool get cleaned
MAX_ALLOWED_SERVERS = 10       # Number of maximum allowed server that mail
                               # server is able to communicate
PROBE_INTERVAL = 5*60
MAX_WORKERS = 2                # Maximum of allowed threads for workers
PATH_DEBUG_LOG = "/var/log/smtp_spam_detector.log"
# ******************************************************************************
# Detector signal handler
is_running = False


