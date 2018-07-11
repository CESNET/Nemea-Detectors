#!/usr/bin/env python

import pytrap
import sys
import re
import os
import urllib
import urlparse
import argparse
import time

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

#ModSecurity CRS Rule - HTTP Request Method Enforcement
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
REQUEST_METHOD_ENFORCEMENT = "request_method_enforcement"

#ModSecurity CRS Rule - HTTP Request Scanner Detection
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-913-SCANNER-DETECTION.conf
REQUEST_SCANNER_DETECTION = "request_scanner_detection"

#ModSecurity CRS Rule - Protocol Enforcement
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
REQUEST_PROTOCOL_ENFORCEMENT = "request_protocol_enforcement"

#ModSecurity CRS Rule - Protocol Attack
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-921-PROTOCOL-ATTACK.conf
REQUEST_PROTOCOL_ATTACK = "request_protocol_attack"

#ModSecurity CRS Rule - Application Attack - LFI
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
REQUEST_APPLICATION_ATTACK_LFI = "request_application_attack_lfi"

#ModSecurity CRS Rule - Application Attack - RFI
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
REQUEST_APPLICATION_ATTACK_RFI = "request_application_attack_rfi"

#ModSecurity CRS Rule - Application Attack - RCE
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
REQUEST_APPLICATION_ATTACK_RCE = "request_application_attack_rce"

#ModSecurity CRS Rule - Application Attack - PHP
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
REQUEST_APPLICATION_ATTACK_PHP = "request_application_attack_php"

#ModSecurity CRS Rule - Application Attack - XSS
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
REQUEST_APPLICATION_ATTACK_XSS = "request_application_attack_xss"

#ModSecurity CRS Rule - Application Attack - SQLI
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
REQUEST_APPLICATION_ATTACK_SQLI = "request_application_attack_sqli"

#ModSecurity CRS Rule - Application Attack - SESSION FIXATION
#https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
REQUEST_APPLICATION_ATTACK_SESSION_FIXATION = "request_application_attack_session_fixation"

#globals - all detection rules available in module
availableRules = [
    REQUEST_METHOD_ENFORCEMENT, REQUEST_SCANNER_DETECTION,
    REQUEST_PROTOCOL_ENFORCEMENT, REQUEST_PROTOCOL_ATTACK,
    REQUEST_APPLICATION_ATTACK_RFI, REQUEST_APPLICATION_ATTACK_SQLI,
    REQUEST_APPLICATION_ATTACK_RCE, REQUEST_APPLICATION_ATTACK_PHP,
    REQUEST_APPLICATION_ATTACK_XSS,
    REQUEST_APPLICATION_ATTACK_SESSION_FIXATION,
    REQUEST_APPLICATION_ATTACK_LFI
]

#constants - http field names - need to be the same strings as in rule files
HTTP_URL = "HTTP_URL"
HTTP_USER_AGENT = "HTTP_USER_AGENT"
HTTP_REFERER = "HTTP_REFERER"
HTTP_HOST = "HTTP_HOST"
HTTP_METHOD = "HTTP_METHOD"

#custom variables for analysis by detection signatures
HTTP_METHOD_AND_URL = "HTTP_METHOD_AND_URL"
HTTP_URL_RAW = "HTTP_URL_RAW"
HTTP_URL_ARGS = "HTTP_URL_ARGS"
HTTP_URL_ARGS_NAMES = "HTTP_URL_ARGS_NAMES"
HTTP_URL_FILENAME = "HTTP_URL_FILENAME"
HTTP_URL_QUERY_STRING = "HTTP_URL_QUERY_STRING"

#web application intrusion - alert fields
WAI_RULE = "WAI_RULE"
WAI_MALICIOUS_FIELD = "WAI_MALICIOUS_FIELD"
WAI_MALICIOUS_VALUE = "WAI_MALICIOUS_VALUE"

#wrapper for all available HTTP information from HTTP Request - rec cannot be extended
HTTPRequest = {
    HTTP_METHOD: "", HTTP_URL: "", HTTP_HOST: "", HTTP_USER_AGENT: "", HTTP_REFERER: "",
    HTTP_METHOD_AND_URL: "", HTTP_URL_RAW: "", HTTP_URL_ARGS: "", HTTP_URL_ARGS_NAMES: "",
    HTTP_URL_FILENAME: ""
}

parser = argparse.ArgumentParser(description="NEMEA Detector for Web Application Intrusion Detection.")
parser.add_argument("-i", "--ifcspec", metavar="IFCSPEC", dest="ifcspec", required=True, help="TRAP IFC specifier")
group = parser.add_mutually_exclusive_group(required=False)
group.add_argument("-r", "--rule", metavar="RULE", dest="enabledRules", nargs="*", default=["all"], choices=["all"]+availableRules, help="Enabled detection rules (default: all). Available detection rules are: "+", ".join(availableRules))
group.add_argument("-nr", "--norule", metavar="RULE", dest="disabledRules", nargs="*", default=None, choices=availableRules, help="Disabled detection rules (default: none). Available detection rules are: "+", ".join(availableRules))
parser.add_argument("-ursrc", metavar="URSOURCE", dest="ursrc", default="ipfixcol", choices=["ipfixcol", "flow_meter"], help="UniRec message source (default: unirec). Available UniRec sources are: ipfixcol, flow_meter")
parser.add_argument("-v", "--verbose", dest="verbose", default=False, action="store_const", const=True, help="Show Alert Messages")
args = parser.parse_args()

#UniRecord templates differ with sources
if args.ursrc == "flow_meter":
    UR_HTTP_URL = "HTTP_URL"
    UR_HTTP_USER_AGENT = "HTTP_USER_AGENT"
    UR_HTTP_REFERER = "HTTP_REFERER"
    UR_HTTP_HOST = "HTTP_HOST"
    UR_HTTP_METHOD = "HTTP_METHOD"
else:
    UR_HTTP_URL = "HTTP_REQUEST_URL"
    UR_HTTP_USER_AGENT = "HTTP_REQUEST_AGENT"
    UR_HTTP_REFERER = "HTTP_REQUEST_REFERER"
    UR_HTTP_HOST = "HTTP_REQUEST_HOST"
    UR_HTTP_METHOD = "HTTP_REQUEST_METHOD_ID"

def prepare_detection_signatures(rules):
    signatures = []
    for rule in rules:
        ruleFile = SCRIPT_PATH + "/rules/" + rule.replace("_", "-") + ".data"
        if os.path.isfile(ruleFile):
            with open(ruleFile) as f:
                ruleSignatures = f.read().splitlines()
                for signature in ruleSignatures:
                    if not signature: continue #skip empty line

                    #the delimiter was chosen like this due to its invalidity as regex expression
                    signature, HTTPFields = signature.split(" ** ")
                    signatures.append([rule, signature, HTTPFields.split(",")])

        if rule == REQUEST_METHOD_ENFORCEMENT:
            dataFile = SCRIPT_PATH + "/data/allowed-http-methods.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)^(?!(" + "|".join(map(re.escape, list(filter(None, data)))) + ")$)", [HTTP_METHOD]])

        elif rule == REQUEST_SCANNER_DETECTION:
            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/scanners-user-agents.data
            dataFile = SCRIPT_PATH + "/data/scanners-user-agents.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)(\\b(" + "|".join(map(re.escape, list(filter(None, data))))+")[/0-9.]*)", [HTTP_USER_AGENT]])

            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/scanners-urls.data
            dataFile = SCRIPT_PATH + "/data/scanners-urls.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_FILENAME, HTTP_URL_ARGS]])

            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/scanners-headers.data
            dataFile = SCRIPT_PATH + "/data/scanners-headers.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_HOST, HTTP_USER_AGENT, HTTP_REFERER]])

        elif rule == REQUEST_APPLICATION_ATTACK_LFI:
            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/restricted-files.data
            dataFile = SCRIPT_PATH + "/data/restricted-files.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_FILENAME]])

            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/lfi-os-files.data
            dataFile = SCRIPT_PATH + "/data/lfi-os-files.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_ARGS, HTTP_URL_ARGS_NAMES]])

        elif rule == REQUEST_APPLICATION_ATTACK_RCE:
            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/windows-powershell-commands.data
            dataFile = SCRIPT_PATH + "/data/windows-powershell-commands.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_ARGS, HTTP_URL_ARGS_NAMES]])

            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/unix-shell.data
            dataFile = SCRIPT_PATH + "/data/unix-shell.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_ARGS, HTTP_URL_ARGS_NAMES]])

        elif rule == REQUEST_APPLICATION_ATTACK_PHP:
            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/php-config-directives.data
            dataFile = SCRIPT_PATH + "/data/php-config-directives.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_ARGS, HTTP_URL_ARGS_NAMES]])

            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/php-variables.data
            dataFile = SCRIPT_PATH + "/data/php-variables.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_ARGS, HTTP_URL_ARGS_NAMES]])

            #data source: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/rules/php-function-names-933150.data
            dataFile = SCRIPT_PATH + "/data/php-function-names-933150.data"
            if os.path.isfile(dataFile):
                with open(dataFile) as f:
                    data = f.read().splitlines()
                    #data includes empty lines removed by list(filter(None, data)), strings are then escaped for regex usage
                    signatures.append([rule, "(?i)" + "|".join(map(re.escape, list(filter(None, data)))), [HTTP_URL_ARGS, HTTP_URL_ARGS_NAMES]])
    return signatures

#prepare detection signatures based on module arguments
if args.disabledRules:
    enabledRules = list(set(availableRules)-set(args.disabledRules))
else:
    enabledRules = availableRules if "all" in args.enabledRules else args.enabledRules

signatures = prepare_detection_signatures(enabledRules)

#initialize input and output interfaces
trap = pytrap.TrapCtx()
trap.init(sys.argv, 1, 1)

# Set the list of required fields in received messages.
if args.ursrc == "flow_meter":
    inputspec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL,string HTTP_METHOD,string HTTP_HOST,string HTTP_URL,string HTTP_USER_AGENT,string HTTP_REFERER,uint16 HTTP_RESPONSE_CODE,string HTTP_CONTENT_TYPE"
else:
    inputspec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 HTTP_REQUEST_AGENT_ID,uint32 HTTP_REQUEST_METHOD_ID,uint32 HTTP_RESPONSE_STATUS_CODE,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL,string HTTP_REQUEST_AGENT,string HTTP_REQUEST_HOST,string HTTP_REQUEST_REFERER,string HTTP_REQUEST_URL,string HTTP_RESPONSE_CONTENT_TYPE"

trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
rec = pytrap.UnirecTemplate(inputspec)

# Define a template of alert (can be extended by any other field)
alertspec = "ipaddr SRC_IP,ipaddr DST_IP,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,time EVENT_TIME, string WAI_RULE, string WAI_MALICIOUS_FIELD, string WAI_MALICIOUS_VALUE"
trap.setDataFmt(0, pytrap.FMT_UNIREC, alertspec)
alert = pytrap.UnirecTemplate(alertspec)

# Allocate memory for the alert
#variable field: WAI_RULE: 64, WAI_MALICIOUS_FIELD: 32, WAI_MALICIOUS_VALUE: 256
#alert.createMessage(352)

totalAlerts = 0
def send_alert(rec, maliciousEvent):
    global alert, totalAlerts

    #fill-in alert:
    alert.createMessage(len(str(maliciousEvent[WAI_RULE])) + len(str(maliciousEvent[WAI_MALICIOUS_FIELD])) + len(str(maliciousEvent[WAI_MALICIOUS_VALUE])))

    alert.SRC_IP = rec.SRC_IP
    alert.DST_IP = rec.DST_IP
    alert.SRC_PORT = rec.SRC_PORT
    alert.DST_PORT = rec.DST_PORT
    alert.PROTOCOL = rec.PROTOCOL
    alert.EVENT_TIME = rec.TIME_LAST
    #rule that detected the intrusion
    alert.WAI_RULE = str(maliciousEvent[WAI_RULE])
    #malicious http request field in which a potential intrusion was detected
    alert.WAI_MALICIOUS_FIELD = str(maliciousEvent[WAI_MALICIOUS_FIELD])
    #malicious value detected as potential intrusion
    alert.WAI_MALICIOUS_VALUE = str(maliciousEvent[WAI_MALICIOUS_VALUE])

    if args.verbose:    
        print("--------------------------------------------------------------------------\r\n")
        print("New Malicious Event Detected: \r\n\r\nDetection Rule: " + str(maliciousEvent[WAI_RULE]) + "\r\nMalicious Field: " + str(maliciousEvent[WAI_MALICIOUS_FIELD]) + "\r\nMalicious Value: " + str(maliciousEvent[WAI_MALICIOUS_VALUE]) + "\r\n")

    # send alert
    trap.send(alert.getData(), 0)
    totalAlerts += 1

def do_detection(rec, HTTPRequest):
    #todo: napsat do diplomky, ze u kazdeho pozadavku hlasim pouze prvni nalezeny utok, nikoli vsechny detekovane
    #todo: napsat do diplomky, ze pro snizeni poctu false positives doporucuju vypnout protocol enforcement
    #todo: do diplomky priklad volani: python waintrusion_detector.py -i f:~/Downloads/http-duracka/http_data.00.trapcap,f:~/Documents/diplomka/output.trapcap -nr request_protocol_enforcement
    #todo: popremyslet o vyhozeni user agenta urlgrabber/3.10 - generuje dost hlaseni

    #HTTP Parameter Pollution Test - generates more false positives than true positives
    #queryParams = urlparse.parse_qs(HTTPRequest[HTTP_URL_QUERY_STRING])
    #for field, fieldValue in queryParams.items():
    #    if len(fieldValue) > 1:
    #        send_alert(rec, {WAI_RULE: REQUEST_PROTOCOL_ATTACK, WAI_MALICIOUS_FIELD: HTTP_URL_QUERY_STRING, WAI_MALICIOUS_VALUE: field})
    #        return

    #evaluate prepared global signatures
    for rule, signature, fields in signatures:
        #evaluate signature for each http field separately
        for field in fields:
            fieldValue = HTTPRequest.get(field, "")
            if isinstance(fieldValue, list):
                fieldValues = fieldValue
                for fieldValue in fieldValues:
                    if re.search(signature, fieldValue):
                        send_alert(rec, {WAI_RULE: rule, WAI_MALICIOUS_FIELD: field, WAI_MALICIOUS_VALUE: fieldValue})
                        return
            else:
                if re.search(signature, fieldValue):
                    send_alert(rec, {WAI_RULE: rule, WAI_MALICIOUS_FIELD: field, WAI_MALICIOUS_VALUE: fieldValue})
                    return

#time measurement
start = time.time()

#152.63, 148.56, 156.15, 156.26, 158.71 pri 235193 requestech s odesilanim alertu verbose, bez protocol_enforcement testu se zasilanim alertu do souboru, 788 alertu, odesilani alertu nema na dobu vliv
#4.47s request_method_enforcement, 0 nalezu
#14.55s request_scanner_detection, 257 nalezu
#9.82s request_protocol_attack, 51 nalezu
#65.05s request_application_attack_lfi, 30 nalezu - zrevidovat, presny ale strasne pomaly
#6.05s request_application_attack_rfi, 32 nalezu
#25.74s request_application_attack_rce, 379 nalezu - zrevidovat, vypada na dost false positives
#23.16s request_application_attack_php, 23 nalezu - zrevidovat, vypada na dost false positives
#26.86s request_application_attack_xss, 16 nalezu - zrevidovat, vypada na dost false positives
#16.02s request_application_attack_sqli, 151 nalezu
#5.04s request_application_attack_session_fixation, 0 nalezu

totalRequests = 0

# Main loop
while True:
    try:
        #receive message and allocate memory for it
        data = trap.recv()
    except pytrap.FormatChanged as e:
        fmttype, inputspec = trap.getDataFmt(0)
        rec = pytrap.UnirecTemplate(inputspec)
        data = e.data
    except pytrap.FormatMismatch:
        print("Error: output and input interfaces data format or data specifier mismatch")
        break
    except pytrap.Terminated:
        print("Error: TRAP Terminated.")
        break
    except pytrap.TrapError:
        print("Error: TRAP Error.")
        break

    if len(data) <= 1:
        break

    rec.setData(data)

    #https communication is not part of the detection
    if rec.SRC_PORT == 443 or rec.DST_PORT == 443: continue

    #http response messages are not part of the detection
    if args.ursrc == "flow_meter":
        if rec.HTTP_RESPONSE_CODE: continue
    else:
        if rec.HTTP_RESPONSE_STATUS_CODE: continue
        if rec.HTTP_REQUEST_METHOD_ID == 11: continue #unknown method associated with https

    #map http method TODO: je potreba zjistit z flowmon exporteru mapovani method_id na method
    if args.ursrc == "ipfixcol":
        HTTPMethodMapping = {1: "GET", 2: "HEAD", 4: "POST"}
        HTTPMethodID = getattr(rec, UR_HTTP_METHOD, "")
        HTTPRequest[HTTP_METHOD] = "GET" if not HTTPMethodID in HTTPMethodMapping.keys() else HTTPMethodMapping[HTTPMethodID]
    else:
        HTTPRequest[HTTP_METHOD] = getattr(rec, HTTP_METHOD, "")

    #initialize HTTPRequest fields for analysis - getattr is due to various templates 
    HTTPRequest[HTTP_URL] = getattr(rec, UR_HTTP_URL, "")
    HTTPRequest[HTTP_HOST] = getattr(rec, UR_HTTP_HOST, "")
    HTTPRequest[HTTP_USER_AGENT] = getattr(rec, UR_HTTP_USER_AGENT, "")
    HTTPRequest[HTTP_REFERER] = getattr(rec, UR_HTTP_REFERER, "")

    #prepare and initialize extended HTTPRequest fields
    HTTPUrlParts = urlparse.urlparse(HTTPRequest[HTTP_URL])
    HTTPRequest[HTTP_URL_QUERY_STRING] = HTTPUrlParts.query
    HTTPRequest[HTTP_METHOD_AND_URL] = HTTPRequest[HTTP_METHOD] + " " + HTTPRequest[HTTP_URL]
    HTTPRequest[HTTP_URL_FILENAME] = HTTPUrlParts.path

    queryParams = urlparse.parse_qs(HTTPUrlParts.query)
    HTTPRequest[HTTP_URL_ARGS_NAMES] = list(queryParams.keys())

    #queryParams.values() is a list of lists - convert lists to strings
    #if a param has multiple values, add them all without duplicates
    queryParamsValues = []
    for queryParamValues in list(queryParams.values()):
        queryParamsValues = list(set(queryParamsValues).union(queryParamValues))
    HTTPRequest[HTTP_URL_ARGS] = queryParamsValues

    #unquote and decode all HTTPRequest params
    #for k, field in HTTPRequest.items():
    #    if isinstance(field, list):
    #        for idx, value in enumerate(field):
    #            HTTPRequest[k][idx] = urllib.unquote(value)
    #    else:
    #        HTTPRequest[k] = urllib.unquote(field)

    HTTPRequest[HTTP_URL_RAW] = getattr(rec, UR_HTTP_URL, "")

    #detection
    do_detection(rec, HTTPRequest)
    totalRequests += 1

if args.verbose:
    print("Elapsed Time: " + str(time.time() - start))
    print("Total Requests: " + str(totalRequests))
    print("Total Alerts: " + str(totalAlerts))

# Free allocated TRAP IFCs - free C memory not Python memory - Python memory (UniRec) gets freed using garbage collector
trap.finalize()

