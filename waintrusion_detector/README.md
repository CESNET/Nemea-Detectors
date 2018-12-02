# Web Application Intrusion Detection

## 1.0 Abstract

The number of attacks on web applications grew rapidly over the last few years. Based on data gathered by Verizon company, this attack vector allowed attackers to steal data from more than four hundred companies and those are only incidents with confirmed data leakage.

The main goal of this project is to detect attacks on web applications in their early stages, so that incident response teams can respond and stop the attacks before they cause any major damage.

## 2.0 Installation and requirements

### 2.1 Prerequisites

### 2.1.1 Components
This module uses pytrap which is part of the [Nemea-Framework](https://github.com/CESNET/Nemea-Framework).

Additional requirements are:
  - [python2.7](https://www.python.org/ftp/python/2.7.15/Python-2.7.15.tar.xz)
  - [Nemea-Framework](https://github.com/CESNET/Nemea-Framework)

### 2.1.2 Directory Structure

The module does not have configurable directory structure. It requires following directory structure.

```
WAIDETECTORDATADIR/
  - rules
  - data
```

### 2.2 Installing using NEMEA package

[See installation of NEMEA system.](https://nemea.liberouter.org/doc/installation/)

### 2.3 How to use

SYNOPSIS:

```
   python waintrusion_detector.py [args] -i [IFCSPEC]
```

OPTIONS:

```
   -i, --ifcspec [IFCSPEC]
      The module has 1 input IFC (HTTP extended flow records) and 1 output IFC.
      See https://nemea.liberouter.org/trap-ifcspec/ for help.

   -r, --rule
      Defines enabled detection rules. Default value is set to all.

   -nr, --norule
      Defines disabled detection rules. This option is mutually exclusive to the -r, --rule option. Default value is set to none.

   -ursrc [ipfixcol/flow_meter]
      Defines the source of unirec messages. Default source is ipfixcol.

   -v
      If set, prints statistics and every detected malicious event on screen.
```

RULES:

```
   request_method_enforcement
      Detects usage of unlisted HTTP method.

   request_scanner_detection
      Detects active vulnerability scanners.

   request_protocol_enforcement
      Detects HTTP requests whose format does not follow HTTP protocol.

   request_protocol_attack
      Detects misuse of HTTP protocol.

   request_application_attack_lfi
      Detects local file inclusion attacks.

   request_application_attack_rfi
      Detects remote file inclusion attacks.

   request_application_attack_rce
      Detects remote code execution attacks.

   request_application_attack_php
      Detects attacks using PHP.

   request_application_attack_xss
      Detects cross site scripting attacks.

   request_application_attack_sqli
      Detects SQL injection attacks.

   request_application_attack_session_fixation
      Detects session fixation attacks.
```

### 2.4 Required Input UniRec Message Format

#### 2.4.1 flow_meter

ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL,string HTTP_METHOD,string HTTP_HOST,string HTTP_URL,string HTTP_USER_AGENT,string HTTP_REFERER,uint16 HTTP_RESPONSE_CODE,string HTTP_CONTENT_TYPE

#### 2.4.2 ipfixcol
ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 HTTP_REQUEST_AGENT_ID,uint32 HTTP_REQUEST_METHOD_ID,uint32 HTTP_RESPONSE_STATUS_CODE,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL,string HTTP_REQUEST_AGENT,string HTTP_REQUEST_HOST,string HTTP_REQUEST_REFERER,string HTTP_REQUEST_URL,string HTTP_RESPONSE_CONTENT_TYPE

### 2.5 Examples

Run realtime detection of SQL injection attacks on flow data captured and provided by flow_meter and print statistics and detected malicious events.

```
/usr/bin/nemea/waintrusion_detector -r request_application_attack_sqli -i u:flow_data_src,u:malicious_events_dst -v -ursrc flow_meter
```

Run realtime detection of all but protocol attacks on flow data provided by ipfixcol.

```
/usr/bin/nemea/waintrusion_detector -nr request_protocol_enforcement,request_protocol_attack -i u:flow,f:~/output.trapcap
```

Or with default values:

```
/usr/bin/nemea/waintrusion_detector -i u:flow_data_src,u:malicious_events_dst
```

which will start detector with all rules enabled. Taking input data provided by IPFIX collector from the UNIX socket `flow_data_src` for flows with HTTP headers, sending output unirec messages to `malicious_events_dst` UNIX socket.

## 3.0 How it works

### 3.1 Basics

The module continuously receives realtime flow data, parses them, uses its own detection engine to analyse them and sends a message about any potential malicious event. The analysis examines URI, HTTP method, HTTP response code and several HTTP headers - host, referer, user-agent and content-type. The module does not store any sensitive data.

The detection engine of the module loads data and signatures required for the analysis and evaluates the signatures one by one till there are no signatures left or there is a match. If there is a match, it means that a potential malicious event has been detected and the module sends a message about it to its output interface. If there are no signatures left, the module takes another input data and repeats the procedure.

### 3.2 Creating/modifying signatures

The module allows creation/modification of signatures for any available rule without changes in code. There are two types of signatures:

   - dynamic that are stored in files and separated by end of line.
   - hardcoded that are located in the code of the module.

Both can be dynamically modified. 

#### 3.2.1 Dynamic Signatures

Dynamic signature can be created just by appending a new line to the signature file of a desired rule.

Each signature has following structure:

```
signature_regular_expression ** searchable_fields_separated_by_comma
```

List of searchable fields:

```
   HTTP_URL
   HTTP_URL_RAW
      UniRec field HTTP_URL|HTTP_REQUEST_URL depends on the flow data source

   HTTP_USER_AGENT
      UniRec field HTTP_USER_AGENT|HTTP_REQUEST_AGENT depends on the flow data source

   HTTP_REFERER
      UniRec field HTTP_REFERER|HTTP_REQUEST_REFERER depends on the flow data source

   HTTP_HOST
      UniRec field HTTP_HOST|HTTP_REQUEST_HOST depends on the flow data source

   HTTP_METHOD
      UniRec field HTTP_METHOD|HTTP_REQUEST_METHOD_ID depends on the flow data source

   HTTP_METHOD_AND_URL
   HTTP_URL_QUERY_STRING
   HTTP_URL_ARGS
   HTTP_URL_ARGS_NAMES
   HTTP_URL_FILENAME
```

Available files containing signatures belonging to listed rules:

```
   request-method-enforcement.data [rule: request_method_enforcement]
      Detects usage of unlisted HTTP method.

   request-scanner-detection.data [rule: request_scanner_detection]
      Detects active vulnerability scanners.

   request-protocol-enforcement.data [rule: request_protocol_enforcement]
      Detects HTTP requests whose format does not follow HTTP protocol.

   request-protocol-attack.data [rule: request_protocol_attack]
      Detects misuse of HTTP protocol.

   request-application-attack-lfi.data [rule: request_application_attack_lfi]
      Detects local file inclusion attacks.

   request-application-attack-rfi.data [rule: request_application_attack_rfi]
      Detects remote file inclusion attacks.

   request-application-attack-rce.data [rule: request_application_attack_rce]
      Detects remote code execution attacks.

   request-application-attack-php.data [rule: request_application_attack_php]
      Detects attacks using PHP.

   request-application-attack-xss.data [rule: request_application_attack_xss]
      Detects cross site scripting attacks.

   request-application-attack-sqli.data [rule: request_application_attack_sqli]
      Detects SQL injection attacks.

   request-application-attack-session-fixation.data [rule: request_application_attack_session_fixation]
      Detects session fixation attacks.
```

#### 3.2.2 Hardcoded Signatures

Hardcoded signatures are list-based and the data are stored in files. Hardcoded signatures can be modified just by appending a value to the end of the file belonging to the signature.

Available data files belonging to hardcoded signatures of listed rules:

```
   allowed-http-methods.data [rule: request_method_enforcement]
      List of allowed HTTP methods.

   scanners-user-agents.data [rule: request_scanner_detection]
      List of values used by vulnerability scanners in HTTP header User-Agent.

   scanners-urls.data [rule: request_scanner_detection]
      List of values used by vulnerability scanners in HTTP URI.

   scanners-headers.data [rule: request_scanner_detection]
      List of values used by vulnerability scanners in various HTTP header fields.

   restricted-files.data [rule: request_application_attack_lfi]
      List of restricted files.

   lfi-os-files.data [rule: request_application_attack_lfi]
      List of absolute/relative paths to OS files.

   windows-powershell-commands.data [rule: request_application_attack_rce]
      List of powershell commands.

   unix-shell.data [rule: request_application_attack_rce]
      List of Unix shell commands.

   php-config-directives.data [rule: request_application_attack_php]
      List of PHP config directives.

   php-variables.data [rule: request_application_attack_php]
      List of global PHP variables.

   php-function-names-933150.data [rule: request_application_attack_php]
      List of PHP function names.
```

### 3.3 Converting UniRec Messages to IDEA

In order to get detected malicious events into WARDEN, UniRec messages generated by the detector module need to be converted into a format acceptable by the system. The acceptable format is called IDEA. For the conversion, there is a module called waintrusion_detector2idea.py, which is a part of the project.

Format of a UniRec message generated by the detector:

```
   ipaddr SRC_IP
      IP address of the attacker.
   
   ipaddr DST_IP
      IP address of the victim.
   
   uint16 DST_PORT
      Port number of the victim.
   
   uint16 SRC_PORT
      Port number of the attacker.
   
   uint8 PROTOCOL
      Transport Protocol.
   
   time EVENT_TIME
      Date and time the malicious event was detected.
   
   string WAI_RULE
      Rule that raised the malicious event.

   string WAI_MALICIOUS_FIELD
      Name of a field that contains the malicious value.
   
   string WAI_MALICIOUS_VALUE
      The detected malicious value.
```

Conversion example:

```
waintrusion_detector2idea.py -i f:~/input.trapcap -n cz.cesnet.nemea.waintrusion_detector --config ~/config.yaml
```

## 4.0 Team

* Tomas Duracka - Author `<t.duracka@gmail.com>`
* Tomas Cejka - Project leader `<cejkat@cesnet.cz>`

## 5.0 License

```
COPYRIGHT AND PERMISSION NOTICE

Copyright (C) 2016-2018 CESNET, z.s.p.o.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.
  3. Neither the name of the Company nor the names of its contributors may
     be used to endorse or promote products derived from this software
     without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this product
may be distributed under the terms of the GNU General Public License (GPL)
version 2 or later, in which case the provisions of the GPL apply INSTEAD OF
those given above.

This software is provided "as is", and any express or implied warranties,
including, but not limited to, the implied warranties of merchantability
and fitness for a particular purpose are disclaimed. In no event shall the
company or contributors be liable for any direct, indirect, incidental,
special, exemplary, or consequential damages (including, but not limited to,
procurement of substitute goods or services; loss of use, data, or profits;
or business interruption) however caused and on any theory of liability,
whether in contract, strict liability, or tort (including negligence or
otherwise) arising in any way out of the use of this software, even if
advised of the possibility of such damage.
```

