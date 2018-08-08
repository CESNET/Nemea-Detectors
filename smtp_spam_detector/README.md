# SMTP Spam Detection

## 1.0 Abstract
It may have seem that these days, the emails are not as popular as the new modern
instant messaging apps (IM) or the social networks. However, we still rely on an
old SMTP protocol, which is the standard protocol for sending e-mails from one
Message Transfer Agent (MTA) to another. The SMTP stands for “Simple Message Transfer
Protocol”, and it has been used since the early 90’s, when the first RFC (RFC [821](https://tools.ietf.org/html/rfc821))
was created. The creators have made a rock solid protocol which is still used for
its reliability. Although its simplicity was a trade off for a security. The simplicity
was abused by the spammers, at that time it was not a big deal as today. With the
e-commerce boom had came many new businesses, scamming methods, and problems.
One of them is the spam which we have to face today in enormous quantities.

The main goal of this project is not to detect spam such as its, but to detect
entities and clusters that are sending it. All this with just a flow data analysis
without interfering a network user privacy. This system contains two modules.
First a static module that will autonomously decide whether the entity is a sender,
legit mail server or potential spammer. The second one is a clustering extension
which will finds similarity between these potential spammers using a SMTP flow
header extension and create a clusters of them.

## 2.0 Installation and requirements
### 2.1 Prerequisites
This module uses pytrap which is part of the [Nemea-Framework](https://github.com/CESNET/Nemea-Framework).\

Additional requirements are:
  - [python3](https://www.python.org/ftp/python/3.7.0/Python-3.7.0.tar.xz)
  - [Nemea-Framework](https://github.com/CESNET/Nemea-Framework)

### 2.2 Installing using Nemea package
[See installation of Nemea system.](https://github.com/CESNET/Nemea#installation)

### 2.3 How to use
SYNOPSIS:
```
   python3 smtp_daemon.py [args] -i [trap ifc in,trap ifc in,trap ifc out]
```

OPTIONS:
```
   -i [t, T, u, b, f] : [interface]
      Specifies the input interface for the detector. The detector uses two input interfaces.
      First for basic flow without smtp header, second one for flows with smtp header extension.
      And third for outpur interface where the output of the dector will be send in json format.

   -t, --interval time
      Defines the probing interval of the entity database. Default value is set to 300 seconds.

   -L, --log /path/to/logging/file
      Defines the path for the logger. Default path is "/var/log/smtp_spam_detector.log".

  --debug [True/False]
      Set the verbose level of the logger to debug while True (For developers). Default value is false.
```
### 2.4 Examples
Run probing every hour with debug output.
```
python3 smtp_daemon.py --debug True --interval 3600 --log /data/smtp_detector/smtp_spam_detector.log -i u:flow_data_source,u:smtp_data_source,u:smtp_detector_out
```
Or with default values:
```
python3 smtp_daemon.py -i u:flow_data_source,u:smtp_data_source,u:smtp_detector_out
```

## 3.0 Output and feature vector in idea reports
### 3.1 Idea report example
```
{
    "Anonymised": false,
    "ByteCount": 138857,
    "Category": [
        "Abusive.Spam"
    ],
    "CeaseTime": "2018-08-06T07:24:39Z",
    "Confidence": "0.95",
    "ConnCount": 14,
    "CreateTime": "2018-08-06T07:25:20Z",
    "DetectTime": "2018-08-06T09:24:48Z",
    "EventTime": "2018-08-06T07:22:59Z",
    "FlowCount": 358,
    "Format": "IDEA0",
    "ID": "b232e5ff-8125-4915-9f8d-3105bf0a6009",
    "Note": "Tags : {'CONN_CNT'}, FV : ['0.0000', '358.0000', '138857.0000', '0.0000', '0.0000', '2133.0000', '14.0000', '0.0000', '5.8805']",
    "PacketCount": 2133,
    "Source": [
        {
            "Email": [
                "<---------@anonymized.com>",
                "<------@anonymized.com>",
                "<----------@anonymized-online.de",
                "<----------------@anonymized.com>",
                "<----------@anonymized.com>"
            ],
            "Hostname": [
                "anonymized.pl",
                "anonymized.pl",
                "anonymized.can",
                "anonymized.edu.pl",
                "anonymized.edu.pl"
            ],
            "IP4": "101.102.103.104",
            "Proto": [
                "SMTP"
            ]
        }
    ]
}
```

### 3.2 Idea report feature vector
   - incoming        number of incoming messages
   - outgoing        number of outgoing messages
   - bytes           total bytes transfered
   - avg_score       average score of the entity
   - traffic_ratio   traffic ratio between sent and received
   - packets         total packets sent
   - conn_cnt        number of communication between unqiue server and this entity
   - conf_lvl        confidence level of this entity being a spam

## 4.0 How it works
### 4.1 Basics
The detector creates a database of entities which are created from flow records
from the given input interfaces. Every entity is uniquely identified with its
own source ip (SRC_IP) address. The detector keeps track of the entity history
and other features that are used for its score evaluation ([see entity data model](#data-model))
which will determine whether the entity is a legit mail server or a spammer.
### 4.2 Score evaluation
The evaluation begins with creating a score for communication of the entity
according to the best current practices and RFC of Mail communication e.g.
RFC [821](https://tools.ietf.org/html/rfc821), [1034](https://tools.ietf.org/html/rfc1034), [1035](https://tools.ietf.org/html/rfc1035) and mostly [2025](https://tools.ietf.org/html/rfc2505).

#### 4.2.1 Average score
```
[Note that this only applies to flow with smtp header ]
```
Average score is evaluated from communication score of each flow with SMTP headers.
Where for each flow is starting with the smtp status codes (e.g SC_SPAM,
SMTP_SC_551 etc.) and each suspicious code is penalized. Next it looks if there
are present email address for SMTP_FIRST_RECIPIENT and SMTP_FIRST_SENDER continued
with the TCP SYN flags validity check.
##### SMTP Status codes
###### SMTP_SC 5XX
It is a permanent error causing transfer termination and return of the mail to\
the sender.This would be the right return of refusing a spam messege.

|Code | Description | Score | Comment |
| --- | ----------- | ----- | ------- |
|500|Syntax error, command unreconcnized |||
|501|Syntax error in parameters or arguments |||
|502|Commmand not implemented |||
|503|Bad sequence of commands |||
|504|Requested action not taken: mailbox unavailable|||
|550|Requested action not taken: mailbox unavailable\[E.g., mailbox not found, no access]|||
|551|User not local; please try <forward-path>|||
|552|Requested mail action aborted: exceeded storage allocation|||
|553|Requested action not taken: mailbox name not allowed\[E.g., mailbox syntax incorrect]|||
|554|Transaction failed |||

>Although, this would be used in perfected world where spammers follows the
>smtp rules.

###### SMTP_SC 4XX

|Code | Description | Score | Comment |
| --- | ----------- | ----- | ------- |
|421|<domain> Service not available, closing transmission channel [This may be a reply to any command if the service knows it must shut down]|||
|450|Requested mail action not taken: mailbox unavailable [E.g., mailbox busy]|||
|451|Requested action aborted: local error in processing|||
|452|Requested action not taken: insufficient system storage|||

###### SMTP_SC 2XX

|Code | Description | Score | Comment |
| --- | ----------- | ----- | ------- |
|211|System status, or system help reply|||
|214|Help message [Information on how to use the receiver or the meaning of a particular non-standard command; this reply is useful only to the human user]
|220|<domain> Service ready|||
|221|<domain> Service closing transmission channel|||
|250|Requested mail action okay, completed|||
|251|User not local; will forward to <forward-path>|||

##### Email configuration

It's a bad practise to not fill a sender or receiver address, therefore it should
be checked whether sender and receiver address are filled. Also there should be
checked if there is a server name.

| Attribute | Description | Score | Comment |
| --------- | ----------- | ----- | ------- |
|SMTP_FIRST_SENDER|Address from first MAIL command|||
|SMTP_FIRST_RECIPIENT|Address from first RCPT command|||
|SMTP_DOMAIN|Domain of the server||

### 4.3 Confidence level
The confidence level evaluation happens for each entity every time t (given by
the parameter --interval) For each entity in the database and determines whether
the entity is a spammer or not. It uses the average score which is described
hereupon. Following with the ratio of sent and received messages. This is done
via the frequency analysis. Considering that the spammers will have more outgoing
communication instead of the incoming.

```
  incoming smtp traffic    +-----------+ outgoing smtp traffic
-------------------------->| SMTP      |-------------------------->
                           | MAIL      |
-------------------------->| SERV      |-------------------------->
                           |           |
-------------------------->|           |-------------------------->
                           +-----------+


  incoming smtp traffic    +-----------+ outgoing smtp traffic
                           | SPAM      |-------------------------->
                           | BOT       |-------------------------->
-------------------------->|           |-------------------------->
                           |           |-------------------------->
                           |           |-------------------------->
                           +-----------+
```

The communication protocol is used to distinguish a legit server from a
spam machine for the reason that the legit servers will more likely communicate
via different protocols like the POP3 or IMAP.

Then it looks at the communication ratio which is then compared with
constant that is computed with the CDF function (TODO dynamically adjust
the ratio threshold). Then it creates an unique list which is basically
a connection count value.

The evaluated score is than adjusted with non-linear function so the score responds
with the percentage value. The function is described hereunder.
```
                                      1
                                  ----------
                  conf_lvl(x) :=  e^-x/2 + 1
```
Which will result to 99% confidence level at 10 points and approximately 0%
at -5 points, where x is the entity score.

##<a name=data-model><\a> 5.0 Data model
```
+--------------------------------+                   +------------------------------+
|    SMTP_Flow (SMTP Header)     |                   |        SMTP_ENTITY           |
+--------------------------------+                   +------------------------------+
| string SMTP_FIRST_RECIPIENT    |                   | ipaddr id                    |
| string SMTP_FIRST_SENDER       |                   | SMTP_Flow smtp_pool          |
| string SMTP_DOMAIN             |      m:n          | Flow basic_pool              |
| uint32_t SMTP_2XX_STAT_CODE    +-------------------+ uint32_t incoming            |
| uint32_t SMTP_3XX_STAT_CODE    |                   | uint32_t outgoing            |
| uint32_t SMTP_4XX_STAT_CODE    |                   | size_t bytes                 |
| uint32_t SMTP_5XX_STAT_CODE    |                   | size_t packets               |
| uint32_t SMTP_COMMAND_FLAGS    |                   | double avg_score             |
| uint32_t SMTP_STAT_CODE_FLAGS  |                   | uint32_t conn_cnt            |
| uint32_t SMTP_RCPT_CMD_COUNT   |                   | double conf_lvl              |
| uint32_t SMTP_MAIL_CMD_COUNT   |                   | double traffic_ratio         |
|                                |                   | list<double> feature_vector  |
|                                |                   | list\<string> tags           |
|                                |                   | time time_start              |
+----------^---------------------+                   | time time_end                |
           |                                         | time time_window             |
           |                                         |                              |
           |                                         |                              |
           |                                         | add_new_flow(flow)           |
+----------+-----------+                             | update_time(flow)            |
|      Flow (Basic)    |                             | set_conf(score)              |
+----------------------+                             | is_spam()                    |
| ipaddr DST_IP        |                             | get_...()                    |
| ipaddr SRC_IP        |                             +------------------------------+
| uint16_t DST_PORT    |
| uint16_t SRC_PORT    |
| time TIME_FIRST      |
| time TIME_LAST       |
| uint32_t PACKETS     |
| uint64_t BYTES       |
|                      |
+----------------------+

```
## 6.0 Authors
Ladislav Macoun - Initial work <ladislavmacoun@gmail.com>\
Tomas Cejka - Project leader <cejkat@cesnet.cz>\
Vaclav Bartos - Project consultant <bartos@cesnet.cz>

### 6.1 Contribution and coding style
This module uses PEP 8 coding style

## 7.0 License and acknowledgments
### 7.1 License
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
### 7.2 Acknowledgments
This was supported by the CTU grant No. SGS17/212/OHK3/3T/18 funded by internal grant of CTU of Prague.
