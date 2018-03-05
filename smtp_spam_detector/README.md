# Copying
```
COPYRIGHT AND PERMISSION NOTICE

Copyright (C) 2012-2013 CESNET, z.s.p.o.

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

# Request for comments
## A Reputation score based on SMTP flow parameters
### 1.0 Abstract
The main goal of this project is to unite best current practices from
RFC [821](https://tools.ietf.org/html/rfc821), [1034](https://tools.ietf.org/html/rfc1034), [1035](https://tools.ietf.org/html/rfc1035) and mostly [2025](https://tools.ietf.org/html/rfc2505).

From this BCPs make a rules which will be used to evaluate a score for smtp
entity (sender) that will determinates if it is a spammer or legit MTA.

This score represents a penalization for a bad configuration or failed attempts
to send an email, and other information that we can get from SMTP return codes,
SMTP commands or SMTP flow header attributes.

The penelaization would be applied to the sender identified by
an IP address. If this value will overcome some thrashold the sender would be
flagged as a spammer.

However, not for all smtp entities there's a SMTP flow header extension, if
there is communication over POP3 or IMAP protocol we have only basic flow header.
Therefore we have to use a frequecy analysis to determine wich entities are spammers
and exlude legit mail servers.

In this case we have to compute the ratio of incoming and outcoming traffic for
each entity in timeframe t. If there is huge difference between sent and recived
messeges we can tell this entity is not a legit server.

## 2.0 SMTP Status codes
### 2.1 SMTP_SC 5XX

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

### 2.2 SMTP_SC 4XX

|Code | Description | Score | Comment |
| --- | ----------- | ----- | ------- |
|421|<domain> Service not available, closing transmission channel [This may be a reply to any command if the service knows it must shut down]|||
|450|Requested mail action not taken: mailbox unavailable [E.g., mailbox busy]|||
|451|Requested action aborted: local error in processing|||
|452|Requested action not taken: insufficient system storage|||

>comment

### 2.3 SMTP_SC 2XX

|Code | Description | Score | Comment |
| --- | ----------- | ----- | ------- |
|211|System status, or system help reply|||
|214|Help message [Information on how to use the receiver or the meaning of a particular non-standard command; this reply is useful only to the human user]
|220|<domain> Service ready|||
|221|<domain> Service closing transmission channel|||
|250|Requested mail action okay, completed|||
|251|User not local; will forward to <forward-path>|||

>Comment

## 3.0 Email configuration

It's a bad practise to not fill a sender or reciver address, therefore it should
be checked whether sender and reciver address are filled. Also there should be
checked if there is a server name.

| Attribute | Description | Score | Comment |
| --------- | ----------- | ----- | ------- |
|SMTP_FIRST_SENDER|Address from first MAIL command|||
|SMTP_FIRST_RECIPIENT|Address from first RCPT command|||
|SMTP_DOMAIN|Domain of the server||

>Comment


## 4.0 Frequecy analysis and legit server exlusion
### 4.1 MAIL SERVERS
```
  incoming smtp traffic    +-----------+ outgoing smtp traffic
-------------------------->| SMTP      |-------------------------->
                           | MAIL      |
-------------------------->| SERV      |-------------------------->
                           |           |
-------------------------->|           |-------------------------->
                           +-----------+
```
### 4.2 MALICIOUS SPAM SERVER
```
  incoming smtp traffic    +-----------+ outgoing smtp traffic
                           | SPAM      |-------------------------->
                           | BOT       |-------------------------->
-------------------------->|           |-------------------------->
                           |           |-------------------------->
                           |           |-------------------------->
                           +-----------+
```
### 4.3 Data Model
```
CURRENT DATA MODEL

+--------------------------------+                   +------------------------------+
|    SMTP_Flow (SMTP Header)     |                   |        SMTP_ENTITY           |
+--------------------------------+                   +------------------------------+
| string SMTP_FIRST_RECIPIENT    |                   | ipaddr ID (machine IP)       |
| string SMTP_FIRST_SENDER       |                   | uint32_t incoming            |
| string SMTP_DOMAIN             |      m:n          | uint32_t outgoing            |
| uint32_t SMTP_2XX_STAT_CODE    +-------------------+ list<Flow> sent_history      |
| uint32_t SMTP_3XX_STAT_CODE    |                   | time last_seen               |
| uint32_t SMTP_4XX_STAT_CODE    |                   | double rep (reputation score)|
| uint32_t SMTP_5XX_STAT_CODE    |                   | double traffic_ratio         |
| uint32_t SMTP_COMMAND_FLAGS    |                   |                              |
| uint32_t SMTP_STAT_CODE_FLAGS  |                   |                              |
| uint32_t SMTP_RCPT_CMD_COUNT   |                   | constructor()                |
| uint32_t SMTP_MAIL_CMD_COUNT   |                   | add_new_flow()               |
|                                |                   | update_time()                |
|                                |                   | report_statistics()          |
|                                |                   | is_mail_server()             |
+----------^---------------------+                   |                              |
           |                                         |                              |
           |                                         |                              |
           |                                         +------------------------------+
           |
+----------+-----------+
|      Flow (Basic)    |
+----------------------+
| ipaddr DST_IP        |
| ipaddr SRC_IP        |
| uint16_t DST_PORT    |
| uint16_t SRC_PORT    |
| time TIME_FIRST      |
| time TIME_LAST       |
| uint32_t PACKETS     |
| uint64_t BYTES       |
|                      |
+----------------------+


```
### 4.5 Detector Diagram
```
                                        +----------+
                                        |  START   |
                                        +-----+----+
                                              |             +-----------+
                                              |             |           |
                                              |             |           |
                                              |             |     +-----v-----+
+----------------------------+<---------------+-------------v-----+ FILTERING +---+
|                            |                                    | INTERVAL  |   |
|                            |                                    +-----------+   |
|      Pararell flow         |                                                    |
|      recie^er              V                                                    |
|               +---+-------------------+---+                                     |
|                   |                   |                                         |
|                   |                   |                              +--+-------v-------+--+
|                   |                   |                                 |               |
|            +------+------+    +-------+------+                          |               |
|            | Basic flow  |    | SMTP flow    |                          |               |
|            | reciever    |    | reciver      |                  +-------v------+  +-----v-------+  Pararell
|            +-------------+    +-------+------+                  | PROBING      |  | CLUSTERING  |  proccess
|                   |                   |                         |              |  |             |
|                   |                   |                         +-------+------+  +---------+---+  clustering is very
|                   |                   |                                 |                   |      demanding for computing
|               +---+---------+---------+---+                             |                   |      power (NP+HARD)
|                             |                                           |                   |
|                             |                         +-----------------v--------------+    |
|                   +---------+----------+              | REPUTATION SCORE               |    |
|                   | DataLoader         |              | Analysing whether to add IP as |    |
|                   | helpWorker to sync |              | suspicious or not              |    |
|                   | pararell loading   |              |                                |    |
|                   +---------+----------+              +-----------------+--------------+    |
|                             |                                           |                   |
|                             |                                           |                   |
|                             |                                           |                   |
|                     +-------v-------+                                   |                   |
|           +---------+  BCP FILTER   +--------+                          |                   |
|           |         |               |        |                      +---v---------+---------v---+
|           |         +---------------+        |                                    |
|           |                                  |                                    |
|           |                                  |                                    |
|           |                                  |                                    |
|           |                                  |                         +----------v-------------+
|           V                                  V                         |  Data report / Alerts  |
|   +-------+------------+        +------------+----------+              |                        |
|   | Add SRC_IP to      |        |  Add flow to datapool |              +------------------------+
|   | suspicious IP List |        |  for further analysis |
|   |                    |        |                       |
|   +-------+------------+        +------------+----------+
|           |                                  |
|           |                                  |
|           |                                  |
|           |                                  |
|           |                                  |
+-----------+----------------------------------+
```

>Comment
