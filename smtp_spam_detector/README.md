# SMTP SPAM BOT DETECTION
@author Ladislav Macoun <macoulad@fit.cvut.cz>

@org CESNET / CVUT

## Table of Contents
* 0.0 License
* 1.0 Intro
* 2.0 Algoritmus
* 3.0 SPAM and SPAM BOT definition according to this module
* 4.0 Data analysis
* X.X XXXXXXXXXXXXX
* X.0 Conclusion

## 0.0 License
   TBD

## 1.0 Intro
   Function of this detector
   =========================
   ...

   How to use
   ==========
   The module is implemented on TRAP platform so you have to specify TRAP
   interfaces correctly. Then you can specify one of the parameters listed below.

   Parameters:
   TBD
   Example:
   TBD
   Usage:
   TBD
   ...

## 2.0 Algoritmus
## Ways of spam bot recognition
```
a) RFC Filtering
   =============
   (Applying best current practices for avoiding spam)
   Filtering flow recordis through multiple RFC rules. If any of these fails add
   that IP to database as a supicios server for further analysis.
   Current filters:
      possitive SC_SPAM flag
      error SMTP codes
      missing SMTP_FIRST_RECIPIENT
      missing SMTP_FIRST_SENDER

   TODO: Reputation system

b) Frequency analysis
   ==================
   Saving flow records to flow data pool database for further analysis. It will
   be also possible to look for the most frequent senders in time window.

c) Legit mail server exlustion
   ===========================
   A normal smtp mail server would have both direction traffic
   (image 2.0.0) whereas a bot server will have massive diffrence
   (note: define SRV_TAFFIC_RATIO, default value for incoming/sent ratio is 1.2)
   between incoming and outgoing smtp traffic (image 2.0.1).

d) Clustering (domain clustering for now, TODO: more clustering attributes)
   ==========
   Current clustering is very slow and it has to be improved but it is not
   necessary for current spam detection, it more like a feature for reporting
   huge spam botnets thus it is not current priority.

```
## MAIL SERVERS
```
  incoming smtp traffic    +-----------+ outgoing smtp traffic
-------------------------->| SMTP      |-------------------------->
                           | MAIL      |
-------------------------->| SERV      |-------------------------->
                           |           |
-------------------------->|           |-------------------------->
                           +-----------+
(2.0.0)
```
## MALICIOUS SPAM SERVER
```
  incoming smtp traffic    +-----------+ outgoing smtp traffic
                           | SPAM      |-------------------------->
                           | BOT       |-------------------------->
-------------------------->|           |-------------------------->
                           |           |-------------------------->
                           |           |-------------------------->
                           +-----------+
(2.0.1)
```
## 2.1 Data Model
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
|                      |
|                      |
+----------------------+


```
## 2.2 Detector Diagram
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
## 3.0 A Spam BOT definition according to this module
   A spam is ... and this module detecs and is able to report ..

