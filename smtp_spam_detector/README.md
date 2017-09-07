# SMTP SPAM BOT DETECTION
```
@author Ladislav Macoun <macoulad@fit.cvut.cz>
@org CESNET / CVUT
```

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
   Filtering flow record through multiple RFC rules. If any of these fails add
   that record to suspicious database for further analysis.

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
(2.0.1)a
```

```
                                                        +--------+
                                                        |        |
                                                        | START  |
                                                        |        |
                                                        +---+----+
                                                            |
+----------------------------------------------------------->
|                                                           |
|                                                     +-----v-----+
|                                          +----------+ FILTERING +----------------------------+
|                                          |          | INTERVAL  |                            |
|                                          |          +-----------+                            |
|                                          |                                                   |
|                                          |                                                   |
|                                          v                                                   v
|                                 +--------+---------+                              +--+-------+-------+--+
|                                 | LOAD NEW FLOW    |                                 |               |
|                                 |                  |                                 |               |
|                                 +--------+---------+                                 v               v
|                                          |                                      +----+----+    +-----+------+   Pararell
|                                          |                                      | PROBING |    | CLUSTERING |   proccess
|                                          |                                      |         |    |            |
|                                          |                                      +----+----+    +---------+--+   clustering is very
|                                          v                                           |                   |      demanding for computing
|                                  +-------+-------+                                   |                   |      power (NP-HARD)
|                      +-----------+  BCP FILTER   +------+        +-------------------v--------------+    |
|                      |           |               |      |        |                                  |    |
|                      |           +---------------+      |        |   REPUTATION SCORE               |    |
|                      |                                  |        |   Analysing whether to add IP as |    |
|                      |                                  |        |   suspicious or not              |    |
|                      |                                  |        |                                  |    |
|                      |                                  |        |                                  |    |
|                      v                                  |        +-------------------+--------------+    |
|              +-------+-----------+                      |                            |                   |
|              |  ADD SRC IP to    |                      v                            |                   |
|              |  SUPICIUS IP List |         +------------+------------+               |                   |
|              |                   |         |  ADD IP TO FLOW SERVER  |               v                   v
|              +-------+-----------+         |  DATA POOL FOR FURTHER  |           +---+---------+---------+---+
|                      |                     |  ANALYSIS               |                         |
|                      |                     |                         |                         |
|                      |                     +------------+------------+                         |
|                      |                                  |                          +-----------v-------------+
|                      |                                  |                          |                         |
+----------------------+----------------------------------+                          |   Data report / Alerts  |
                                                                                     |                         |
                                                                                     +-------------------------+


```
## 3.0 A Spam BOT definition accorting to this module
   A spam is ... and this module detecs and is able to report ..



