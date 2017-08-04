# SMTP SPAM BOT DETECTION 
@author Ladislav Macoun <macoulad@fit.cvut.cz>
@org CESNET / CVUT
## Table of Contents 
* 1.0 Intr0
* 2.0 Algoritmus
* 3.0 Spam BOT definition according to this module
* 4.0 Data analysis
* X.X XXXXXXXXXXXXX
* X.0 Conclusion

## 1.0 Intro
   Function of this detector
   ...

   How to use 
   ...

## 2.0 Algoritmus
## Ways of spam bot recognition

a) RFC Filtering 
   (Applying best current practices for avoiding spam) 
   Filtering flow record through multiple RFC rules. If any of these fails add 
   that record to suspicious database for further analysis.

b) Frequency analysis 
   Saving flow records to trashholding database  and looking for the most 
   frequent senders in current time window. 

c) Legit mail server exlustion 
   A normal smtp mail server would have both direction traffic 
   (image 2.0.0) whereas a bot server will have massive diffrence
   between incoming and outgoing smtp traffic (image 2.0.1).

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
## MALICIOUS SPAM SERVERR
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
## 3.0 A Spam BOT definition accorting to this module 
   A spam is ... and this module detecs and is able to report ..



