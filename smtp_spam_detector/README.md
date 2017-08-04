#SMTP SPAM BOT DETECTION 
@author Ladislav Macoun <macoulad@fit.cvut.cz>
@org CESNET / CVUT
 
- 1.0 Intr0
- 2.0 Algoritmus
- 3.0 Spam BOT definition according to this module
- 4.0 Data analysis
- X.X XXXXXXXXXXXXX
- X.0 Conclusion

## 1.0 Intro

## 2.0 Algoritmus
### Ways of spam bot recognition

a) Legit mail server exlustion 
   A normal smtp mail server would have both direction traffic 
   (shown in image 2.0.0) whereas a bot server will have massive diffrence
   between incoming and outgoing smtp traffic (image 2.0.1).

###MAIL SERVERS

  incoming smtp traffic    +-----------+ outgoing smtp traffic
-------------------------->| SMTP      |-------------------------->
                           | MAIL      |
-------------------------->| SERV      |-------------------------->
                           |           |
-------------------------->|           |-------------------------->
                           +-----------+
(2.0.0)
##MALICIOUS SPAM SERVERR

  incoming smtp traffic    +-----------+ outgoing smtp traffic
                           | SPAM      |-------------------------->
                           | BOT       |-------------------------->
-------------------------->|           |-------------------------->
                           |           |-------------------------->
                           |           |-------------------------->
                           +-----------+
(2.0.1)

b) 


