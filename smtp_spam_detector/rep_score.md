# Request for comments
## A Reputation score based on SMTP flow parameters
### Abstract
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
Therefore we have to use a frequecy analysis to determine wich entities are spammer
and exlude legit mail servers. 

In this case we have to compute the ratio of incoming and outcoming traffic for
each entity in timeframe t. If there is huge difference between sent and recived
messeges we can tell this entity is not a legit server.

## SMTP Status codes
### SMTP_SC 5XX

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

### SMTP_SC 4XX

|Code | Description | Score | Comment |
| --- | ----------- | ----- | ------- |
|421|<domain> Service not available, closing transmission channel [This may be a reply to any command if the service knows it must shut down]|||
|450|Requested mail action not taken: mailbox unavailable [E.g., mailbox busy]|||
|451|Requested action aborted: local error in processing|||
|452|Requested action not taken: insufficient system storage|||

>comment

### SMTP_SC 2XX

|Code | Description | Score | Comment |
| --- | ----------- | ----- | ------- |
|211|System status, or system help reply|||
|214|Help message [Information on how to use the receiver or the meaning of a particular non-standard command; this reply is useful only to the human user]
|220|<domain> Service ready|||
|221|<domain> Service closing transmission channel|||
|250|Requested mail action okay, completed|||
|251|User not local; will forward to <forward-path>|||

>Comment

## Email configuration
If there's no filled sender or reciver domain 


### 

