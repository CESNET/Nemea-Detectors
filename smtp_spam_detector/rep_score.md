# Request for comments
## A Reputation score based on SMTP status codes

### SMTP_SC 5XX 
It is a permanent error causing transfer termination and return of the mail to\
the sender.This would be the right return of refusing a spam messege.
|Code | Description | Score | Comment |
|500| Syntax error, command unreconcnized |||
|501| Syntax error in parameters or arguments |||
|502| Commmand not implemented |||
|503| Bad sequence of commands |||
|504| Requested action not taken: mailbox unavailable|||
|550| Requested action not taken: mailbox unavailable\[E.g., mailbox not found, no access]|||
|551| User not local; please try <forward-path>|||
|552| Requested mail action aborted: exceeded storage allocation|||
|553| Requested action not taken: mailbox name not allowed\[E.g., mailbox syntax incorrect]|||
|554| Transaction failed |||
>Comment

### SMTP_SC 4XX
|Code | Description | Score | Comment |
|421| <domain> Service not available, closing transmission channel\[This may be a reply to any command if the service knows it must shut down]|||
|450| Requested mail action not taken: mailbox unavailable\[E.g., mailbox busy]|||
|451| Requested action aborted: local error in processing|||
|452| Requested action not taken: insufficient system storage|||
>Comment

### SMTP_SC 2XX
|Code | Description | Score | Comment |
|211| System status, or system help reply|||
|214| Help message [Information on how to use the receiver\or the meaning of a\particular non-standard command; this reply is useful only\to the human user]
|220| <domain> Service ready|||
|221| <domain> Service closing transmission channel|||
|250| Requested mail action okay, completed|||
|251| User not local; will forward to <forward-path>|||
>Comment
