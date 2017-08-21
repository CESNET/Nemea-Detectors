# Description of Config and Module

This module requires config file in Yaml with the following structure:

```
blacklistid:
    file: /path/to/blacklistfile
    name: Name of blacklist
    description: Description of blacklist
    filter_type: ip
```

Multiple blacklists may be specified in one config file.

## Yaml config file

Every blacklist must have unique `blacklistid`.

`file` specifies path to local file containing list of blacklisted entities

`name` is used in alert

`description` is used in alert

`filter_type` may be `ip` or `domain` or `http` (only `ip` will be implemented in the first version)


## Filter type

**`filter_type` == `ip`**

File specified by `file` must contain list of entities separated by newline (one entity on one line).

Entity might be in one of the following formats:

* `[IP]`
* `[IP]/[MASK]`
* `[IP]>`
* `>[IP]`
* `[IP]>[IP]`
* `[IP]/[MASK]>[IP]`
* `[IP]/[MASK]>[IP]/[MASK]`
* `[IP]/[MASK]>[IP]/[MASK]%[PORT]`
* `[IP]/[MASK]>[IP]/[MASK]%[PORT]^`
* `[IP]/[MASK]>[IP]/[MASK]%^[PORT]`
* `[IP]/[MASK]>[IP]/[MASK]%[PORT]^[PORT]`
* `[IP]%[PORT]^[PORT]`
* `[IP]%[PORT]-[PORT]`

Where `/` is used to indicate subnet, `>` specifies SRC and DST addresses (SRC is on the left, DST on the right),
`^` specifies SRC and DST ports, `-` specifies port range.
Currently, protocol number is not matched.

Complex example:

`10.0.0.0/24>10.0.1.0/24%^1-1024` describes flows with SRC IP from `10.0.0.0/24` and DST IP from `10.0.1.0/24` with DST ports from `1-1024`.



