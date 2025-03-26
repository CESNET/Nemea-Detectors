# URL blacklist filter - NEMEA module

## Description

This modul recieves UniRec, checks if URL is on blacklist, if it is on blacklist, then it sends this UniRec to output. It requires file with blacklist as parameter.
The primary function of tthis module is to monitor incoming HTTP network traffic and detect any attempts to access addresses listed on a pre-established blacklist. This module acts as a filter. 
When a malicious address is detected, the module forwards it to the output interface, which should be connected to input of the [urlblacklist2idea](https://github.com/CESNET/URL_Evaluator/tree/main/nemea_modules/urlblacklist2idea) reporting module (part of [URL Evaluator](https://github.com/CESNET/URL_Evaluator)).

### Input

Number of inputs: 1\
Description of input: The module receives UniRec data related to HTTP traffic. Required UniRec fields for this module are HTTP_REQUEST_HOST and HTTP_REQUEST_URL

### Output

Number of outputs: 1\
Description of output: Incoming UniRec data is sent to the output if the URL within the UniRec entry is found on a blacklist.
  
## Installation

1) Let Autotools process the configuration files.\
``` autoreconf -i ```

2) Configure the module directory.\
``` ./configure ```

3) Build the module.\
``` make ```

4) Install the module. The command should be performed as root (e.g. using sudo). \
``` make install ```

## Usage

``` url_blacklist_filter -f FILE_PATH -i IFC_SPEC ```

### Parameters of module [OPTIONS]

|Parameter|Description|
|---|---|
|-f  --file <char*>|Path to blacklist file with list of malicious URL addresses. Each line in the provided text file should contain a single URL.|

### Common TRAP parameters [COMMON]

|Parameter|Description|
|---|---|
|-h [trap,1]|If no argument, print this message. If "trap" or 1 is given, print TRAP help.|
|-i IFC_SPEC|Specification of interface types and their parameters, see "-h trap" (mandatory parameter).|
|-v|Be verbose.|
|-vv|Be more verbose.|
|-vvv|Be even more verbose.|
