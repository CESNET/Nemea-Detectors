# DDoS detector

### README outline

* [Module description](#module-description)
* [Input data](#input-data)
* [Output data](#output-data)
* [Module parameters](#module-parameters)


## Module description

This module is a **simple, threshold-based detector for distributed denial of service attacks** which processes incoming flow records and outputs alerts.
The module uses the TRAP platform and has **one input and one output interface**.

The detection algorithm uses information from basic flow records and it is based on comparing flow in historical windows for every *DST_IP* of prefix.

For each flow record, the detector finds an appropriate entry in a B+tree and stores the number of bytes in windows according to the duration of the flow. It also updates the count of unique SRC_IP in every affected window.
Every time an entry is updated, the algorithm checks whether following conditions for 2 consecutive windows are satisfied:

* the number of bytes in 2 consecutive windows is *threshold_flow_rate* times higher then the average number of bytes in preceding windows
* the average flow in both windows is higher than *minimal_attack_size*
* the number of unique *SRC_IP* in both windows must be *threshold_ip_cnt_rate* times higher than the average number of unique *SRC_IP* in preceding windows

If all of these conditions are satisfied, a flood report is sent.


## Input data

Data received via the input interface are in the UniRec format. The table below shows required flow information together with the corresponding names of UniRec fields:

| Flow info                    | UniRec field |
|:----------------------------:|:------------:|
| source IP address            | SRC_IP       |
| destination IP address       | DST_IP       |
| first time stamp             | TIME_FIRST   |
| last time stamp              | TIME_LAST    |
| number of bytes              | BYTES        |


## Output data

In case some destination IP address reaches the rules specified above, a report is sent via the output interface.
The report is also in the UniRec format and it contains the following information:

| UniRec field | Description                               |
|:------------:|:-----------------------------------------:|
| DST_IP       | target of attack/IP address of the victim |
| BYTES        | bytes of attack in current interval       |
| TIME_FIRST   | the beginning of the reported interval    |
| TIME_LAST    | the end of the reported interval          |
| EVENT_ID     | identifier of reported event              |
| EVENT_TYPE   | serial number of event with same EVENT_ID |

One flood is reported several times (repeatedly in intervals at least 5 minutes long), but the reports share one *EVENT_ID*. The first report is sent immediately at the time of a flood detection and the field *BYTES* is empty. In the following reports, the field *BYTES* is properly filled with bytes processed between *TIME_FIRST* and *TIME_LAST*.


## Module parameters

------------------
	-m		Minimal attack size (kb/s). Default value is 1000 kb/s.
	-t		Rate, how many times must increase flow in next 2 windows compared
			to average of previous windows to be detected as flood attack.
	-c		Rate between the increase of number of unique SRC_IP addresses in
			next 2 windows and the average from previous windows to consider
			this behavior as a flood attack.
	-s		Get only prefix bits from source addresses corresponding given mask,
			default value/mask is 24.
	-d		Get only prefix bits from destination addresses corresponding given
			mask, default value/mask required_argument, "
	-p		Minimal size of flow traffic (average of flow in windows) in kb/s
			which will not be removed. Entries containing less flow will be
			removed. Default value is 10kb/s.

Except these parameters, the module has also implicit *libtrap* parameters `-i IFC_SPEC`, `-h` and `-v` (see [Execute a module](https://github.com/CESNET/Nemea#try-out-nemea-modules)).
