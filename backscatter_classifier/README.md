# Backscatter classifier module - README

## Requirements
* Nemea Framework, pytrap, pycommon
* For other Python packages see requirements.txt (scikit-learn, numpy, pandas, pymisp, geoip2)

## Description
Classify feature vectors from *backscatter* module into DDoS and Non-DDoS category and report DDoS attacks to MISP instance.

## Interfaces
- Inputs: 1 (Feature vectors)
- Outputs: 0 (Reporting is done via MISP)

## Parameters
-  `--model MODEL`         Machine learning DDoS model.
-  `--agp AGP`             ASN GeoIP2 database path.
-  `--cgp CGP`             City GeoIP2 database path.
-  `--url URL`             URL to MISP instance.
-  `--key KEY`             Automation MISP key.
-  `--ssl SSL`             CA Bundle.
-  `--logfile LOGFILE`     Path and name of file used for logging.
-  `--misp_templates_dir MISP_TEMPLATES_DIR` Directory with MISP object templates.
-  `--min_flows MIN_FLOWS`         Minimum number of flows in feature vector in order for event to be reported.
-  `--min_threshold MIN_THRESHOLD` Minimum classification threshold for event to be considered as DDoS attack. Threshold is real number in range (0,1), higher values results in less false positives.
-  `--min_duration MIN_DURATION`   Minimum duration of event in order to be reported, events below this value will not be reported.
-  `--max_duration MAX_DURATION`   Maximum duration of event in order to be reported, events above this value will not be reported.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Feature vectors are classified into DDoS class based on provided stored machine learning MODEL. Vector is classified as DDoS attack when prediction value (*predict\_proba from sklearn*) is greater than THRESHOLD. Only attacks with atleast MIN\_FLOWS are reported and their duration must be in range <MIN\_DURATION, MAX_DURATION>. 

Note: Only attacks with assigned domain are reported to MISP in order to increase relevancy of attacks.

## Notes
Automatization key and CA Bundle is not part of repository and should be added manually according to NEMEA configuration files.

## Examples

python3 ./backscatter\_classifier.py -i <input interface> --model <backscatter model> --min\_flows <min_flows> --min\_duration <min duration> --max\_duration <max duration> --min\_threshold <min threshold> --agp <ASN database> --cgp <city database> --url <misp url> --key <automatization key> --misp\_templates\_dir <misp templates> --logfile LOGFILE --ssl SSL

python3 backscatter\_classifier.py -i u:backscatter --model ./data/backscatter\_ddos\_model.pickle --agp ./data/GeoLite2-ASN\_20210330/GeoLite2-ASN.mmdb --cgp ./data/GeoLite2-City\_20210330/GeoLite2-City.mmdb --url https://localhost:8443/ --key KEY --misp\_templates\_dir ./objects --logfile log\_file.txt --ssl ./ca\_bundle

