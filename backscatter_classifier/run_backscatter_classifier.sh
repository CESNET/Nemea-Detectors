#!/usr/bin/bash
# terminate in case of error
set -e
# setting virtual environment
VENV=/var/run/nemea/backscatter_classifier/backscatter_classifier_env
REQV=/etc/nemea/backscatter_classifier/requirements.txt
if [ ! -d $VENV ]; then
    python3 -m venv $VENV --system-site-packages
    source $VENV/bin/activate
    python3 -m pip install -r $REQV
else
    source $VENV/bin/activate
fi

KEY=$(</etc/nemea/backscatter_classifier/misp_key)
SSL=/etc/nemea/backscatter_classifier/cert
MODEL=/etc/nemea/backscatter_classifier/data/backscatter_ddos_model.pickle
AGP=/etc/nemea/backscatter_classifier/data/GeoLite2-ASN_20210330/GeoLite2-ASN.mmdb
CGP=/etc/nemea/backscatter_classifier/data/GeoLite2-City_20210330/GeoLite2-City.mmdb
OBJECTS=/etc/nemea/backscatter_classifier/objects
URL=https://misp-sparta.liberouter.org
LOGFILE=/var/run/nemea/backscatter_classifier/backscatter_classifier.log

# set run as wd
cd /var/run/nemea/backscatter_classifier/
EXEC=/bin/nemea/backscatter_classifier/backscatter_classifier.py
# Note "$@" other parameters passed to scripts such as interface from Supervisor 
python3 $EXEC "$@" --model $MODEL --min_flows 200000 --min_duration 60 --max_duration 3600 --min_threshold 0.99 --agp $AGP --cgp $CGP --url $URL --key $KEY --misp_templates_dir $OBJECTS --ssl $SSL --logfile $LOGFILE
