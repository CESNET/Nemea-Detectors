#!/bin/bash
pushd ..
echo ${PWD}
python detector.py start ip $@
#python detector.py install ip
popd 
