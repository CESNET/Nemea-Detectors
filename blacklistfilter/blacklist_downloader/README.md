## Blacklist Downloader

Blacklist Downloader is a python script used to download public blacklists. 
It periodically fetches IP/URL blacklists, preprocesses them and stores them
in files which can be loaded by the detectors (ipblacklistfilter, urlblacklistfilter,..).
The files for the detectors are specified in a configuration file (bl_downloader_config.xml), 
along with the list of blacklists to download.
   
# How it works

By default, the downloader fetches the blacklists every 10 minutes. If there is an update of some
blacklist, it creates a new file for the detector. This file is preprocessed by the downloader, so that
the detector can just read it and start the detection. Preprocessing means: one entity per line,
adding blacklist indexes to the entities, trimming whitespaces, sorting the entities,..

# Usage:

Just run the script without arguments
