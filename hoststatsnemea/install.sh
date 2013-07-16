#!/bin/sh
#
# Simple script to install NfSen plugin template - based on install.sh
# script from SURFmap plugin
#
# Copyright (C) 2012 INVEA-TECH a.s.
# Author(s): 	Pavel Celeda <celeda@invea-tech.com>
#		Rick Hofstede <r.j.hofstede@utwente.nl>
#		Michal Trunecka <trunecka@ics.muni.cz>
#
# LICENSE TERMS - 3-clause BSD license
#

function err {
	echo $1 >&2;
	exit 1;
}

function print_help {

echo "Install script for HostStats."
echo
echo "Usage:"
echo "     $0 [-d][-c /path/nfsen.conf]"
echo "     $0 [-h]"
echo 
echo "  -d                    Dry-run - script only prints the commands"
echo "  -c /path/nfsen.conf   Path to nfsen.conf. Install script will find this file"
echo "                        automaticaly if NfSen is running"
echo "  -h                    Print this help and exit" 
echo
}


echo
echo "################################################"
echo "#  HostStats NfSen plugin installation script  #"
echo "################################################"
echo


DRY_RUN=""
NFSEN_CONF=""

while getopts ":c:dh" opt; do
	case $opt in
	c)
		echo ">>> Provided nfsen.conf: $OPTARG "
		if [ ! -e $OPTARG ]; then error 5 "ERROR: $OPTARG does not exist."; fi
		if [ ! -r $OPTARG ]; then error 6 "ERROR: You don't have the permission to read $OPTARG ."; fi
		NFSEN_CONF=$OPTARG
		;;
	h)
		print_help
		exit 0
		;;
	d)
		echo ">>> Dry-run mode: Nothing will be executed."
		DRY_RUN=1
		;;
	\?)
		error 3 "Invalid option: -$OPTARG"
		;;
	esac
done


NFSEN_VARFILE=/tmp/nfsen-tmp.conf

if [ "x$NFSEN_CONF" = "x" ]; then
	# Discover NfSen configuration
	if [ ! -n "$(ps axo command | grep [n]fsend | grep -v nfsend-comm)" ]; then
		err "NfSen - nfsend not running. Can not detect nfsen.conf location!"
	fi
	NFSEN_LIBEXECDIR=$(cat $(ps axo command= | grep [n]fsend | grep -v nfsend-comm | cut -d' ' -f3) | grep libexec | cut -d'"' -f2 | head -n 1)
	NFSEN_CONF=$(cat ${NFSEN_LIBEXECDIR}/NfConf.pm | grep \/nfsen.conf | cut -d'"' -f2)
fi


# Parse nfsen.conf file
cat ${NFSEN_CONF} | grep -v \# | grep '=' | grep -v '=>' | egrep '\$BASEDIR|\$BINDIR|\$HTMLDIR|\$FRONTEND_PLUGINDIR|\$BACKEND_PLUGINDIR|\$WWWGROUP|\$WWWUSER|\$USER' | tr -d ';' | tr -d ' ' | cut -c2- | sed 's,/",",g' > ${NFSEN_VARFILE}
. ${NFSEN_VARFILE}
rm -rf ${NFSEN_VARFILE}


# Check permissions to install the plugin - you must be ${USER} or root
if [ "$(id -u)" != "$(id -u ${USER})" ] && [ "$(id -u)" != "0" ]; then
	err "You do not have sufficient permissions to install the NfSen plugin on this server!"
fi

if [ "$(id -u)" = "$(id -u ${USER})" ]; then
	WWWUSER=${USER}		# we are installing as normal user
fi



read -p "Enter installation directory [/usr/local/hoststats]:" INSTALLDIR
if [ -z "$INSTALLDIR" ] ; then
   INSTALLDIR=/usr/local/hoststats
fi
# remove trailing slash
INSTALLDIR=$(sed "s/\/$//" <<< $INSTALLDIR)
if [ ! $DRY_RUN ] ; then
   if ! mkdir -p $INSTALLDIR ; then
      err "Can't create $INSTALLDIR"
   fi
fi

read -p "Enter data directory [/data/hoststats]: " DATADIR
if [ -z "$DATADIR" ] ; then
   DATADIR=/data/hoststats
fi
# remove trailing slash
DATADIR=$(sed "s/\/$//" <<< $DATADIR)
if [ ! $DRY_RUN ] ; then
   if ! mkdir -p $DATADIR ; then
      err "Can't create $DATADIR"
   fi
fi

echo
echo "### Copying program files and auxiliary sripts into $INSTALLDIR"
[ ! $DRY_RUN ] && cp hoststatserv comphoststats nfreader.so hoststats hostsendwarden.pl hscleaner.py ${INSTALLDIR}/
echo "cp hoststatserv comphoststats nfreader.so hostsendwarden.pl hscleaner.py ${INSTALLDIR}/"
[ ! $DRY_RUN ] && cp --backup=numbered --suffix ".backup" hoststats.conf.default ${INSTALLDIR}/hoststats.conf
echo "cp --backup=numbered --suffix \".backup\" hoststats.conf.default ${INSTALLDIR}/hoststats.conf"

echo
echo "### Creating subdirectories in $DATADIR"
[ ! $DRY_RUN ] && mkdir -p $DATADIR/data
echo "mkdir -p $DATADIR/data"
[ ! $DRY_RUN ] && mkdir -p $DATADIR/log
echo "mkdir -p $DATADIR/log"


# Install backend and frontend plugin files
echo
echo "### Installing HostStats NfSen plugin to $FRONTEND_PLUGINDIR and $BACKEND_PLUGINDIR"
[ ! $DRY_RUN ] && cp HostStats.pm ${BACKEND_PLUGINDIR}/
echo "cp HostStats.pm ${BACKEND_PLUGINDIR}/"
[ ! $DRY_RUN ] && cp -r frontend/* ${FRONTEND_PLUGINDIR}/
echo "cp -r frontend/* ${FRONTEND_PLUGINDIR}/"


# Set permissions - owner and group
echo
echo "### Setting plugin files permissions - user \"${USER}\" and group \"${WWWGROUP}\""
[ ! $DRY_RUN ] && chown -R ${USER}:${WWWGROUP} ${FRONTEND_PLUGINDIR}/HostStats*
echo "chown -R ${USER}:${WWWGROUP} ${FRONTEND_PLUGINDIR}/HostStats*"
[ ! $DRY_RUN ] && chmod -R g+r ${FRONTEND_PLUGINDIR}/HostStats*
echo "chmod -R g+r ${FRONTEND_PLUGINDIR}/HostStats*"
[ ! $DRY_RUN ] && find ${FRONTEND_PLUGINDIR}/HostStats -type d -exec chmod g+x {} \;
echo "find ${FRONTEND_PLUGINDIR}/HostStats -type d -exec chmod g+x {} \;"
[ ! $DRY_RUN ] && chown -R ${USER}:${WWWGROUP} ${BACKEND_PLUGINDIR}/HostStats*
echo "chown -R ${USER}:${WWWGROUP} ${BACKEND_PLUGINDIR}/HostStats*"


# Enable plugin
echo
echo "### Updating NfSen configuration file ${NFSEN_CONF}"
#sed -i "/HostStats/d" ${NFSEN_CONF}

OLDENTRY=$(grep "^\@plugins" ${NFSEN_CONF})
if [ -n "$OLDENTRY" ] ; then
  [ ! $DRY_RUN ] && sed -i "s/${OLDENTRY}/${OLDENTRY}\n    \[ 'live', 'HostStats' ],/g" ${NFSEN_CONF}
  echo "sed -i \"s/${OLDENTRY}/${OLDENTRY}\n    \[ 'live', 'HostStats' ],/g\" ${NFSEN_CONF}"
else
  echo "** ERROR: \"@plugins\" array not found in ${NFSEN_CONF}, can't add HostStats to the list of plugins"
fi


echo
echo "### Updating HostStats configuration file $INSTALLDIR/hoststats.conf"

[ ! $DRY_RUN ] && sed -i "s,^db-path.*,db-path = $DATADIR/data/," $INSTALLDIR/hoststats.conf
echo "sed -i \"s,^db-path.*,db-path = $DATADIR/data/,\" $INSTALLDIR/hoststats.conf"
[ ! $DRY_RUN ] && sed -i "s,^detection-log.*,detection-log = $DATADIR/log," $INSTALLDIR/hoststats.conf
echo "sed -i \"s,^detection-log.*,detection-log = $DATADIR/log,\" $INSTALLDIR/hoststats.conf"
[ ! $DRY_RUN ] && sed -i "s,\./,$INSTALLDIR/,g" $INSTALLDIR/hoststats.conf
echo "sed -i \"s,\./,$INSTALLDIR/,g\" $INSTALLDIR/hoststats.conf"

#TODO: Fill flow-data-path and flow-sources automatically using nfsen.conf

echo
echo "Please restart/reload NfSen to finish plugin installation (e.g. sudo ${BINDIR}/nfsen reload)"
echo
echo "** IMPORTANT: Check configuration in ${INSTALLDIR}/hoststats.conf before running hoststatserv! **"

