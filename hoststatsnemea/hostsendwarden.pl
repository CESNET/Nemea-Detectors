#!/usr/bin/perl -w
#
# Copyright (C) 2011-2012 Cesnet z.s.p.o
#
# Use of this source is governed by a BSD-style license, see LICENSE file.  

use strict;
use POSIX;
use DateTime;
use Date::Parse;
#-------------------------------------------------------------------------------
# Warden 2.0. Client, Sender, Example 
#
# Sample script using warden-client sending functionality. This example is not
# intended to be a standalone script. It only shows how to use warden-client
# functionality.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Preparation of event attributes.
# This should be handled by detection application.


#my $local_detected = DateTime->from_epoch(epoch => time());

my $cmdline= shift(@ARGV);
my @event = split(',', $cmdline, 9);

#my $service 		= "ScanDetector";
#my $detected 		= "$local_detected";
#my $type 		= "portscan";
#my $source_type 	= "IP";
#my $source 		= "123.123.123.123";
#my $target_proto 	= "TCP";
#my $target_port 	= "22";
#my $attack_scale 	= "1234567890";
#my $note 		= "important note or comment";
#my $priority 		= "null";
#my $timeout 		= "20";

#my @event 		= ($service, $detected, $type, $source_type, $source,
#			   $target_proto, $target_port, $attack_scale, $note,
#			   $priority, $timeout );

# Add priority and timeout (undefined)
undef $event[9];
undef $event[10];

# Convert detection time from local time to UTC
my $detected=$event[1];
my $tz_name=strftime("%Z", localtime());
$detected = strftime("%Y-%m-%dT%H:%M:%S", gmtime(str2time($detected, $tz_name)));
$event[1]=$detected;

# Print what is being sent to Warden
print "hostsendwarden.pl: Sending to Warden: ";
my $i;
for ($i=0; $i <= $#event; $i++) {
#foreach $item (@event) {
   if (defined($event[$i])) {
      print "$event[$i]";
   }
   else {
      print "<undef>";
   }
   if ($i < $#event) {
      print ",";
   }
   else {
      print "\n";
   }
}


#-------------------------------------------------------------------------------
# Use of warden-client sender.
# This code should developer add to his/her detection application
# (with corresponding paths appropriately changed).

# Path to warden-client folder
my $warden_path = '/opt/warden-client';

# Inclusion of warden-client sender module
require $warden_path . '/lib/WardenClientSend.pm';

# Sending event to Warden server
WardenClientSend::saveNewEvent($warden_path, \@event);

exit 0;
