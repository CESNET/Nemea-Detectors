#!/usr/bin/perl -w
#
# Copyright (C) 2011-2012 Cesnet z.s.p.o
#
# Use of this source is governed by a BSD-style license, see LICENSE file.  

use strict;

#------------------------------------------------------------------------------
# Warden 2.0 Client, Receiver, Example
#
# Simple use of warden-client receiver functionality to download new events
# from # Warden server. This code illustrates how to integrate warden-client
# receive functionality into local applications.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# This code should developer add into his/her application.

# Path to warden-client directory
my $warden_path = '/opt/warden-client';

# Inclusion of warden-client receiving functionality
require $warden_path . '/lib/WardenClientReceive.pm';

# Definition of requested event type. This attributes is also set on server
# and must not change.
my $requested_type = "portscan";

# Download of new evetns from Warden server
my @new_events = WardenClientReceive::getNewEvents($warden_path, $requested_type);

#------------------------------------------------------------------------------
# Simple code that prints out new events obtained from Warden server.

print "+------------------------------------------------------------------------------------------------------------------------------------------+\n";
print "| id | hostname | service | detected | type | source_type | source | target_proto | target_port | attack_scale | note | priority | timeout |\n";
print "+------------------------------------------------------------------------------------------------------------------------------------------+\n";

foreach (@new_events) {
  print "| " . join(' | ', @$_) . " |" . "\n";
}
print "+------------------------------------------------------------------------------------------------------------------------------------------+";
print "\n";
print "Last events in: " . scalar(localtime(time)) . "\n";

exit 0;
