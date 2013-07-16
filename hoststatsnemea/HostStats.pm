#!/usr/bin/perl

# HostStats plugin for NfSen

# Name of the plugin
package HostStats;

use strict;
use NfProfile;
use NfConf;
use IO::Socket::INET;

#
# The plugin may send any messages to syslog
# Do not initialize syslog, as this is done by 
# the main process nfsen-run
use Sys::Syslog;
  
our %cmd_lookup = (
	'request' => \&req,
);

# This string identifies the plugin as a version 1.3.0 plugin. 
our $VERSION = 130;

my $MSG_NEW_DATA = "\x01";
#my $ERR_CPP_CONNECT = 1;

my $EODATA 	= ".\n";

my ( $PROFILEDIR );


sub req {
	my $socket = shift;
	my $opts   = shift;
	
	# Read request message
	my $code    = $$opts{'code'};
	my $params  = $$opts{'params'};

	my %reply;
	
	syslog('info', "HostStats: Request from frontend received: ($code) '$params'");
	
	my $cpp_socket = new IO::Socket::INET (
		PeerHost => '127.0.0.1',
		PeerPort => '3333',
		Proto => 'tcp',
		); #or die "ERROR in Socket Creation: $!\n";

	if (!$cpp_socket) {
		$reply{'code'} = 0x01;
		$reply{'errmsg'} =  "Can't connect to C++ module of backend, hoststatserv is probably not running.";
		syslog('err', "HostStats: Error when connecting to C++ module of backend.");
		Nfcomm::socket_send_ok($socket, \%reply);
		return;
	}

	$cpp_socket->send(chr($code));
	$cpp_socket->send($params);
	$cpp_socket->send("\000");
	shutdown($cpp_socket, 1);
	#$cpp_socket->close();

	syslog('info', "HostStats: Request sent, waiting for reply");
	
	my %reply;
	$reply{'code'} = 0x00;
	$reply{'data'} = "";

	while (<$cpp_socket>) {
		$reply{'data'} .= $_;
	}
	
	$cpp_socket->close();

	# Send reply
	Nfcomm::socket_send_ok($socket, \%reply);
	
	my $length = length $reply{'data'};
	if ($length > 200) {
		$reply{'data'} = (substr $reply{'data'}, 0, 200) . "...";
	}
	syslog('info', "HostStats: Reply received and sent to frontend: \"" . $reply{'data'} . "\" (" . $length . " bytes total)");
}

#
# Periodic data processing function
#	input:	hash reference including the items:
#			'profile'		profile name
#			'profilegroup'	profile group
#			'timeslot' 		time of slot to process: Format yyyymmddHHMM e.g. 200503031200
sub run {
	my $argref 		 = shift;
	my $profile 	 = $$argref{'profile'};
	my $profilegroup = $$argref{'profilegroup'};
	my $timeslot 	 = $$argref{'timeslot'};

	syslog('info', "HostStats run: Profilegroup: $profilegroup, Profile: $profile, Time: $timeslot");
   my $cpp_socket = new IO::Socket::INET (
      PeerHost => '127.0.0.1',
      PeerPort => '3333',
      Proto => 'tcp',
      ) or die "ERROR in Socket Creation: $!\n";

	$cpp_socket->send("$MSG_NEW_DATA$timeslot\0");
	
	$cpp_socket->close();
	syslog('info', "HostStats: NewData request sent");
	return;
}


#
# The Init function is called when the plugin is loaded. It's purpose is to give the plugin 
# the possibility to initialize itself. The plugin should return 1 for success or 0 for 
# failure. If the plugin fails to initialize, it's disabled and not used. Therefore, if
# you want to temporarily disable your plugin return 0 when Init is called.
#
sub Init {
	syslog("info", "HostStats plugin: Init");

	$PROFILEDIR = "$NfConf::PROFILEDATADIR";
	
	return 1;
}

#
# The Cleanup function is called, when nfsend terminates. It's purpose is to give the
# plugin the possibility to cleanup itself. It's return value is discard.
#sub Cleanup {
#	syslog("info", "HostStats plugin: Cleanup");
#}

1;
