# $Id$  -*-perl-*-

use strict;
use Test::More tests => 23;

use Net::DNS;


my $res = Net::DNS::Resolver->new();
ok( $res->isa('Net::DNS::Resolver'), 'new() created object' );


ok( !$res->dnssec(), "default dnssec flag off" );
my $udpsize = $res->udppacketsize();

$res->dnssec(1);
ok( $res->dnssec(), "dnssec flag toggles on" );
my $size = $res->udppacketsize();
isnt( $size, $udpsize, "dnssec(1) sets udppacketsize ($size)" );

$res->dnssec(0);
ok( !$res->dnssec(), "dnssec flag toggles off" );


my @flag = qw(adflag cdflag force_v4 force_v6 prefer_v6);
foreach my $flag (@flag) {
	ok( !$res->$flag(), "default $flag off" );
	$res->$flag(1);
	ok( $res->$flag(), "toggle $flag on" );
	$res->$flag(0);
	ok( !$res->$flag(), "toggle $flag off" );
}

foreach my $flag (qw(prefer_v4)) {
	ok( $res->$flag(), "default $flag on" );
	$res->$flag(0);
	ok( !$res->$flag(), "toggle $flag off" );
	$res->$flag(1);
	ok( $res->$flag(), "toggle $flag on" );
}


exit;

