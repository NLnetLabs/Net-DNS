# $Id$  -*-perl-*-

use strict;
use Test::More tests => 11;

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


ok( !$res->adflag(), "default adflag  off" );
$res->adflag(1);
ok( $res->adflag(), "toggle adflag  on" );
$res->adflag(0);
ok( !$res->adflag(), "toggle adflag  off" );


ok( !$res->cdflag(), "default cdflag  off" );
$res->cdflag(1);
ok( $res->cdflag(), "toggle cdflag  on" );
$res->cdflag(0);
ok( !$res->cdflag(), "toggle cdflag  off" );


exit;

