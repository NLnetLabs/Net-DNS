# $Id$  -*-perl-*-

use strict;
use Test::More tests => 8;


BEGIN { use_ok('Net::DNS'); }


my $res = Net::DNS::Resolver->new();

SKIP: {
	my $DNSSEC = eval { require Net::DNS::SEC; };
	skip( 'No Net::DNS::SEC installed', 4 ) unless $DNSSEC;

	ok( !$res->dnssec(), "Default dnssec flag off" );
	$res->dnssec(1);
	ok( $res->dnssec(), "dnssec flag toggles on" );
	$res->dnssec(0);
	ok( !$res->dnssec(), "dnssec flag toggles off" );

	ok( $res->adflag(), "Default adflag on" );
}


ok( !$res->cdflag(), "Default cdflag  off" );
$res->cdflag(1);
ok( $res->cdflag(), "toggle cdflag  on" );
$res->cdflag(0);
ok( !$res->cdflag(), "toggle cdflag  off" );

