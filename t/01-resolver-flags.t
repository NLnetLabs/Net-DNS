# $Id$  -*-perl-*-

use Test::More tests => 7;
use strict;
use File::Spec;
use Data::Dumper;


BEGIN { use_ok('Net::DNS'); }



my $res = Net::DNS::Resolver->new();

SKIP: {
	skip 'No Net::DNS::SEC installed', 3
		unless  $Net::DNS::DNSSEC;

		ok(! $res->dnssec(),"Default DNSSEC off");
		$res->dnssec(1);
		ok( $res->dnssec(),"DNSSEC toggles on");
		$res->dnssec(0);
		ok( ! $res->dnssec(),"DNSSEC toggles off");
}



ok(! $res->cdflag(),"Default cdflag  off");
$res->cdflag(1);
ok( $res->cdflag(),"toggle cdflag  on");
$res->cdflag(0);

ok(! $res->cdflag(),"toggle cdflag  off");


