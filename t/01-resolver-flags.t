# $Id$  -*-perl-*-

use strict;
use Test::More tests => 10;

use Net::DNS;

use constant DNSSEC => eval { require Net::DNS::SEC; } || 0;

my $res = Net::DNS::Resolver->new();
isa_ok( $res, 'Net::DNS::Resolver', 'new() created object' );

ok( !$res->dnssec(), "default dnssec flag off" );
my $udpsize = $res->udppacketsize();

my @warning;
local $SIG{__WARN__} = sub { @warning = @_; };

$res->dnssec(1);
is( scalar(@warning), 0, 'no warning setting $res->dnssec(1)' ) if DNSSEC;
ok( scalar(@warning), "expected warning: [@warning]" ) unless DNSSEC;


SKIP: {
	skip( 'Net::DNS::SEC not installed', 4 ) unless DNSSEC;

	ok( $res->dnssec(), "dnssec flag toggles on" );
	my $size = $res->udppacketsize();
	isnt( $size, $udpsize, "dnssec(1) sets udppacketsize ($size)" );

	$res->dnssec(0);

	ok( !$res->dnssec(), "dnssec flag toggles off" );

	ok( $res->adflag(), "default adflag on" );
}


ok( !$res->cdflag(), "default cdflag  off" );
$res->cdflag(1);
ok( $res->cdflag(), "toggle cdflag  on" );
$res->cdflag(0);
ok( !$res->cdflag(), "toggle cdflag  off" );


exit;

