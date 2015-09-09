# $Id$	-*-perl-*-
#

use strict;
use Test::More;
use Net::DNS;

my @prerequisite = qw(
		Net::DNS::RR::NSEC3;
		);

foreach my $package (@prerequisite) {
	next if eval "require $package";
	plan skip_all => "$package not installed";
	exit;
}

plan tests => 20;


my %testcase = (
	"U"	     => 'ak',
	"UU"	     => 'alag',
	"UUU"	     => 'alala',
	"UUUU"	     => 'alalal8',
	"UUUUU"	     => 'alalalal',
	"UUUUUU"     => 'alalalalak',
	"UUUUUUU"    => 'alalalalalag',
	"UUUUUUUU"   => 'alalalalalala',
	"UUUUUUUUU"  => 'alalalalalalal8',
	"UUUUUUUUUU" => 'alalalalalalalal',
	);


foreach my $binary ( sort keys %testcase ) {
	my $expect = $testcase{$binary};
	my $encode = Net::DNS::RR::NSEC3::_encode_base32($binary);
	my $decode = Net::DNS::RR::NSEC3::_decode_base32($encode);
	is( $encode,	     $expect,	      'base32 encode correct' );
	is( length($decode), length($binary), 'decode length correct' );
}


exit;

