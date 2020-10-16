#!/usr/bin/perl
# $Id$	-*-perl-*-
#

use strict;
use warnings;
use Test::More;
use Net::DNS;

my @prerequisite = qw(
		Digest::GOST
		Digest::GOST::CryptoPro
		MIME::Base64
		Net::DNS::RR::DNSKEY
		Net::DNS::RR::DS
		);

foreach my $package (@prerequisite) {
	next if eval "require $package";## no critic
	plan skip_all => "$package not installed";
	exit;
}

plan tests => 3;


# Simple known-answer tests based upon the examples given in RFC5933, section 4.1

my $dnskey = Net::DNS::RR->new( <<'END' );
example.net. 86400   DNSKEY  257 3 12 (
	LMgXRHzSbIJGn6i16K+sDjaDf/k1o9DbxScO
	gEYqYS/rlh2Mf+BRAY3QHPbwoPh2fkDKBroF
	SRGR7ZYcx+YIQw== ) ; key id = 40692
END

my $ds = Net::DNS::RR->new( << 'END' );
example.net. 3600 IN DS 40692 12 3 (
	22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B
	2071398F )
END


my $test = Net::DNS::RR::DS->create(
	$dnskey,
	digtype => 'GOST',
	ttl	=> 3600
	);

is( $test->string, $ds->string, 'created DS matches RFC5933 example DS' );

ok( $test->verify($dnskey), 'created DS verifies RFC5933 example DNSKEY' );

ok( $ds->verify($dnskey), 'RFC5933 example DS verifies DNSKEY' );

$test->print;

__END__


