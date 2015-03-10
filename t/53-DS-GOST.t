# $Id$

use strict;

BEGIN {
	use Test::More;

	my @prerequisite = qw(
		Digest::GOST
		Digest::GOST::CryptoPro
		);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
			unless eval "require $package";
	}

	plan tests => 4;

	use_ok('Net::DNS::SEC');
}


# Simple known-answer tests based upon the examples given in RFC5933, section 4.1

my $dnskey = Net::DNS::RR->new(
	'example.net. 86400   DNSKEY  257 3 12 (
					LMgXRHzSbIJGn6i16K+sDjaDf/k1o9DbxScO
					gEYqYS/rlh2Mf+BRAY3QHPbwoPh2fkDKBroF
					SRGR7ZYcx+YIQw==
					) ; key id = 40692'
	);

my $ds = Net::DNS::RR->new(
	'example.net. 3600 IN DS 40692 12 3 (
			22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B
			2071398F )'
	);


my $test = create Net::DNS::RR::DS(
	$dnskey,
	digtype => 'GOST',
	ttl	=> 3600
	);

is( $test->string, $ds->string, 'created DS matches RFC5933 example DS' );

ok( $test->verify($dnskey), 'created DS verifies RFC5933 example DNSKEY' );

ok( $ds->verify($dnskey), 'RFC5933 example DS verifies DNSKEY' );

$test->print;

__END__

