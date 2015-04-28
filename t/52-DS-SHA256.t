# $Id$

use strict;

BEGIN {
	use Test::More;

	my @prerequisite = qw(
		Digest::SHA
		);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
			unless eval "require $package";
	}

	plan tests => 4;

	use_ok('Net::DNS');
}



# Simple known-answer tests based upon the examples given in RFC4509, section 2.3

my $dnskey = Net::DNS::RR->new(
	'dskey.example.com. 86400 IN DNSKEY 256 3 5 (	AQOeiiR0GOMYkDshWoSKz9Xz
							fwJr1AYtsmx3TGkJaNXVbfi/
							2pHm822aJ5iI9BMzNXxeYCmZ
							DRD99WYwYqUSdjMmmAphXdvx
							egXd/M5+X7OrzKBaMbCVdFLU
							Uh6DhweJBjEVv5f2wwjM9Xzc
							nOf+EPbtG9DMBmADjFDc2w/r
							ljwvFw==
							) ;  key id = 60485'
	);

my $ds = Net::DNS::RR->new(
	'dskey.example.com. 86400 IN DS 60485 5 2   (	D4B7D520E7BB5F0F67674A0C
							CEB1E3E0614B93C4F9E99B83
							83F6A1E4469DA50A )'
	);


my $test = create Net::DNS::RR::DS( $dnskey, digtype => 'SHA256' );

is( $test->string, $ds->string, 'created DS matches RFC4509 example DS' );

ok( $test->verify($dnskey), 'created DS verifies RFC4509 example DNSKEY' );

ok( $ds->verify($dnskey), 'RFC4509 example DS verifies DNSKEY' );

$test->print;

__END__

