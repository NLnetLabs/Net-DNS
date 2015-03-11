# $Id$

use strict;

BEGIN {
	use Test::More;

	plan tests => 5;

	use_ok('Net::DNS');
	use_ok('Digest::SHA');
}


# Simple known-answer tests based upon the examples given in RFC3658, section 2.7

my $key = Net::DNS::RR->new(
	'dskey.example. KEY  256 3 1 (
			AQPwHb4UL1U9RHaU8qP+Ts5bVOU1s7fYbj2b3CCbzNdj
			4+/ECd18yKiyUQqKqQFWW5T3iVc8SJOKnueJHt/Jb/wt
			) ; key id = 28668'
	);

my $ds = Net::DNS::RR->new(
	'dskey.example. DS	28668 1	 1  49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE'
	);


my $test = create Net::DNS::RR::DS( $key, digtype => 'SHA1', );

is( $test->string, $ds->string, 'created DS matches RFC3658 example DS' );

ok( $test->verify($key), 'created DS verifies RFC3658 example KEY' );

ok( $ds->verify($key), 'RFC3658 example DS verifies example KEY' );

$test->print;

__END__

