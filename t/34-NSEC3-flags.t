# $Id$	-*-perl-*-
#

use strict;

BEGIN {
	use Test::More;
	use Net::DNS;
	use Net::DNS::Parameters;

	my @prerequisite = qw(
			MIME::Base32
			Net::DNS::RR::NSEC3;
			);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
				unless eval "require $package";
	}

	plan tests => 3;
}


my $rr = new Net::DNS::RR( type	 => 'NSEC3' );


my $optout = $rr->optout;
ok( !$optout, 'Boolean optout flag has default value' );

$rr->optout( !$optout );
ok( $rr->optout, 'Boolean optout flag toggled' );

$rr->optout($optout);
ok( !$optout, 'Boolean optout flag restored' );


exit;

__END__

