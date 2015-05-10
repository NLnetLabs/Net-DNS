# $Id$	-*-perl-*-
#

use strict;

BEGIN {
	use Test::More;
	use Net::DNS;
	use Net::DNS::Parameters;

	my @prerequisite = qw(
			Net::DNS::RR::NSEC;
			Net::DNS::DomainName;
			);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
				unless eval "require $package";
	}

	plan tests => 80;
}


my $rr = new Net::DNS::RR(
	type	 => 'NSEC',
	nxtdname => 'irrelevent',
	);

foreach my $rrtype ( 0, 256, 512, 768, 1024 ) {
	my $type = typebyval($rrtype);
	$rr->typelist($type);
	my $rdata = $rr->rdata;
	my ( $name, $offset ) = decode Net::DNS::DomainName( \$rdata );
	my ( $w, $l, $bitmap ) = unpack "\@$offset CCa*", $rdata;
	is( $w, $rrtype >> 8, "expected window number for $type" );
}

foreach my $rrtype ( 0, 7, 8, 15, 16, 23, 24, 31, 32, 39 ) {
	my $type = typebyval($rrtype);
	$rr->typelist($type);
	my $rdata = $rr->rdata;
	my ( $name, $offset ) = decode Net::DNS::DomainName( \$rdata );
	my ( $w, $l, $bitmap ) = unpack "\@$offset CCa*", $rdata;
	is( $l, 1 + ( $rrtype >> 3 ), "expected map length for $type" );
}

foreach my $rrtype ( 0 .. 64 ) {
	my $type = typebyval($rrtype);
	$rr->typelist($type);
	my $rdata = $rr->rdata;
	my ( $name, $offset ) = decode Net::DNS::DomainName( \$rdata );
	my ( $w, $l, $bitmap ) = unpack "\@$offset CCa*", $rdata;
	my $last = unpack 'C', reverse $bitmap;
	is( $last, ( 0x80 >> ( $rrtype % 8 ) ), "expected map bit for $type" );
}


exit;

__END__

