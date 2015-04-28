# $Id$	-*-perl-*-
#

use strict;

BEGIN {
	use Test::More;
	use Net::DNS;
	use Net::DNS::Parameters;

	plan tests => 23;
}


my $rr = new Net::DNS::RR(
	name => 'NSEC.example.',
	type => 'NSEC',
	nxtdname => '.',
	);

foreach my $rrtype ( 0, 256, 512, 768, 1024 ) {
	my $type = typebyval($rrtype);
	$rr->typelist($type);
	my ( $w, $l, $bitmap ) = unpack 'x CCa*', $rr->rdata;
	is( $w, $rrtype >> 8, "expected window number for $type" );
}

foreach my $rrtype ( 0, 7, 8, 15, 16, 23, 24, 31, 32, 39 ) {
	my $type = typebyval($rrtype);
	$rr->typelist($type);
	my ( $w, $l, $bitmap ) = unpack 'x CCa*', $rr->rdata;
	is( $l, 1 + ( $rrtype >> 3 ), "expected map length for $type" );
}

foreach my $rrtype ( 0 .. 7 ) {
	my $type = typebyval($rrtype);
	$rr->typelist($type);
	my ( $w, $l, $bitmap ) = unpack 'x CCa*', $rr->rdata;
	my $last = unpack 'C', reverse $bitmap;
	is( $last, ( 0x80 >> $rrtype ), "expected map bit for $type" );
}


exit;

__END__

