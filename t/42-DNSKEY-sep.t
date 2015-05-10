# $Id$	-*-perl-*-
#

use strict;

BEGIN {
	use Test::More;
	use Net::DNS;

	my @prerequisite = qw(
			MIME::Base64
			Net::DNS::RR::DNSKEY;
			);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
				unless eval "require $package";
	}

	plan tests => 6;
}


my $key = new Net::DNS::RR <<'END';
RSASHA1.example.	IN	DNSKEY	256 3 5 (
	AwEAAZHbngk6sMoFHN8fsYY6bmGR4B9UYJIqDp+mORLEH53Xg0f6RMDtfx+H3/x7bHTUikTr26bV
	AqsxOs2KxyJ2Xx9RGG0DB9O4gpANljtTq2tLjvaQknhJpSq9vj4CqUtr6Wu152J2aQYITBoQLHDV
	i8mIIunparIKDmhy8TclVXg9 ; Key ID = 1623
	)
END

ok( $key, 'set up DNSKEY record' );


my $sep = $key->sep;
ok( !$sep, 'Boolean sep flag has expected value' );

my $keytag = $key->keytag;
$key->sep( !$sep );
ok( $key->sep, 'Boolean sep flag toggled' );
isnt( $key->keytag, $keytag, 'keytag recalculated using modified sep flag' );

$key->sep($sep);
ok( !$sep, 'Boolean sep flag restored' );

is( $key->keytag, $keytag, 'keytag recalculated using restored sep flag' );

exit;

__END__

