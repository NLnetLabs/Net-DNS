# $Id$	-*-perl-*-
#

use strict;


BEGIN {
	use Test::More;

	my @prerequisite = qw(
			MIME::Base64
			Time::Local
			Net::DNS::RR::RRSIG
			Net::DNS::SEC
			Net::DNS::SEC::ECDSA
			);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
				unless eval "require $package";
	}

	plan tests => 7;

	use_ok('Net::DNS::SEC');
}


my $ksk = new Net::DNS::RR <<'END';
ECDSAP384SHA384.example.	IN	DNSKEY	257 3 14 (
	M7KQuXJ6te/ySDoqb6KKh6KJEtlkGrRN1fr3ECqG9/cF7wZLMj+HuW6zh3rq1D9Pz7ycOB7ODxgj
	bq5eSFTCcGUqlNiE5gw4VoFSJE1zS5VQPUj0O35kgnJtfiT5hzr3 ; Key ID = 23772
	)
END

ok( $ksk, 'set up ECDSA public ksk' );


my $keyfile = $ksk->privatekeyname;

END { unlink $keyfile }


open( KSK, ">$keyfile" ) or die "$keyfile $!";
print KSK <<'END';
Private-key-format: v1.2
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: PYm2xD5F4AGcefONoEQkGYGIO/Ur6HNWJOETACal/ZEnCimviFyvrJ1hFmgz5zaQ
END
close(KSK);


my $key = new Net::DNS::RR <<'END';
ECDSAP384SHA384.example.	IN	DNSKEY	256 3 14 (
	2lG4/insv7kKxX9QzQUzgnyneD7ZbPVSnjgI6jfmfdTHtnxHuKEnbgX7QQubj/YGA+Fpc86Lj0cp
	zDxLFwHgNJwJ0qjIXXfwTWiwkuNiShQPPVvF06iMyVpyoZntC7cc ; Key ID = 38753
	)
END

ok( $key, 'set up ECDSA public key' );


my @rrset = ( $key, $ksk );
my $rrsig = create Net::DNS::RR::RRSIG( \@rrset, $keyfile );
ok( $rrsig, 'create RRSIG over rrset using private ksk' );

my $verify = $rrsig->verify( \@rrset, $ksk );
ok( $verify, 'verify RRSIG using ksk' ) || diag $rrsig->vrfyerrstr;

ok( !$rrsig->verify( \@rrset, $key ), 'verify fails using wrong key' );

my @badrrset = ($key);
ok( !$rrsig->verify( \@badrrset, $ksk ), 'verify fails using wrong rrset' );


exit;

__END__

