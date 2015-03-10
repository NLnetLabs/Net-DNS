# $Id$	-*-perl-*-
#

use strict;


BEGIN {
	use Test::More;

	my @prerequisite = qw(
			Net::DNS::SEC
			Net::DNS::SEC::RSA
			);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
				unless eval "require $package";
	}

	plan tests => 8;

	use_ok('Net::DNS::SEC');
}


my $key = new Net::DNS::RR <<'END';
RSAMD5.example.		IN	KEY	512 3 1 (
	AwEAAcUHtdNvhdBKMkUle+MJ+ntJ148yfsITtZC0g93EguURfU113BQVk6tzgXP/aXs4OptkCgrL
	sTapAZr5+vQ8jNbLp/uUTqEUzBRMBqi0W78B3aEb7vEsC0FB6VLoCcjylDcKzzWHm4rj1ACN2Zbu
	6eT88lDYHTPiGQskw5LGCze7 ; Key ID = 2871
	)
END

ok( $key, 'set up RSA public key' );

my $keyfile = $key->privatekeyname;

END { unlink($keyfile) }


open( KEY, ">$keyfile" ) or die "$keyfile $!";
print KEY <<'END';
Private-key-format: v1.2
Algorithm: 1 (RSA)
Modulus: xQe102+F0EoyRSV74wn6e0nXjzJ+whO1kLSD3cSC5RF9TXXcFBWTq3OBc/9pezg6m2QKCsuxNqkBmvn69DyM1sun+5ROoRTMFEwGqLRbvwHdoRvu8SwLQUHpUugJyPKUNwrPNYebiuPUAI3Zlu7p5PzyUNgdM+IZCyTDksYLN7s=
PublicExponent: AQAB
PrivateExponent: yOATgH0y8Ci1F8ofhFmoBgpCurvAgB2X/vALgQ3YZbJvDYob1l4pL6OTV7AO2pF5LvPPSTJielfUSyyRrnANJSST/Dr19DgpSpnY2GWE7xmJ6/QqnIaJ2+10pFzVRXShijJZjt9dY7JXmNIoQ+JseE08aquKHFEGVfsvkThk8Q==
Prime1: 9lyWnGhbZZwVQo/qNHjVeWEDyc0hsc/ynT4Qp/AjVhROY+eJnBEvhtmqj3sq2gDQm2ZfT8uubSH5ZkNrnJjL2Q==
Prime2: zL0L5kwZXqUyRiPqZgbhFEib210WZne+AI88iyi39tU/Iplx1Q6DhHmOuPhUgCCj2nqQhWs9BAkQwemLylfHsw==
Exponent1: rcETgHChtYJmBDIYTrXCaf8get2wnAY76ObzPF7DrVxZBWExzt7YFFXEU7ncuTDF8DQ9mLvg45uImLWIWkPx0Q==
Exponent2: qtb8vPi3GrDCGKETkHshCank09EDRhGY7CKZpI0fpMogWqCrydrIh5xfKZ2d9SRHVaF8QrhPO7TM1OIqkXdZ3Q==
Coefficient: IUxSSCxp+TotMTbloOt/aTtxlaz0b5tSS7dBoLa7//tmHZvHQjftEw8KbXC89QhHd537YZX4VcK/uYbU6SesRA==
END
close(KEY);


my $update = new Net::DNS::Update('example.com');
ok( $update, 'set up new update packet' );

$update->push( update => rr_add('foo.example.com A 10.1.2.3') );
ok( scalar $update->authority(), 'insert record in update packet' );

$update->sign_sig0($keyfile);
my $buffer = $update->data;		## SIG0 generation occurs here

my ($updsig) = reverse $update->additional;
ok( $updsig->sigbin, 'sign update packet (SIG0)' );


my $packet = new Net::DNS::Packet( \$buffer );


my ($sigrr) = reverse $update->additional;
my $verify = $sigrr->verify( $packet, $key );
ok( $verify, 'verify packet using public key' ) || diag $sigrr->vrfyerrstr;

my $bad = new Net::DNS::RR <<'END';
RSAMD5.example.		IN	KEY	512 3 1 (
	AwEAAdDembFMoX8rZTqTjHT8PbCZHbTJpDgtuL0uXpJqPZ6ZKnGdQsXVn4BSs8VJlH7+NEv+7Spq
	Ncxjx6o86HhrvFg5DsDMhEi5MIqlt1OcUYa0zUhFSkb+yzOSnPL7doSoaW8pxoX4uDemkfyOY9xN
	tNCNBJcvmp1Uvdnttf7LUorD ; Key ID = 21130
	)
END
ok( !$sigrr->verify( $packet, $bad ), 'verify fails using wrong key' );

$packet->push( update => $bad );
ok( !$sigrr->verify( $packet, $key ), 'verify fails for modified packet' );


exit;

__END__

