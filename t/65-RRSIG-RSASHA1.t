#!/usr/bin/perl
# $Id$	-*-perl-*-
#

use strict;
use warnings;
use IO::File;
use Test::More;

my %prerequisite = (
	'MIME::Base64'	=> 2.13,
	'Net::DNS::SEC' => 1.01,
	'Time::Local'	=> 1.19,
	);

foreach my $package ( sort keys %prerequisite ) {
	my @revision = grep {$_} $prerequisite{$package};
	next if eval "use $package @revision; 1;";		## no critic
	plan skip_all => "$package not installed";
	exit;
}

plan tests => 32;


my $ksk = Net::DNS::RR->new( <<'END' );
RSASHA1.example.	IN	DNSKEY	257 3 5 (
	AwEAAefP0RzK3K39a5wznjeWA1PssI2dxqPb9SL+ppY8wcimOuEBmSJP5n6/bwg923VFlRiYJHe5
	if4saxWCYenQ46hWz44sK943K03tfHkxo54ayAk/7dMj1wQ7Dby5FJ1AAMGZZO65BlKSD+2BTcwp
	IL9mAYuhHYfkG6FTEEKgHVmOVmtyKWA3gl3RrSSgXzTWnUS5b/jEeh2SflXG9eXabaoVXEHQN+oJ
	dTiAiErZW4+Zlx5pIrSycZBpIdWvn4t71L3ik6GctQqG9ln12j2ngji3blVI3ENMnUc237jUeYsy
	k7E5TughQctLYOFXHaeTMgJt0LUTyv3gIgDTRmvgQDU= ) ; Key ID = 4501
END

ok( $ksk, 'set up RSA public ksk' );


my $keyfile = $ksk->privatekeyname;

END { unlink($keyfile) if defined $keyfile; }

my $handle = IO::File->new( $keyfile, '>' ) || die "$keyfile $!";
print $handle <<'END';
Private-key-format: v1.2
Algorithm: 5 (RSASHA1)
Modulus: 58/RHMrcrf1rnDOeN5YDU+ywjZ3Go9v1Iv6mljzByKY64QGZIk/mfr9vCD3bdUWVGJgkd7mJ/ixrFYJh6dDjqFbPjiwr3jcrTe18eTGjnhrICT/t0yPXBDsNvLkUnUAAwZlk7rkGUpIP7YFNzCkgv2YBi6Edh+QboVMQQqAdWY5Wa3IpYDeCXdGtJKBfNNadRLlv+MR6HZJ+Vcb15dptqhVcQdA36gl1OICIStlbj5mXHmkitLJxkGkh1a+fi3vUveKToZy1Cob2WfXaPaeCOLduVUjcQ0ydRzbfuNR5izKTsTlO6CFBy0tg4Vcdp5MyAm3QtRPK/eAiANNGa+BANQ==
PublicExponent: AQAB
PrivateExponent: qVfDp4j61ZAAAMgkmO7Z14FdKNdNuX6CAeKNx8rytaXZ9W25dLtx4r3uWtL1cyI13RWn7l54VFoWkEwDQ0/6P4vLbE0QbvFWjUMkX1TH9kQSRc+R6WCRPuH1Ex0R1h5fbw6kEVDRMZjKUfLX5oFVDv1xu5Mjg5Y8KQoJIuLdDgHtRRV7ZETcGcSXBQ1eY2rNxui2YzM0mtqzApgGq7pLb3GfiM5aqW5fSdRaFajGC2VIXkN3jZYxAryT8EYJ6uRFJk0X3VegEwj6keHOem/tBV2DaNlv1JWidauPeU67evKNTQVW3h3AbQxnOtegdWrRKoa9Ksf27bgoKAlveHIfsQ==
Prime1: +s1y+iP+AoB4UVS4S5njIZD21AWm36JTaqEvRPdevjuzc9q7yJATROdRdcAitdSPHeRC8xtQw/C9zGhJRdynlxfmUTeyYgM0EYHYiG7PLwkW5Wu9EeXJ7/Fpct51L+ednloQ0d7tYP/5QUd6cqbFGGKH0yF5zZMO0k+ZZ/saeCs=
Prime2: 7J2eVZ5Psue4BTNya8PMA89cC0Gf51zFeQ8dPBZIOpN28DJN2EN6C6fwGtnr6BO+M/6loXzcekPGgRkpNcQ6MzJup8hZQmU8RxESAMlmQzOtaBbtmMwPa0p6IcZBUWpbRaKwQ4ZjAUS9R13PFwgEU+a855o0XRRTupdmyZ6OmR8=
Exponent1: nGakbdMmIx9EaMuhRhwIJTWGhz+jCdDrnhI4LRTqM019oiDke7VFHvH1va18t9F/Ek/3ZC1Dl304jxD1qKhqpnGUAk/uYOrIfKZxhts7PoS3j4g5VsDqxkPQ035gq+gPReG6nXYcqCHYqVnOxVK0lHlVZFd64rTzSDm1W7+eiRM=
Exponent2: evAuKygVGsxghXtEkQ9rOfOMTGDtdyVxiMO8mdKt9plV69kHLz1n9RRtoVXmx28ynQtK/YvFdlUulzb+fWwWHTGv4scq8V9uITKSWwxJcNMx3upCyugDfuh0aoX6vBV5lMXBtWPmnusbOTBZgArvTLSPI/qwCEiedE1j34/dYVs=
Coefficient: JTEzUDflC+G0if7uqsJ2sw/x2aCHMjsCxYSmx2bJOW/nhQTQpzafL0N8E6WmKuEP4qAaqQjWrDyxy0XcAJrfcojJb+a3j2ndxYpev7Rq8f7P6M7qqVL0Nzj9rWFH7pyvWMnH584viuhPcDogy8ymHpNNuAF+w98qjnGD8UECiV4=
END
close($handle);

my $private = Net::DNS::SEC::Private->new($keyfile);
ok( $private, 'set up RSA private key' );


my $bad1 = Net::DNS::RR->new( <<'END' );
RSASHA1.example.	IN	DNSKEY	256 3 5 (
	AwEAAZHbngk6sMoFHN8fsYY6bmGR4B9UYJIqDp+mORLEH53Xg0f6RMDtfx+H3/x7bHTUikTr26bV
	AqsxOs2KxyJ2Xx9RGG0DB9O4gpANljtTq2tLjvaQknhJpSq9vj4CqUtr6Wu152J2aQYITBoQLHDV
	i8mIIunparIKDmhy8TclVXg9 ) ; Key ID = 1623
END


my $bad2 = Net::DNS::RR->new( <<'END' );
ECDSAP256SHA256.example.	IN	DNSKEY	( 256 3 13
	7Y4BZY1g9uzBwt3OZexWk7iWfkiOt0PZ5o7EMip0KBNxlBD+Z58uWutYZIMolsW8v/3rfgac45lO
	IikBZK4KZg== ) ; Key ID = 44222
END


my @rrset    = ( $bad1, $ksk );
my @badrrset = ($bad1);

{
	my $object = Net::DNS::RR::RRSIG->create( \@rrset, $keyfile );
	ok( $object->sig(), 'create RRSIG over rrset using private ksk' );

	my $verified = $object->verify( \@rrset, $ksk );
	ok( $verified, 'verify using public ksk' );
	is( $object->vrfyerrstr, '', 'observe no object->vrfyerrstr' );
}


{
	my $object = Net::DNS::RR::RRSIG->create( \@rrset, $keyfile );

	my $verified = $object->verify( \@badrrset, $bad1 );
	ok( !$verified,		 'verify fails using wrong key' );
	ok( $object->vrfyerrstr, 'observe rrsig->vrfyerrstr' );
}


{
	my $object = Net::DNS::RR::RRSIG->create( \@rrset, $keyfile );

	my $verified = $object->verify( \@badrrset, $bad2 );
	ok( !$verified,		 'verify fails using key with wrong algorithm' );
	ok( $object->vrfyerrstr, 'observe rrsig->vrfyerrstr' );
}


{
	my $object = Net::DNS::RR::RRSIG->create( \@rrset, $keyfile );

	my $verified = $object->verify( \@rrset, [$bad1, $bad2, $ksk] );
	ok( $verified, 'verify using array of keys' );
	is( $object->vrfyerrstr, '', 'observe no rrsig->vrfyerrstr' );
}


{
	my $object = Net::DNS::RR::RRSIG->create( \@rrset, $keyfile );

	my $verified = $object->verify( \@badrrset, [$bad1, $bad2, $ksk] );
	ok( !$verified,		 'verify fails using wrong rrset' );
	ok( $object->vrfyerrstr, 'observe rrsig->vrfyerrstr' );
}


{
	my $wild   = Net::DNS::RR->new('*.example. A 10.1.2.3');
	my $match  = Net::DNS::RR->new('leaf.twig.example. A 10.1.2.3');
	my $object = Net::DNS::RR::RRSIG->create( [$wild], $keyfile );

	my $verified = $object->verify( [$match], $ksk );
	ok( $verified, 'wildcard matches child domain name' );
	is( $object->vrfyerrstr, '', 'observe no rrsig->vrfyerrstr' );
}


{
	my $wild   = Net::DNS::RR->new('*.example. A 10.1.2.3');
	my $bogus  = Net::DNS::RR->new('example. A 10.1.2.3');
	my $object = Net::DNS::RR::RRSIG->create( [$wild], $keyfile );

	my $verified = $object->verify( [$bogus], $ksk );
	ok( !$verified,		 'wildcard does not match parent domain' );
	ok( $object->vrfyerrstr, 'observe rrsig->vrfyerrstr' );
}


{
	my $time = time() + 3;
	my %args = (
		siginception  => $time,
		sigexpiration => $time,
		);
	my $object = Net::DNS::RR::RRSIG->create( \@rrset, $keyfile, %args );

	ok( !$object->verify( \@rrset, $ksk ), 'verify fails for postdated RRSIG' );
	ok( $object->vrfyerrstr,	       'observe rrsig->vrfyerrstr' );
	sleep 1 until $time < time();
	ok( !$object->verify( \@rrset, $ksk ), 'verify fails for expired RRSIG' );
	ok( $object->vrfyerrstr,	       'observe rrsig->vrfyerrstr' );
}


{
	my $object   = Net::DNS::RR->new( type => 'RRSIG' );
	my $class    = ref($object);
	my $array    = [];
	my $dnskey   = Net::DNS::RR->new( type => 'DNSKEY' );
	my $private  = Net::DNS::SEC::Private->new($keyfile);
	my $packet   = Net::DNS::Packet->new();
	my $rr1	     = Net::DNS::RR->new( name	=> 'example', type => 'A' );
	my $rr2	     = Net::DNS::RR->new( name	=> 'differs', type => 'A' );
	my $rr3	     = Net::DNS::RR->new( type	=> 'A',	      ttl  => 1 );
	my $rr4	     = Net::DNS::RR->new( type	=> 'A',	      ttl  => 2 );
	my $rr5	     = Net::DNS::RR->new( class => 'IN',      type => 'A' );
	my $rr6	     = Net::DNS::RR->new( class => 'ANY',     type => 'A' );
	my $rr7	     = Net::DNS::RR->new( type	=> 'A' );
	my $rr8	     = Net::DNS::RR->new( type	=> 'AAAA' );
	my @testcase = (		## test create() with invalid arguments
		[$dnskey,      $dnskey],
		[$array,       $private],
		[[$rr1, $rr2], $private],
		[[$rr3, $rr4], $private],
		[[$rr5, $rr6], $private],
		[[$rr7, $rr8], $private],
		);

	foreach my $arglist (@testcase) {
		my @argtype = map { ref($_) } @$arglist;
		eval { $class->create(@$arglist); };
		my ($exception) = split /\n/, "$@\n";
		ok( $exception, "create(@argtype)\t[$exception]" );
	}
}


{
	my $object   = Net::DNS::RR->new( type => 'RRSIG' );
	my $packet   = Net::DNS::Packet->new();
	my $dnskey   = Net::DNS::RR->new( type => 'DNSKEY' );
	my $dsrec    = Net::DNS::RR->new( type => 'DS' );
	my $scalar   = 'SCALAR';
	my @testcase = (		## test verify() with invalid arguments
		[$packet, $dnskey],
		[$dnskey, $dsrec],
		[$dnskey, $scalar],
		);

	foreach my $arglist (@testcase) {
		my @argtype = map { ref($_) || $_ } @$arglist;
		eval { $object->verify(@$arglist); };
		my ($exception) = split /\n/, "$@\n";
		ok( $exception, "verify(@argtype)\t[$exception]" );
	}
}


{
	my $object = Net::DNS::RR->new( type => 'RRSIG', algorithm => 0 );

	foreach my $method (qw(_CreateSig _VerifySig)) {
		eval { $object->$method(); };
		my $errorstring = $object->vrfyerrstr() || $@;
		my ($exception) = split /\n/, "$errorstring\n";
		ok( $exception, "$method()\t[$exception]" );
	}
}


exit;

__END__

