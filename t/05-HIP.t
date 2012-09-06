# $Id$	-*-perl-*-

use strict;
use diagnostics;
use Test::More tests => 13;


use Net::DNS;


my $name = 'HIP.example';
my $type = 'HIP';
my $code = 55;
my @attr = qw( pkalgorithm hit pubkey servers );
my @data = qw( 2 200100107b1a74df365639cc39f1d578
		AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D
		rvs1.example.com
		rvs2.example.com );
my @also = qw( pubkeybin );

my $wire = join '', qw( 10020084200100107B1A74DF365639CC39F1D57803010001B771CA136E4AEB5C
		E44333C53B3D2C13C22243851FC708BCCE29F7E2EB5787B5F56CCAD34F8223AC
		C10904DDB56B2EC4A6D6232F3B50EA094F0914B3B941BBE529AF582C36BBADEF
		DAF2ADAF9B4911906F5B2522603C615272B880EC8FB930CC6EE39C444DAA75B1
		678F005A4B2499D1DA5433F805C7A5AD3237ACC5DD5C5E430472767331076578
		616D706C6503636F6D000472767332076578616D706C6503636F6D00
		);

{
	my $typecode = unpack 'xn', new Net::DNS::RR(". $type")->encode;
	is( $typecode, $code, "$type RR type code = $code" );

	my $hash = {};
	@{$hash}{@attr} = @data;

	my $rr = new Net::DNS::RR(
		name => $name,
		type => $type,
		%$hash
		);

	my $string = $rr->string;
	my $rr2	   = new Net::DNS::RR($string);
	is( $rr2->string, $string, 'new/string transparent' );

	is( $rr2->encode, $rr->encode, 'new($string) and new(%hash) equivalent' );

	foreach (@attr) {
		next if /server/;
		is( $rr->$_, $hash->{$_}, "expected result from rr->$_()" );
	}

	for (qw(servers)) {
		my ($rvs) = $rr->$_;				# limitation: single element list
		is( $rvs, $hash->{$_}, "expected result from rr->$_()" );
	}

	foreach (@also) {
		is( $rr2->$_, $rr->$_, "additional attribute rr->$_()" );
	}
}

{
	my $empty   = new Net::DNS::RR("$name $type");
	my $rr	    = new Net::DNS::RR("$name $type @data");
	my $encoded = $rr->encode;
	my $decoded = decode Net::DNS::RR( \$encoded );
	my $hex1    = uc unpack 'H*', $decoded->encode;
	my $hex2    = uc unpack 'H*', $encoded;
	my $hex3    = uc unpack 'H*', substr( $encoded, length $empty->encode );
	is( $hex1, $hex2, 'encode/decode transparent' );
	is( $hex3, $wire, 'encoded RDATA matches example' );
}


{
	my $lc		= new Net::DNS::RR( lc ". $type @data" );
	my $rr		= new Net::DNS::RR( uc ". $type @data" );
	my $hash	= {};
	my $predecessor = $rr->encode( 0, $hash );
	my $compressed	= $rr->encode( length $predecessor, $hash );
	ok( length $compressed == length $predecessor, 'encoded RDATA not compressible' );
	isnt( $rr->encode,    $lc->encode, 'encoded RDATA names not downcased' );
	isnt( $rr->canonical, $lc->encode, 'canonical RDATA names not downcased' );
}


exit;

