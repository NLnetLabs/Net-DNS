# $Id$	-*-perl-*-

use strict;
use Test::More tests => 29;


use Net::DNS;


my $name = 'DS.example';
my $type = 'DS';
my $code = 43;
my @attr = qw( keytag algorithm digtype digest );
my @data = ( 60485, 5, 1, '2bb183af5f22588179a53b0a98631fad1a292118' );
my @also = qw( digestbin babble );

my $wire = qw( EC4505012BB183AF5F22588179A53B0A98631FAD1A292118 );


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
		is( $rr->$_, $hash->{$_}, "expected result from rr->$_()" );
	}

	foreach (@also) {
		is( $rr2->$_, $rr->$_, "additional attribute rr->$_()" );
	}


	my $empty   = new Net::DNS::RR("$name $type");
	my $encoded = $rr->encode;
	my $decoded = decode Net::DNS::RR( \$encoded );
	my $hex1    = uc unpack 'H*', $decoded->encode;
	my $hex2    = uc unpack 'H*', $encoded;
	my $hex3    = uc unpack 'H*', substr( $encoded, length $empty->encode );
	is( $hex1, $hex2, 'encode/decode transparent' );
	is( $hex3, $wire, 'encoded RDATA matches example' );
}


{
	my $rr	  = new Net::DNS::RR(". $type @data");
	my $class = ref($rr);

	$rr->algorithm('RSASHA512');
	is( $rr->algorithm(),		    10,		 'algorithm mnemonic accepted' );
	is( $rr->algorithm('MNEMONIC'),	    'RSASHA512', "rr->algorithm('MNEMONIC')" );
	is( $class->algorithm('RSASHA512'), 10,		 "class method algorithm('RSASHA512')" );
	is( $class->algorithm(10),	    'RSASHA512', "class method algorithm(10)" );
	is( $class->algorithm(255),	    255,	 "class method algorithm(255)" );

	eval { $rr->algorithm('X'); };
	my $exception = $1 if $@ =~ /^(.+)\n/;
	ok( $exception ||= '', "unknown mnemonic\t[$exception]" );
}


{
	my $rr	  = new Net::DNS::RR(". $type @data");
	my $class = ref($rr);

	$rr->digtype('SHA256');
	is( $rr->digtype(),	       2,	  'digest type mnemonic accepted' );
	is( $rr->digtype('MNEMONIC'),  'SHA-256', "rr->digtype('MNEMONIC')" );
	is( $class->digtype('SHA256'), 2,	  "class method digtype('SHA256')" );
	is( $class->digtype(2),	       'SHA-256', "class method digtype(2)" );
	is( $class->digtype(255),      255,	  "class method digtype(255)" );

	eval { $rr->digtype('X'); };
	my $exception = $1 if $@ =~ /^(.+)\n/;
	ok( $exception ||= '', "unknown mnemonic\t[$exception]" );
}


{
	my $rr = new Net::DNS::RR(". $type @data");
	eval { $rr->digest('123456789XBCDEF'); };
	my $exception = $1 if $@ =~ /^(.+)\n/;
	ok( $exception ||= '', "corrupt hexadecimal\t[$exception]" );
}


{
	my $rr = new Net::DNS::RR(". $type");
	foreach ( @attr, 'rdstring' ) {
		ok( !$rr->$_(), "'$_' attribute of empty RR undefined" );
	}
}


{
	my $rr = new Net::DNS::RR("$name $type @data");
	$rr->print;
}


exit;

