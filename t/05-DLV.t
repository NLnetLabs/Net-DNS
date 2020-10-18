#!/usr/bin/perl
# $Id$	-*-perl-*-
#

use strict;
use warnings;
use Test::More tests => 13;


use Net::DNS;


my $name = 'DLV.example';
my $type = 'DLV';
my $code = 32769;
my @attr = qw( keytag algorithm digtype digest );
my @data = ( 42495, 5, 1, '0ffbeba0831b10b8b83440dab81a2148576da9f6' );
my @also = qw( digestbin babble );

my $wire = join '', qw( A5FF 05 01 0FFBEBA0831B10B8B83440DAB81A2148576DA9F6 );


{
	my $typecode = unpack 'xn', Net::DNS::RR->new(". $type")->encode;
	is( $typecode, $code, "$type RR type code = $code" );

	my $hash = {};
	@{$hash}{@attr} = @data;

	my $rr = Net::DNS::RR->new(
		name => $name,
		type => $type,
		%$hash
		);

	my $string = $rr->string;
	my $rr2	   = Net::DNS::RR->new($string);
	is( $rr2->string, $string, 'new/string transparent' );

	is( $rr2->encode, $rr->encode, 'new($string) and new(%hash) equivalent' );

	foreach (@attr) {
		is( $rr->$_, $hash->{$_}, "expected result from rr->$_()" );
	}

	foreach (@also) {
		is( $rr2->$_, $rr->$_, "additional attribute rr->$_()" );
	}


	my $empty   = Net::DNS::RR->new("$name $type");
	my $encoded = $rr->encode;
	my $decoded = Net::DNS::RR->decode( \$encoded );
	my $hex1    = uc unpack 'H*', $decoded->encode;
	my $hex2    = uc unpack 'H*', $encoded;
	my $hex3    = uc unpack 'H*', substr( $encoded, length $empty->encode );
	is( $hex1, $hex2, 'encode/decode transparent' );
	is( $hex3, $wire, 'encoded RDATA matches example' );


	$rr->algorithm('RSASHA512');
	is( $rr->algorithm(), 10, 'algorithm mnemonic accepted' );

	$rr->digtype('SHA256');
	is( $rr->digtype(), 2, 'digest type mnemonic accepted' );
}


{
	my $rr = Net::DNS::RR->new("$name $type @data");
	$rr->print;
}
exit;

