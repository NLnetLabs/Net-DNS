# $Id$	-*-perl-*-

use strict;
use diagnostics;
use Test::More tests => 44;


use Net::DNS;


my $name = 'TXT.example';
my $type = 'TXT';
my $code = 16;
my @attr = qw( txtdata );
my @data = qw( arbitrary_text );

my $wire = '0E6172626974726172795F74657874';


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
	foreach my $testcase (
		q|contiguous|,	q|unquoted contiguous strings|,
		q|"in quotes"|, q|"two separate" "quoted strings"|,
		q|"" empty|,	q|" " space|,
		q|!|,		q|"\""|,
		q|#|,		q|"$"|,
		q|%|,		q|&|,
		q|"'"|,		q|"("|,
		q|")"|,		q|*|,
		q|+|,		q|,|,
		q|-|,		q|.|,
		q|/|,		q|:|,
		q|";"|,		q|<|,
		q|=|,		q|>|,
		q|?|,		q|"@"|,
		q|[|,		q|\\\\|,
		q|]|,		q|^|,
		q|_|,		q|`|,
		q|{|,		q(|),
		q|}|,		q|~|,
		) {
		my $string = "example.com.	TXT	$testcase";
		my $expect = new Net::DNS::RR($string)->string;	# test for consistent parsing
		my $result = new Net::DNS::RR($expect)->string;
		is( $result, $expect, $string );
	}
}


exit;

