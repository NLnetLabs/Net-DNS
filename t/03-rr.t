# $Id$	-*-perl-*-

use strict;
use Test::More tests => 52;


BEGIN {
	use_ok('Net::DNS');
	use_ok('Net::DNS::RR');
}


{				## check exception raised for unparsable argument
	foreach my $testcase ( undef, '', ' ' ) {
		eval { new Net::DNS::RR($testcase) };
		my $exception = $1 if $@ =~ /^(.+)\n/;
		my $test = defined $testcase ? "'$testcase'" : 'undef';
		ok( $exception ||= '', "new Net::DNS::RR($test)\t[$exception]" );
	}
}


{				## check basic parsing of all acceptable forms of A record
	my $example  = new Net::DNS::RR('example.com. 0 IN A 192.0.2.1');
	my $expected = $example->string;
	foreach my $testcase (
		join( "\t", qw( example.com 0 IN A ), q(\# 4 c0 00 02 01) ),
		join( "\t", qw( example.com 0 IN A ), q(\# 4 c0000201 ) ),
		'example.com	0	IN	A	192.0.2.1',
		'example.com	0	IN	TYPE1	192.0.2.1',
		'example.com	0	CLASS1	A	192.0.2.1',
		'example.com	0	CLASS1	TYPE1	192.0.2.1',
		'example.com	0		A	192.0.2.1',
		'example.com	0		TYPE1	192.0.2.1',
		'example.com		IN	A	192.0.2.1',
		'example.com		IN	TYPE1	192.0.2.1',
		'example.com		CLASS1	A	192.0.2.1',
		'example.com		CLASS1	TYPE1	192.0.2.1',
		'example.com			A	192.0.2.1',
		'example.com			TYPE1	192.0.2.1',
		'example.com	IN	0	A	192.0.2.1',
		'example.com	IN	0	TYPE1	192.0.2.1',
		'example.com	CLASS1	0	A	192.0.2.1',
		'example.com	CLASS1	0	TYPE1	192.0.2.1',
		) {
		my $rr = new Net::DNS::RR("$testcase");
		is( $rr->string, $expected, "new Net::DNS::RR( $testcase )" );
	}
}


{				## check parsing of comments, quotes and brackets
	my $example  = new Net::DNS::RR('example.com. 0 IN TXT "txt-data"');
	my $expected = $example->string;
	foreach my $testcase (
		q(example.com 0 IN TXT txt-data ; space delimited),
		q(example.com 0    TXT txt-data),
		q(example.com   IN TXT txt-data),
		q(example.com      TXT txt-data),
		q(example.com IN 0 TXT txt-data),
		q(example.com	0	IN	TXT	txt-data	; tab delimited),
		q(example.com	0		TXT	txt-data),
		q(example.com		IN	TXT	txt-data),
		q(example.com			TXT	txt-data),
		q(example.com	IN	0	TXT	txt-data),
		q(example.com	0	IN	TXT	'txt-data'	; 'quoted'),
		q(example.com	0		TXT	'txt-data'),
		q(example.com		IN	TXT	'txt-data'),
		q(example.com			TXT	'txt-data'),
		q(example.com	IN	0	TXT	'txt-data'),
		q(example.com	0	IN	TXT	"txt-data"	; "quoted"),
		q(example.com	0		TXT	"txt-data"),
		q(example.com		IN	TXT	"txt-data"),
		q(example.com			TXT	"txt-data"),
		q(example.com	IN	0	TXT	"txt-data"),
		'example.com (	0	IN	TXT	txt-data )	; bracketed',
		) {
		my $rr = new Net::DNS::RR("$testcase");
		is( $rr->string, $expected, "new Net::DNS::RR( $testcase )" );
	}
}


{				## check parsing of implemented RR type with hexadecimal RDATA
	my @common   = qw( example.com. 3600 IN TXT );
	my $expected = join "\t", @common, q("two separate" "quoted strings");
	my $testcase = join "\t", @common, q(\# 28 0c74776f2073657061726174650e71756f74656420737472696e6773);
	my $rr	     = new Net::DNS::RR("$testcase");
	is( $rr->string, $expected, "new Net::DNS::RR( $testcase )" );
}


{				## check parsing of known but unimplemented RR type
	my $expected = join "\t", qw( example.com. 3600 IN ATMA ),   q(\# 4 c0000201);
	my $testcase = join "\t", qw( example.com. 3600 IN TYPE34 ), q(\# 4 c0000201);
	my $rr	     = new Net::DNS::RR("$testcase");
	is( $rr->string, $expected, "new Net::DNS::RR( $testcase )" );
}


{				## check for exception if RFC3597 format hexadecimal data inconsistent
	foreach my $testcase ( '\# 0 c0 00 02 01', '\# 3 c0 00 02 01', '\# 5 c0 00 02 01' ) {
		eval { new Net::DNS::RR("example.com 3600 IN A $testcase") };
		my $exception = $1 if $@ =~ /^(.+)\n/;
		ok( $exception ||= '', "mismatched length: $testcase\t[$exception]" );
	}
}


{				## check encode/decode functions
	my $example = 'example.com. 123 IN A 192.0.2.1';
	my $packet  = new Net::DNS::Packet('example.com');
	my $A	    = new Net::DNS::RR($example);
	$packet->push( 'answer', $A );
	my $encoded = $packet->data;


	my ($rr)    = new Net::DNS::Packet( \$encoded )->answer;
	my $expect  = $A->string;
	is( $rr->string, $expect, "encode/decode $example" );

	isa_ok( $rr, 'Net::DNS::RR::A', 'check decoded object' );

	my $uncompressed = new Net::DNS::Packet('example.net');
	$uncompressed->push( 'answer', $A );
	ok( length $packet->data < length $uncompressed->data, 'owner domain name compressible' );
}

