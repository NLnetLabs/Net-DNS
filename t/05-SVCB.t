#!/usr/bin/perl
# $Id$	-*-perl-*-
#

use strict;
use warnings;
use Test::More tests => 50;

use Net::DNS;

my $name = 'alias.example';
my $type = 'SVCB';
my $code = 64;
my @attr = qw( svcpriority targetname );
my @data = qw( 0 pool.svc.example );
my @also = qw(mandatory alpn no-default-alpn port ipv4hint ech ipv6hint);

my $wire = '000004706f6f6c03737663076578616d706c6500';


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

	foreach (qw(svcpriority targetname)) {
		is( $rr->$_, $hash->{$_}, "expected result from rr->$_()" );
	}


	my $null    = Net::DNS::RR->new("$name NULL")->encode;
	my $empty   = Net::DNS::RR->new("$name $type")->encode;
	my $rxbin   = Net::DNS::RR->decode( \$empty )->encode;
	my $txtext  = Net::DNS::RR->new("$name $type")->string;
	my $rxtext  = Net::DNS::RR->new($txtext)->encode;
	my $encoded = $rr->encode;
	my $decoded = Net::DNS::RR->decode( \$encoded );
	my $hex1    = unpack 'H*', $encoded;
	my $hex2    = unpack 'H*', $decoded->encode;
	my $hex3    = unpack 'H*', substr( $encoded, length $null );
	is( $hex2,	     $hex1,	    'encode/decode transparent' );
	is( $hex3,	     $wire,	    'encoded RDATA matches example' );
	is( length($empty),  length($null), 'encoded RDATA can be empty' );
	is( length($rxbin),  length($null), 'decoded RDATA can be empty' );
	is( length($rxtext), length($null), 'string RDATA can be empty' );
}


{
	my @rdata	= qw(0 svc.example.net);
	my $lc		= Net::DNS::RR->new( lc ". $type @rdata" );
	my $rr		= Net::DNS::RR->new( uc ". $type @rdata" );
	my $hash	= {};
	my $predecessor = $rr->encode( 0,		    $hash );
	my $compressed	= $rr->encode( length $predecessor, $hash );
	ok( length $compressed == length $predecessor, 'encoded RDATA not compressible' );
	isnt( $rr->encode,    $lc->encode, 'encoded RDATA names not downcased' );
	isnt( $rr->canonical, $lc->encode, 'canonical RDATA names not downcased' );
}


{
	my $rr = Net::DNS::RR->new(". $type");
	foreach ( qw(TargetName), @also ) {
		is( $rr->$_(), undef, "attribute '$_'	of empty RR undefined" );
	}
}


{
	my $rr = Net::DNS::RR->new(qq(. $type 1 . alpn="h3,h2" no-default-alpn));
	ok( $rr->alpn, 'key string for alpn' );
}


{
	my $rr = Net::DNS::RR->new(". $type 1 . port=1234");
	ok( $rr->port, 'key string for port' );
}


{
	my $rr = Net::DNS::RR->new(". $type 1 . ipv4hint=192.0.2.1");
	ok( $rr->ipv4hint, 'key string for ipv4hint' );
}


{
	my $rr = Net::DNS::RR->new(". $type 1 . ipv6hint=2001:DB8::1");
	ok( $rr->ipv6hint, 'key string for ipv6hint' );
}


{
	my $l0 = length( Net::DNS::RR->new(". $type 1 .")->encode );
	my $rr = Net::DNS::RR->new(". $type 1 . port=1234");
	$rr->key3(undef);
	is( length( $rr->encode ), $l0, 'delete SvcParams key' );
	is( $rr->key3, undef, 'return undef for undefined key' );
}


{
	eval { Net::DNS::RR->new(". $type 1 . mandatory=bogus") };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "unknown mandatory key\t[$exception]" );
}


{
	my $wire = Net::DNS::RR->new(". $type 1 . mandatory=port port=1234")->encode;
	substr( $wire, -4, 2 ) = pack 'H*', '0003';
	eval { Net::DNS::RR->decode( \$wire ) };
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "corrupt wire format\t[$exception]" );
}


####	Test Vectors

## D.1.	Alias Form

{
	my $testcase = Net::DNS::RR->new('example.com.	 SVCB	0 foo.example.com.');
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 19 (
00 00							; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00	; target
)
END
	is( $testcase->string, $expected->string, 'SVCB Alias Form' );
}


## D.2.	Service Form

{
	my $testcase = Net::DNS::RR->new('example.com.	 SVCB	1 .');
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 3 (
00 01							; priority
00							; target (root label)
)
END
	is( $testcase->string, $expected->string, 'SVCB Service Form' );
}


{
	my $testcase = Net::DNS::RR->new( <<'END' );
example.com.   SVCB   16 foo.example.com. port=53
END
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 25 (
00 10							; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00	; target
00 03							; key 3
00 02							; length 2
00 35							; value
)
END
	is( $testcase->string, $expected->string, 'SVCB defines a port' );
}


{
	my $testcase = Net::DNS::RR->new( <<'END' );
example.com.   SVCB   1 foo.example.com. key667=hello
END
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 28 (
00 01							; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00	; target
02 9b							; key 667
00 05							; length 5
68 65 6c 6c 6f						; value
)
END
	is( $testcase->string, $expected->string, 'unregistered key, unquoted value' );
}


{
	my $testcase = Net::DNS::RR->new( <<'END' );
example.com.   SVCB   1 foo.example.com. key667="hello\210qoo"
END
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 32 (
00 01							; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00	; target
02 9b							; key 667
00 09							; length 9
68 65 6c 6c 6f d2 71 6f 6f				; value
)
END
	is( $testcase->string, $expected->string, 'unregistered key, quoted with decimal escape' );
}


{
	my $testcase = Net::DNS::RR->new( <<'END' );
example.com.   SVCB   1 foo.example.com. ipv6hint="2001:db8::1,2001:db8::53:1"
END
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 55 (
00 01							; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00	; target
00 06							; key 6
00 20							; length 32
20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01		; first address
20 01 0d b8 00 00 00 00 00 00 00 00 00 53 00 01		; second address
)
END
	is( $testcase->string, $expected->string, 'two IPv6 hints in quoted presentation format' );
}


{
	my $testcase = Net::DNS::RR->new( <<'END' );
example.com.   SVCB   1 example.com. ipv6hint="2001:db8:ffff:ffff:ffff:ffff:198.51.100.100"
END
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 35 (
00 01							; priority
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00			; target
00 06							; key 6
00 10							; length 16
20 01 0d b8 ff ff ff ff ff ff ff ff c6 33 64 64		; address
)
END
	is( $testcase->string, $expected->string, 'single IPv6 hint in IPv4 mapped IPv6 format' );
}


{
	my $testcase = Net::DNS::RR->new( <<'END' );
example.com.   SVCB   16 foo.example.org. (alpn=h2,h3-19 mandatory=ipv4hint,alpn
			ipv4hint=192.0.2.1)
END
	my $expected = Net::DNS::RR->new( <<'END' );
example.com	SVCB	\# 48 (
00 10							; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00	; target
00 00							; key 0
00 04							; param length 4
00 01							; value: key 1
00 04							; value: key 4
00 01							; key 1
00 09							; param length 9
02							; alpn length 2
68 32							; alpn value
05							; alpn length 5
68 33 2d 31 39						; alpn value
00 04							; key 4
00 04							; param length 4
c0 00 02 01						; param value
)
END
	is( $testcase->string, $expected->string, 'unsorted SvcParams and mandatory key list' );
}


{
	my $testcaseA = Net::DNS::RR->new( <<'END' );
;foo.example.com	SVCB	16 foo.example.org. alpn="f\\\\oo\\,bar,h2"
foo.example.com	SVCB	16 foo.example.org. alpn="f\\oo\,bar,h2"
END
	my $testcaseB = Net::DNS::RR->new( <<'END' );
;foo.example.com	SVCB	16 foo.example.org. alpn=f\\\092oo\092,bar,h2
foo.example.com	SVCB	16 foo.example.org. alpn=f\092oo\,bar,h2
END
	my $expected = Net::DNS::RR->new( <<'END' );
foo.example.com	SVCB	\# 35 (
00 10							; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00	; target
00 01							; key 1
00 0c							; param length 12
08							; alpn length 8
66 5c 6f 6f 2c 62 61 72					; alpn value
02							; alpn length 2
68 32							; alpn value
)
END
	is( $testcaseA->string, $expected->string, 'alpn with escaped escape and escaped comma' );
	is( $testcaseB->string, $expected->string, 'alpn with numeric escape and escaped comma' );
}


## D.3.	Failure Cases

{
	eval {
		Net::DNS::RR->new( <<'END' ) };
example.com.   SVCB   1 foo.example.com. (
			key123=abc key123=def
			)
END
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "key already defined\t[$exception]" );
}


{
	foreach my $key (qw(mandatory alpn port ipv4hint ipv6hint)) {
		eval {
			Net::DNS::RR->new( <<"END" ) };
example.com.   SVCB   1 foo.example.com. $key
END
		my ($exception) = split /\n/, "$@\n";
		ok( $exception, "no argument ($key)\t[$exception]" );
	}
}


{
	eval {
		Net::DNS::RR->new( <<'END' ) };
example.com.   SVCB   1 foo.example.com. no-default-alpn=abc
END
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "no-default-alpn + value\t[$exception]" );
}


{
	eval {
		Net::DNS::RR->new( <<'END' ) };
example.com.   SVCB   1 foo.example.com. mandatory=mandatory
END
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "mandatory lists key0\t[$exception]" );
}


{
	eval {
		Net::DNS::RR->new( <<'END' ) };
example.com.   SVCB   1 foo.example.com. (
			mandatory=key123,key123 key123=abc
			)
END
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "duplicate mandatory key\t[$exception]" );
}


{
	eval {
		Net::DNS::RR->new( <<'END' ) };
example.com.   SVCB   1 foo.example.com. mandatory=key123
END
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "undefined mandatory key\t[$exception]" );
}


{
	eval {
		Net::DNS::RR->new( <<'END' ) };
example.com.   SVCB   1 foo.example.com. (
			no-default-alpn		; without expected alpn
			)
END
	my ($exception) = split /\n/, "$@\n";
	ok( $exception, "alpn not specified\t[$exception]" );
}


####


foreach (qw(. short long.example.net)) {			# cosmetic bits
	Net::DNS::RR->new("alias.net $type 1 $_ port=1234")->string;
}


{
	my $rr = Net::DNS::RR->new( <<'END' );
example.com.   SVCB   16 foo.example.org. (alpn=h2,h3-19 mandatory=ipv4hint,alpn
			ipv4hint=192.0.2.1)
END
	$rr->print;
}


{
	local $SIG{__WARN__} = sub { };				# echconfig deprecated in favour of ech
	Net::DNS::RR->new(qq[. $type 1 . echconfig="..."])
}

exit;

