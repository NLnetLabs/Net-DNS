# $Id$	-*-perl-*-

use strict;
use Test::More tests => 16;


use Net::DNS;

use Digest::HMAC_MD5;


sub mysign {
	my ( $key, $data ) = @_;
	my $hmac = new Digest::HMAC_MD5($key);
	$hmac->add($data);
	return $hmac->hexdigest;
}


my $name = '123456789-test';
my $type = 'TSIG';
my $code = 250;
my @attr = qw( algorithm		time_signed fudge	key	sign_func );
my @data = ( qw(fake.algorithm.example.com 100001 36000 ), 'fake key', \&mysign );
my @also = qw( mac macbin error other );

my $wire =
'0466616b6509616c676f726974686d076578616d706c6503636f6d000000000186a18ca00020386163653137316336353034373533373861343635306135383339336662333104d200000000';


my $hash = {};
@{$hash}{@attr} = @data;


{
	my $typecode = unpack 'xn', new Net::DNS::RR(". $type")->encode;
	is( $typecode, $code, "$type RR type code = $code" );

	my $rr = new Net::DNS::RR(
		name => $name,
		type => $type,
		%$hash
		);

	my $string = $rr->string;
	like( $rr->string, "/$$hash{algorithm} NOERROR/", 'got expected rr->string' );

	foreach (@attr) {
		is( $rr->$_, $hash->{$_}, "expected result from rr->$_()" );
	}

	foreach (@also) {
		ok( defined $rr->$_, "additional attribute rr->$_()" );
	}


	my $null   = new Net::DNS::RR("$name NULL")->encode;
	my $empty  = new Net::DNS::RR("$name $type")->encode;
	my $rxbin  = decode Net::DNS::RR( \$empty )->encode;
	my $packet = Net::DNS::Packet->new( $name, 'TKEY', 'IN' );
	$packet->header->id(1234);				# fix packet id
	my $encoded = $rr->encode( 0, {}, $packet );
	my $decoded = decode Net::DNS::RR( \$encoded );
	my $hex1    = unpack 'H*', $encoded;
	my $hex2    = unpack 'H*', $decoded->encode;
	my $hex3    = unpack 'H*', substr( $encoded, length $null );
	is( $hex2,	    $hex1,	   'encode/decode transparent' );
	is( $hex3,	    $wire,	   'encoded RDATA matches example' );
	is( length($empty), length($null), 'encoded RDATA can be empty' );
	is( length($rxbin), length($null), 'decoded RDATA can be empty' );
}


{
	my $tkey = new Net::DNS::RR(
		name	   => $name,
		type	   => 'TKEY',
		algorithm  => $$hash{algorithm},
		inception  => 100000,				# fix inception time to give predictable checksum
		expiration => 100000 + 24 * 3600,
		mode	   => 3,				# GSS API
		key	   => "fake key",
		);


	my $tsig = new Net::DNS::RR(
		name => $name,
		type => 'TSIG',
		%$hash
		);


	my $packet = Net::DNS::Packet->new( $name, 'TKEY', 'IN' );
	$packet->header->id(1234);				# fixed packet id to give predictable checksum
	$packet->push( 'answer',     $tkey );
	$packet->push( 'additional', $tsig );


	my $raw_packet = $packet->data;				# create the packet - which fills in the 'mac' field

	is(	$tsig->mac,
		'6365643161343964663364643264656131306638303633626465366236643465',
		'generated MAC matches known good specimen'
		);
}


exit;

