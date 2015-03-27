# $Id$	-*-perl-*-

use strict;
use Test::More tests => 27;


use Net::DNS;


my $name = '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example';
my $type = 'NSEC3';
my $code = 50;
my @attr = qw( algorithm flags iterations salt hnxtname typelist );
my @data = qw( 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA MX RRSIG DNSKEY NSEC3PARAM );
my @hash = ( qw( 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr ), q(NS SOA MX RRSIG DNSKEY NSEC3PARAM) );
my @also = qw( optout );

my $wire = '0101000c04aabbccdd14174eb2409fe28bcb4887a1836f957f0a8425e27b000722010000000290';


{
	my $typecode = unpack 'xn', new Net::DNS::RR(". $type")->encode;
	is( $typecode, $code, "$type RR type code = $code" );

	my $hash = {};
	@{$hash}{@attr} = @hash;

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


	my $null    = new Net::DNS::RR("$name NULL")->encode;
	my $empty   = new Net::DNS::RR("$name $type")->encode;
	my $rxbin   = decode Net::DNS::RR( \$empty )->encode;
	my $txtext  = new Net::DNS::RR("$name $type")->string;
	my $rxtext  = new Net::DNS::RR($txtext)->encode;
	my $encoded = $rr->encode;
	my $decoded = decode Net::DNS::RR( \$encoded );
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
	use Net::DNS::RR::NSEC3 qw(name2hash);

	my $algorithm = 1;					# test vectors from RFC5155
	my $iteration = 12;
	my $salt      = pack 'H*', 'aabbccdd';

	my @name = qw(example a.example ai.example ns1.example ns2.example
		w.example *.w.example x.w.example y.w.example x.y.w.example);
	my %testcase = (
		'example'	=> '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom',
		'a.example'	=> '35mthgpgcu1qg68fab165klnsnk3dpvl',
		'ai.example'	=> 'gjeqe526plbf1g8mklp59enfd789njgi',
		'ns1.example'	=> '2t7b4g4vsa5smi47k61mv5bv1a22bojr',
		'ns2.example'	=> 'q04jkcevqvmu85r014c7dkba38o0ji5r',
		'w.example'	=> 'k8udemvp1j2f7eg6jebps17vp3n8i58h',
		'*.w.example'	=> 'r53bq7cc2uvmubfu5ocmm6pers9tk9en',
		'x.w.example'	=> 'b4um86eghhds6nea196smvmlo4ors995',
		'y.w.example'	=> 'ji6neoaepv8b5o6k4ev33abha8ht9fgc',
		'x.y.w.example'	=> '2vptu5timamqttgl4luu9kg21e0aor3s',
		);

	foreach my $name (@name) {
		my $hash = $testcase{$name};
		my @args = ( $algorithm, $name, $iteration, $salt );
		is( name2hash(@args), $hash, "H($name)" );
	}
}


{
	my @rdata = qw(1 1 12 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A);
	my $rr = new Net::DNS::RR(". $type @rdata");
	is( $rr->salt, '', 'parse RR with salt field placeholder' );
	is( $rr->rdstring, "@rdata", 'placeholder denotes empty salt field' );
}


{
	my $rr = new Net::DNS::RR("$name $type @data");
	$rr->print;
}

exit;

