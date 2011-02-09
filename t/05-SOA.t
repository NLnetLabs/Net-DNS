# $Id$	-*-perl-*-

use strict;
use Test::More tests => 22;


use Net::DNS;


my $name = 'example.com.';
my $type = 'SOA';
my $code = 6;
my @attr = qw( mname rname serial refresh retry expire minimum );
my @data = qw( ns.example.net rp.example.com 0 14400 1800 604800 7200 );
my $wire = '026E73076578616D706C65036E657400027270076578616D706C6503636F6D0000000000000038400000070800093A8000001C20';


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
}


{
	my $empty   = new Net::DNS::RR(". $type");
	my $rr	    = new Net::DNS::RR(". $type @data");
	my $encoded = $rr->encode;
	my $decoded = decode Net::DNS::RR( \$encoded );
	my $hex1    = uc unpack 'H*', $decoded->encode;
	my $hex2    = uc unpack 'H*', $encoded;
	my $hex3    = uc unpack 'H*', substr( $encoded, length $empty->encode );
	is( $hex1, $hex2, 'encode/decode transparent' );
	is( $hex3, $wire, 'encoded RDATA matches example' );
}


{
	my $string	= lc join ' ', @data;
	my $lc		= new Net::DNS::RR(". $type $string" );
	my $rr		= new Net::DNS::RR(uc ". $type $string" );
	my $hash	= {};
	my $predecessor = $rr->encode( 0, $hash );
	my $compressed	= $rr->encode( length $predecessor, $hash );
	ok( length $compressed < length $predecessor, 'encoded RDATA compressible' );
	isnt( $rr->encode, $lc->encode, 'encoded RDATA names not downcased' );
	is( $rr->canonical, $lc->encode, 'canonical RDATA names downcased' );
}



#use constant SEQUENTIAL => undef;

{
	use integer;
	my $rr	    = new Net::DNS::RR('name SOA mname rname 1');
	my $initial = $rr->serial;
	$rr->serial(SEQUENTIAL);
	is( $rr->serial, ++$initial, 'rr->serial(SEQUENTIAL) increments existing serial number' );

	my $pre31wrap  = 0x7FFFFFFF;
	my $post31wrap = 0x80000000;
	$rr->serial($pre31wrap);
	is( $rr->serial(SEQUENTIAL), 0 + $post31wrap, "rr->serial(SEQUENTIAL) wraps $pre31wrap to $post31wrap" );

	my $pre32wrap  = 0xFFFFFFFF;
	my $post32wrap = 0x00000000;
	$rr->serial($pre32wrap);
	is( $rr->serial(SEQUENTIAL), 0 + $post32wrap, "rr->serial(SEQUENTIAL) wraps $pre32wrap to $post32wrap" );
}



#sub YYYYMMDDxx {
#	my ( $dd, $mm, $yy ) = (localtime)[3 .. 5];
#	return 1900010000 + sprintf '%d%0.2d%0.2d00', $yy, $mm, $dd;
#}

{
	use integer;
	my $rr	     = new Net::DNS::RR('name SOA mname rname 2000000000');
	my $predate  = $rr->serial;
	my $postdate = YYYYMMDDxx;
	my $postincr = $postdate + 1;
	is( $rr->serial($postdate), $postdate, "rr->serial(YYYYMMDDxx) steps from $predate to $postdate" );
	is( $rr->serial($postdate), $postincr, "rr->serial(YYYYMMDDxx) increments $postdate to $postincr" );
}


{
	use integer;
	my $rr	     = new Net::DNS::RR('name SOA mname rname 1000000000');	# September 2001
	my $pretime  = $rr->serial;
	my $posttime = time;
	my $postincr = $posttime + 1;
	is( $rr->serial($posttime), $posttime, "rr->serial(time) steps from $pretime to $posttime" );
	is( $rr->serial($posttime), $postincr, "rr->serial(time) increments $posttime to $postincr" );
}


exit;

