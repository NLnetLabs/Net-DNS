# $Id$	-*-perl-*-

use strict;

BEGIN {
	use Test::More;
	use Net::DNS;

	my @prerequisite = qw(
		MIME::Base64
		Time::Local
		);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
			unless eval "require $package";
	}

	plan tests => 18;
}


my $name = 'net-dns.org';
my $type = 'SIG';
my $code = 24;
my @attr = qw( typecovered algorithm labels orgttl sigexpiration siginception keytag signame signature );
my @data = (	qw( NS  7  2  3600 20130914141655 20130815141655 60909  net-dns.org ),
		join '', qw(	IRlCjYNZCkddjoFw6UGxAga/EvxgENl+IESuyRH9vlrys
				yqne0gPpclC++raP3+yRA+gDIHrMkIwsLudqod4iuoA73
				Mw1NxETS6lm2eQTDNzLSY6dnJxZBqXypC3Of7bF3UmR/G
				NhcFIThuV/qFq+Gs+g0TJ6eyMF6ydYhjS31k= )
		);
my @also = qw( sigbin );

my $wire = '0002070200000E1052346FD7520CE2D7EDED076E65742D646E73036F7267002119428D83590A475D8E8170E941B10206BF12FC6010D97E2044AEC911FDBE5AF2B32AA77B480FA5C942FBEADA3F7FB2440FA00C81EB324230B0BB9DAA87788AEA00EF7330D4DC444D2EA59B67904C33732D263A767271641A97CA90B739FEDB17752647F18D85C1484E1B95FEA16AF86B3E8344C9E9EC8C17AC9D6218D2DF59';


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
	my @rdata	= @data;
	my $sig		= pop @rdata;
	my $lc		= new Net::DNS::RR( lc(". $type @rdata ").$sig );
	my $rr		= new Net::DNS::RR( uc(". $type @rdata ").$sig );
	my $hash	= {};
	my $predecessor = $rr->encode( 0, $hash );
	my $compressed	= $rr->encode( length $predecessor, $hash );
	ok( length $compressed == length $predecessor, 'encoded RDATA not compressible' );
	is( $rr->encode, $lc->encode, 'encoded RDATA names downcased' );
	is( $rr->canonical, $lc->encode, 'canonical RDATA names downcased' );
}


{
	my $rr = new Net::DNS::RR("$name $type @data");
	$rr->print;
}

exit;

