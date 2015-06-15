# $Id$	-*-perl-*-

use strict;
use Test::More;

use Net::DNS;
use Net::DNS::Parameters;

my @opt = keys %Net::DNS::Parameters::ednsoptionbyname;

plan tests => 21 + scalar(@opt);


my $name = '.';
my $type = 'OPT';
my $code = 41;
my @attr = qw( size rcode flags );
my @data = qw( 1280 0 32768 );
my @also = qw( version );

my $wire = '0000290500000080000000';


{					## check conversion functions
	foreach ( sort( keys %Net::DNS::Parameters::ednsoptionbyname ), 65500 ) {
		my $expect = uc($_);
		my $name = eval {
			my $val = ednsoptionbyname($_);
			ednsoptionbyval( ednsoptionbyname($val) );
		};
		my $exception = $@ =~ /^(.+)\n/ ? $1 : '';
		is( $name, $expect, "ednsoptionbyname('$_')\t$exception" );
	}

	foreach my $testcase ('BOGUS') {
		eval { ednsoptionbyname($testcase); };
		my $exception = $1 if $@ =~ /^(.+)\n/;
		ok( $exception ||= '', "ednsoptionbyname($testcase)\t[$exception]" );
	}
}


{
	my $typecode = unpack 'xn', new Net::DNS::RR( name => '.', type => $type )->encode;
	is( $typecode, $code, "$type RR type code = $code" );

	my $hash = {};
	@{$hash}{@attr} = @data;

	my $rr = new Net::DNS::RR(
		name => $name,
		type => $type,
		%$hash
		);

	my $string = $rr->string;
	like( $string, '/EDNS/', 'string method works' );

	foreach (@attr) {
		is( $rr->$_, $hash->{$_}, "expected result from rr->$_()" );
	}

	foreach (@also) {
		my $value = $rr->$_;
		ok( defined $rr->$_, "additional attribute rr->$_()" );
	}

	my $encoded = $rr->encode;
	my $decoded = decode Net::DNS::RR( \$encoded );
	my $hex1    = uc unpack 'H*', $encoded;
	my $hex2    = uc unpack 'H*', $decoded->encode;
	is( $hex1, $hex2, 'encode/decode transparent' );
	is( $hex1, $wire, 'encoded RDATA matches example' );
}


{
	my $rr = new Net::DNS::RR( name => '.', type => $type );
	foreach (@attr) {
		my $initial = 0x5A5;
		my $changed = 0xA5A;
		$rr->{$_} = $initial;
		is( $rr->$_($changed), $changed, "rr->$_(x) returns function argument" );
		is( $rr->$_(),	       $changed, "rr->$_(x) changes attribute value" );
	}
}


{
	my $rr = new Net::DNS::RR( name => '.', type => $type );
	my $n = 3;
	$n++ until ednsoptionbyval($n) eq "$n";
	my @optn = ( ( $n - 3 ) .. $n );
	foreach (@optn) {
		my $value = "value $_";
		$rr->option( $_ => $value );
	}

	my $encoded = $rr->encode;
	my $decoded = decode Net::DNS::RR( \$encoded );
	my @result  = sort $decoded->options;
	is( scalar(@result), scalar(@optn), 'expected number of options' );

	foreach (@result) {
		my $value = "value $_";
		is( $decoded->option($_), $value, "expected value for option $_" );
	}

	$rr->print;
}


exit;

