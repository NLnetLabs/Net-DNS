# $Id$	-*-perl-*-

use strict;
use Test::More tests => 42;


BEGIN {
	my $codeword = unpack 'H*', '[|';
	my %codename = (
		'5b7c' => 'ISO-8859-1',
		'ba4f' => 'EBCDIC cp37',
		'4abb' => 'EBCDIC cp500',
		'4a6a' => 'EBCDIC cp875',
		'68bb' => 'EBCDIC cp1026',
		'ad4f' => 'EBCDIC cp1047',
		'bb4f' => 'EBCDIC posix-bc'
		);
	my $encoding = $codename{lc $codeword} || "unknown [$codeword]";
	diag("character encoding: $encoding");

diag("Net::DNS::Domain is included for testing only. Failures can safely be ignored");

	use_ok('Net::DNS::Domain') || require 5.008;
}


t2: {
	my $domain = new Net::DNS::Domain('example.com');
	isa_ok( $domain, 'Net::DNS::Domain', 'object returned by new() constructor' );
}


{
	eval { my $domain = new Net::DNS::Domain(); };
	my $exception = $1 if $@ =~ /^(.+\n)/;
	chomp $exception;
	ok( $exception, "empty argument list\t($exception)" );
}


{
	eval { my $domain = new Net::DNS::Domain(undef); };
	my $exception = $1 if $@ =~ /^(.+\n)/;
	chomp $exception;
	ok( $exception, "argument undefined\t($exception)" );
}


t5: {
	my $domain = new Net::DNS::Domain('example.com');
	my $labels = $domain->_wire;
	is( $labels, 2, 'domain labels separated by dots' );
}


use constant ESC => '\\';

{
	my $case   = ESC . '.';
	my $domain = new Net::DNS::Domain("example${case}com");
	my $labels = $domain->_wire;
	is( $labels, 1, "$case devoid of special meaning" );
}


{
	my $case   = ESC . ESC;
	my $domain = new Net::DNS::Domain("example${case}.com");
	my $labels = $domain->_wire;
	is( $labels, 2, "$case devoid of special meaning" );
}


{
	my $case   = ESC . ESC . ESC . '.';
	my $domain = new Net::DNS::Domain("example${case}com");
	my $labels = $domain->_wire;
	is( $labels, 1, "$case devoid of special meaning" );
}


{
	my $case   = '\092';
	my $domain = new Net::DNS::Domain("example${case}.com");
	my $labels = $domain->_wire;
	is( $labels, 2, "$case devoid of special meaning" );
}


t10: {
	my $name   = 'example.com.';
	my $domain = new Net::DNS::Domain("$name...");
	is( $domain->string, $name, 'ignore gratuitous trailing dots' );
}


{
	my $left   = 'example';
	my $right  = 'com.';
	my $domain = new Net::DNS::Domain("$left..$right");
	is( $domain->string, "$left.$right", 'ignore interior null label' );
}


{
	my $domain = new Net::DNS::Domain('');
	is( $domain->name, '.', 'DNS root represented as single dot' );

	my $binary = unpack 'H*', $domain->encode;
	my $expect = '00';
	is( $binary, $expect, 'DNS root wire-format representation' );
}


{
	eval { my $domain = new Net::DNS::Domain('.example.com') };
	my $exception = $1 if $@ =~ /^(.+\n)/;
	chomp $exception;
	ok( $exception, "null domain label\t($exception)" );
}


t15: {
	my @warnings;
	local $SIG{__WARN__} = sub { push( @warnings, "@_" ); };
	my $name      = 'LO-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-O-NG!';
	my $domain    = new Net::DNS::Domain("$name");
	my ($warning) = @warnings;
	chomp $warning;
	ok( $warning, "long domain label\t($warning)" );
}


{
	my $ldh	      = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-0123456789';
	my $domain    = new Net::DNS::Domain($ldh);
	my $subdomain = new Net::DNS::Domain("sub.$ldh");
	is( $domain->string, "$ldh.", '63 octet LDH character label' );

	my $dnhash = {};
	my $buffer = $domain->encode( 0, $dnhash );
	my $hex	   = '3f'
			. '4142434445464748494a4b4c4d4e4f505152535455565758595a'
			. '6162636465666768696a6b6c6d6e6f707172737475767778797a'
			. '2d30313233343536373839' . '00';
	is( lc unpack( 'H*', $buffer ), $hex, 'simple wire-format encoding' );

	my $repeat = $domain->encode( length $buffer, $dnhash );
	my $pointer = 'c000';
	$buffer .= $repeat;
	is( lc unpack( 'H*', $repeat ), $pointer, 'compressed wire-format encoding' );

	my $sub = $subdomain->encode( length $buffer, $dnhash );
	my $data = '03737562c000';
	$buffer .= $sub;
	is( lc unpack( 'H*', $sub ), $data, 'compressed wire-format encoding' );

	my ( $decode, $offset ) = decode Net::DNS::Domain( \$buffer );
	is( $decode->name, $domain->name, 'simple wire-format decoding' );

	( $decode, $offset ) = decode Net::DNS::Domain( \$buffer, $offset );
	is( $decode->name, $domain->name, 'compressed wire-format decoding' );

	( $decode, $offset ) = decode Net::DNS::Domain( \$buffer, $offset );
	is( $decode->name, $subdomain->name, 'compressed wire-format decoding' );

	my $encode = $decode->encode( 0, {} );
	my $recycle = decode Net::DNS::Domain( \$encode );
	is( $recycle->name, $subdomain->name, 'encoding decoded compressed data' );
}


{
	my $buffer = pack 'H*', 'c002';
	eval { my $domain = decode Net::DNS::Domain( \$buffer ); };
	my $exception = $@;
	chomp $exception;
	ok( $exception, "bad compression pointer\t($exception)" );
}


t25: {
	my $buffer = pack 'H*', 'c000';
	eval { my $domain = decode Net::DNS::Domain( \$buffer ); };
	my $exception = $@;
	chomp $exception;
	ok( $exception, "name compression loop\t($exception)" );
}


{
	my $hex = '40'
			. '4142434445464748494a4b4c4d4e4f505152535455565758595a'
			. '6162636465666768696a6b6c6d6e6f707172737475767778797a'
			. '2d30313233343536373839ff' . '00';
	my $buffer = pack 'H*', $hex;
	eval { my $domain = decode Net::DNS::Domain( \$buffer ); };
	my $exception = $@;
	chomp $exception;
	ok( $exception, "corrupt wire-format\t($exception)" );
}


{
	foreach my $case (
		'\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015',
		'\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031'
		) {
		my $domain = new Net::DNS::Domain($case);
		my $binary = $domain->encode;
		my $result = decode Net::DNS::Domain( \$binary )->string;
		chop($result);
		is( unpack( 'H*', $result ), unpack( 'H*', $case ), "C0 controls:\t$case" );
	}
}


t29: {
	foreach my $case (
		'\032!\"#\$%&\'\(\)*+,-\./',			#  32 .. 47
		'0123456789:\;<=>?',				#  48 ..
		'\@ABCDEFGHIJKLMNO',				#  64 ..
		'PQRSTUVWXYZ[\\\\]^_',				#  80 ..
		'`abcdefghijklmno',				#  96 ..
		'pqrstuvwxyz{|}~\127'				# 112 ..
		) {
		my $domain = new Net::DNS::Domain($case);
		my $binary = $domain->encode( 0, {} );
		my $result = decode Net::DNS::Domain( \$binary )->string;
		chop($result);
		is( unpack( 'H*', $result ), unpack( 'H*', $case ), "G0 graphics:\t$case" );
	}
}


t35: {
	foreach my $case (
		'\128\129\130\131\132\133\134\135\136\137\138\139\140\141\142\143',
		'\144\145\146\147\148\149\150\151\152\153\154\155\156\157\158\159',
		'\160\161\162\163\164\165\166\167\168\169\170\171\172\173\174\175',
		'\176\177\178\179\180\181\182\183\184\185\186\187\188\189\190\191',
		'\192\193\194\195\196\197\198\199\200\201\202\203\204\205\206\207',
		'\208\209\210\211\212\213\214\215\216\217\218\219\220\221\222\223',
		'\224\225\226\227\228\229\230\231\232\233\234\235\236\237\238\239',
		'\240\241\242\243\244\245\246\247\248\249\250\251\252\253\254\255'
		) {
		my $domain = new Net::DNS::Domain($case);
		my $binary = $domain->encode;
		my $result = decode Net::DNS::Domain( \$binary )->string;
		chop($result);
		is( unpack( 'H*', $result ), unpack( 'H*', $case ), "8-bit codes:\t$case" );
	}
}


exit;

